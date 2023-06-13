// file_dates_dump1.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <assert.h>
#include <Windows.h>

inline uint64_t filetime_to_unix_time(uint64_t filetime)
{
    static constexpr uint64_t windows_tick = 10000000;
    static constexpr uint64_t sec_to_unix_epoch = 11644473600;
    return filetime / windows_tick - sec_to_unix_epoch;
}

std::string string_from_wstring(const std::wstring& unicode_string) {
    std::string transformed;
    transformed.resize(unicode_string.size() * 2);
    int result = WideCharToMultiByte(CP_UTF8, NULL, unicode_string.c_str(), unicode_string.size(), &transformed[0], transformed.size(), 0, 0);
    assert(result > 0);
    transformed.resize(result);
    return transformed;
}

inline uint64_t uint64_from_file_time(FILETIME file_time) {
    return (static_cast<uint64_t>(file_time.dwHighDateTime ) << 32) | file_time.dwLowDateTime;
}

struct file {
    std::string file_name;
    uint64_t creation_date, modify_date, access_date;
};

class dir_entry {
    std::string m_dir_path;
    std::vector<dir_entry> m_sub_entries;
    std::vector<file> m_files;

public:

    dir_entry(const std::string& dir_name) : m_dir_path(dir_name) {}
    dir_entry(const dir_entry& rhs) : m_dir_path(rhs.m_dir_path), m_sub_entries(rhs.m_sub_entries), m_files(rhs.m_files) {}
    dir_entry(dir_entry&& rhs) noexcept : m_dir_path(std::move(rhs.m_dir_path)), m_sub_entries(std::move(rhs.m_sub_entries)), m_files(std::move(rhs.m_files)) {}
    std::vector<file> get_dir_files() const {
        return m_files;
    }

    const std::vector<dir_entry>& get_nested_dirs() const {
        return m_sub_entries;
    }

    std::string get_dir_path() const {
        return m_dir_path;
    }

    void set_dir_path(const std::string& dir_path) {
        m_dir_path = dir_path;
    }

    void push_dir(dir_entry&& entry) {
        m_sub_entries.push_back(std::move(entry));
    }

    void push_file(file&& entry) {
        m_files.push_back(std::move(entry));
    }

    size_t get_size() const {
        return m_sub_entries.size() + m_files.size();
    }
};

class scanning_error : public std::exception {
public:
    virtual const char* what() const {
        return "unable to scan directories!";
    }
};

class scanner {
    static void check_handle(HANDLE value) {
        if (value == INVALID_HANDLE_VALUE) {
            throw scanning_error();
        }
    }
public:
    static dir_entry scan(const wchar_t* file_path) {
        WIN32_FIND_DATAW found = { 0 };
        HANDLE find_file = FindFirstFileW(file_path, &found);
        check_handle(find_file);
        dir_entry entries(string_from_wstring(file_path));
        while (FindNextFileW(find_file, &found)) {
            if (wcscmp(L"..", found.cFileName) == 0) continue;
            if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::wstring next_dir_path(file_path, wcslen(file_path) - 2);
                //next_dir_path += L"\\";
                next_dir_path += found.cFileName;
                next_dir_path += L"\\* ";
                entries.push_dir(scan(next_dir_path.c_str()));
            }
            else {
                entries.push_file({ string_from_wstring(found.cFileName), filetime_to_unix_time(uint64_from_file_time(found.ftCreationTime)), filetime_to_unix_time(uint64_from_file_time(found.ftLastWriteTime)), filetime_to_unix_time(uint64_from_file_time(found.ftLastAccessTime)) });
            }
        }
        return entries;
    }
};

class base_writer {
protected:
    std::shared_ptr<std::ostringstream> m_write_stream;
public:
    base_writer() = delete;
    base_writer(std::shared_ptr<std::ostringstream> write_stream) : m_write_stream(write_stream) {}
    std::shared_ptr<std::ostringstream> get_stream() {
        return m_write_stream;
    }
};

class element_writer : public base_writer {
public:
    element_writer() = delete;
    element_writer(std::shared_ptr<std::ostringstream> write_stream) : base_writer(write_stream) {
        *(m_write_stream) << '{';
    }
    virtual ~element_writer() {
        *(m_write_stream) << '}';
    }
};

class array_writer : public base_writer {
public:
    array_writer(std::shared_ptr<std::ostringstream> write_stream) : base_writer(write_stream) {
        *(m_write_stream) << '[';
    }
    ~array_writer() {
        *(m_write_stream) << ']';
    }
};

class file_info_writer : public base_writer {
    int m_counter = 0;
public:
    file_info_writer(std::shared_ptr<std::ostringstream> write_stream) : base_writer(write_stream) {}
    void push_file_info(const file& file_info) {
        if (m_counter++ > 0)
            *(m_write_stream) << ", ";
        *(m_write_stream) << "{\"name\": \"" << file_info.file_name << "\", \"created:\": " << file_info.creation_date << ", \"modified\": " << file_info.modify_date << ", \"last_access\": " << file_info.access_date << '}';
    }
};

class dir_info_writer : public element_writer {
public:
    dir_info_writer(std::shared_ptr<std::ostringstream> write_stream) : element_writer(write_stream) {}
    void push_dir_name(const std::string& dir_name) {
        *(m_write_stream) << "\"name\": \"" << dir_name << "\", \"files\": ";
    }
    void create_dirs_array() {
        *(m_write_stream) << ", \"dirs\": ";
    }
};

class json_writer {
    std::shared_ptr<std::ostringstream> m_write_stream;
public:
    json_writer() : m_write_stream(std::make_shared<std::ostringstream>()) {
        *(m_write_stream) << "{\"root\": ";
    }
    std::string get_buffer() {
        std::string json_encoded = m_write_stream->str();
        json_encoded += '}';
        return json_encoded;
    }
    std::shared_ptr<std::ostringstream> get_stream() {
        return m_write_stream;
    }
};

class json_serializer {
    typedef std::shared_ptr<std::ostringstream> stream_t;
    static void iterate_dir(const dir_entry& entry, stream_t stream) {
        dir_info_writer dir_writer(stream);
        dir_writer.push_dir_name(entry.get_dir_path());
        {
            array_writer array_json(stream);
            file_info_writer info_writer(stream);
            for (auto& l : entry.get_dir_files()) {
                info_writer.push_file_info(l);
            }
        }
        dir_writer.create_dirs_array();
        {
            array_writer array_json(stream);
            const std::vector<dir_entry> & nested_dirs = entry.get_nested_dirs();
            auto nested_dirs_iterator = nested_dirs.begin();
            for (; nested_dirs_iterator != nested_dirs.end(); nested_dirs_iterator++) {
                if (nested_dirs_iterator != nested_dirs.begin()) {
                    *(stream) << ", ";
                }
                iterate_dir(*nested_dirs_iterator, stream);
            }
        }
    }
public:
    static std::string serialize(const dir_entry& root) {
        json_writer writer;
        iterate_dir(root, writer.get_stream());
        return writer.get_buffer();
    }
};

int main(int argc, char** argv)
{
    std::ostream* writer = nullptr;
    if (argc == 1) {
        writer = &std::cout;
    }
    else {
        writer = new std::ofstream(argv[1]);
    }
    dir_entry root = scanner::scan(L".\\* ");
    const std::string result = json_serializer::serialize(root);
    *(writer) << result;
    if (writer != &std::cout) {
        delete writer;
    }
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
