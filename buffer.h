#pragma once

#include <vector>
#include <ostream>

namespace mtproto {

	namespace data {

		class binary_buffer
		{
			typedef std::vector<std::byte> byte_storage_t;
			byte_storage_t m_data;
		public:
			binary_buffer() : m_data() { }
			binary_buffer(const byte_storage_t& binary_buffer) : m_data(binary_buffer) {}
			binary_buffer(byte_storage_t&& binary_buffer) noexcept : m_data(std::move(binary_buffer)) {}
			binary_buffer(const binary_buffer& binary_buffer) : m_data(binary_buffer.m_data) {}
			binary_buffer(binary_buffer&& binary_buffer) noexcept : m_data(std::move(binary_buffer.m_data)) {}
			binary_buffer(const char* data, size_t size) : m_data((std::byte*)data, (std::byte*)data + size) {}
			binary_buffer& operator=(binary_buffer&& buffer) noexcept {
				m_data = std::move(buffer.m_data);
				return *this;
			}
			binary_buffer& operator=(const binary_buffer& buffer) noexcept {
				m_data = buffer.m_data;
				return *this;
			}
			const byte_storage_t& get_data() const {
				return m_data;
			}
			byte_storage_t& get_data() {
				return m_data;
			}
			const char* get_data_pointer() const {
				return (const char*)m_data.data();
			}
			void slice(size_t from, size_t to) {
				m_data = byte_storage_t(m_data.begin() + from, m_data.begin() + to);
			}
			void append(const char* data, size_t size) {
				m_data.insert(m_data.end(), (std::byte*)data, (std::byte*)data + size);
			}
			void append(const binary_buffer& buffer) {
				m_data.insert(m_data.end(), buffer.get_data().begin(), buffer.get_data().end());
			}
			void append(char c) {
				m_data.push_back((std::byte)c);
			}
			void insert_begin(const char* data, size_t size) {
				m_data.insert(m_data.begin(), (std::byte*)data, (std::byte*)data + size);
			}
			void set_data(const char* data, size_t size) {
				m_data = byte_storage_t((std::byte*)data, (std::byte*)data + size);
			}
			void set_size(size_t new_size) {
				m_data.resize(new_size);
			}
			void reserve(size_t size) {
				m_data.reserve(size);
			}
			void add_padding(size_t size) {
				for (int i = 0; i < size; i++) {
					m_data.push_back((std::byte)0);
				}
			}
			void copy(char* data, size_t size, size_t offset = 0) const {
				if (size > m_data.size()) throw std::invalid_argument("invalid size was provided!");
				memcpy(data, m_data.data() + offset, size);
			}
			void clear() {
				m_data.clear();
			}
			size_t get_size() const {
				return m_data.size();
			}
		};

		class immutable_data_view {
			const char* m_data;
			size_t m_size;
		public:
			immutable_data_view(const binary_buffer& buffer) : m_data(buffer.get_data_pointer()), m_size(buffer.get_size()) {}
			immutable_data_view(const std::string& buffer) : m_data(buffer.c_str()), m_size(buffer.size()) {}
			immutable_data_view(const char* text) : m_data(text), m_size(strlen(text)) {}
			immutable_data_view(const char* data, size_t length) : m_data(data), m_size(length) {}

			size_t get_size() const {
				return m_size;
			}

			const char* get_data() const {
				return m_data;
			}
		};

		std::ostream& operator<<(std::ostream& lhs, const binary_buffer& rhs);
		void dump_bytes(std::ostream& stream, const char* data, size_t size);
	}
}