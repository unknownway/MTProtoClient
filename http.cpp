#include "http.h"

namespace mtproto::http {

    HTTPSender::HTTPSender(const char* address, int port) : m_address(address), m_port(port) {}

    boost::asio::ip::tcp::socket HTTPSender::create_connection() {
        boost::asio::ip::tcp::socket sock(m_io);
        // boost::asio::ip::tcp::endpoint endp(boost::asio::ip::address::from_string("149.154.167.50"), 80);
        boost::asio::ip::tcp::endpoint endp(boost::asio::ip::address::from_string(m_address), m_port);
        sock.connect(endp);
        return sock;
    }
    std::string HTTPSender::get_header_from_response(const std::vector<std::byte>& bytes) {
        std::string header;
        header.insert(header.begin(), (char*)bytes.data(), (char*)bytes.data() + bytes.size());
        size_t end_pos = header.find("\r\n\r\n");
        return header.substr(0, end_pos);
    }
    int HTTPSender::get_content_length_from_header(const std::string& header) {
        std::string prepared_header;
        prepared_header.resize(header.size());
        std::transform(header.begin(), header.end(), prepared_header.begin(), [](char c) {
            return tolower(c);
            });
        size_t pos = prepared_header.find("content-length");
        if (pos == std::string::npos) throw std::invalid_argument("invalid header");
        std::string content_length_value = prepared_header.substr(pos);
        int content_length = 0;
        sscanf(content_length_value.c_str(), "content-length: %d", &content_length);
        return content_length;
    }

    mtproto::data::binary_buffer HTTPSender::send(const mtproto::data::binary_buffer& data) {
        std::vector<std::byte> request;
        request.insert(request.begin(), (std::byte*)m_header.data(), (std::byte*)m_header.data() + m_header.size());
        std::string data_size = std::to_string(data.get_size());
        data_size += "\r\n\r\n";
        request.insert(request.end(), (std::byte*)data_size.data(), (std::byte*)data_size.data() + data_size.size());
        request.insert(request.end(), data.get_data().begin(), data.get_data().end());
        auto client = create_connection();
        client.write_some(boost::asio::buffer(request));
        std::vector<std::byte> response;
        response.resize(1024);
        response.resize(client.read_some(boost::asio::buffer(response)));
        std::string header = get_header_from_response(response);
        int content_length = get_content_length_from_header(header);
        mtproto::data::binary_buffer response_buffer;
        auto& data_response = response_buffer.get_data();
        int current_content_length = response.size() - header.size() - 4;
        data_response.insert(data_response.begin(), response.end() - current_content_length, response.end());
        while (content_length > current_content_length) {
            std::vector<std::byte> new_response;
            new_response.resize(512);
            new_response.resize(client.read_some(boost::asio::buffer(new_response)));
            current_content_length += new_response.size();
            data_response.insert(data_response.end(), new_response.begin(), new_response.end());
        }
        client.close();
        return response_buffer;
    }

    uint32_t HTTPSender::get_ip() {
        return boost::asio::ip::address_v4::from_string(m_address).to_ulong();
    }

    const std::string HTTPSender::m_header = "POST /api HTTP/1.1\r\nHost: localhost\r\nUser-Agent: mtproto-client/1.0\r\nAccept: /*/\r\nConnection: closed\r\nContent-Length: ";
}