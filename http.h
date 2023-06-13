#pragma once

#include "buffer.h"
#include <boost/asio.hpp>

namespace mtproto {
    namespace http {
        class HTTPSender {
            boost::asio::io_service m_io;
            static const std::string m_header;
            std::string m_address;
            int m_port;
            boost::asio::ip::tcp::socket create_connection();
            std::string get_header_from_response(const std::vector<std::byte>& bytes);
            int get_content_length_from_header(const std::string& header);
        public:
            HTTPSender() = delete;
            HTTPSender(const char* address, int port);
            HTTPSender(const HTTPSender&) = delete;
            HTTPSender& operator=(const HTTPSender&) = delete;
            mtproto::data::binary_buffer send(const mtproto::data::binary_buffer& data);
            uint32_t get_ip();
        };
    }
}