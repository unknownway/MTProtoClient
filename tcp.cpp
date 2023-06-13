#define WIN32_LEAN_AND_MEAN

#include "tcp.h"
#include "binary_stream.h"
#include <Windows.h>
#include <WinSock2.h>

namespace mtproto::transport {

	tcp_intermediate::tcp_intermediate(const char* address, uint16_t port) {
		m_port = port;
		m_ip = inet_addr(address);
		m_socket = INVALID_SOCKET;
	}

	tcp_intermediate::tcp_intermediate(uint32_t ip, uint16_t port) {
		m_ip = ip;
		m_port = port;
	}

	bool tcp::is_connected() {
		return m_socket != INVALID_SOCKET;
	}

	void tcp::swap(uint32_t& value) {
		if (!mtproto::data::binary_stream::is_little_endian) {
			value = _byteswap_ulong(value);
		}
	}

	void tcp::send_bytes(const char* data, int length) {
		if (::send(m_socket, data, length, 0) <= 0) {
			throw invalid_socket();
		}
	}

	int tcp::receive_bytes(char* buffer, int length) {
		int result = ::recv(m_socket, buffer, length, 0);
		if (result < 0) throw invalid_socket();
		return result;
	}

	void tcp_intermediate::connect() {
		if (m_socket != INVALID_SOCKET) {
			closesocket(m_socket);
			m_socket = INVALID_SOCKET;
		}
		m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		struct sockaddr_in address = { 0 };
		address.sin_addr.S_un.S_addr = htonl(m_ip);
		address.sin_port = htons(m_port);
		address.sin_family = AF_INET;
		if (::connect(m_socket, (struct sockaddr*)&address, sizeof(address)) != 0) {
			closesocket(m_socket);
			m_socket = INVALID_SOCKET;
			throw std::runtime_error("unable to connect to server!");
		}
		char connection_preface[4];
		memset(connection_preface, 0xee, 4);
		send_bytes(connection_preface, 4);
	}

	void tcp_intermediate::send(mtproto::data::binary_buffer&& buffer) {
		mtproto::data::binary_buffer send_buffer = std::move(buffer);
		uint32_t length = send_buffer.get_size();
		swap(length);
		send_buffer.insert_begin((char*)&length, 4);
		send_bytes(send_buffer.get_data_pointer(), send_buffer.get_size());
	}

	mtproto::data::binary_buffer tcp_intermediate::receive() {
		uint32_t length;
		if (receive_bytes((char*)&length, 4) < 4) {
			return mtproto::data::binary_buffer();
		}
		swap(length);
		mtproto::data::binary_buffer buffer;
		buffer.set_size(length);
		receive_bytes((char*)buffer.get_data_pointer(), length);
		return buffer;
	}

	tcp::~tcp() {
		closesocket(m_socket);
		m_socket = INVALID_SOCKET;
	}

	void tcp::close() {
		closesocket(m_socket);
		m_socket = INVALID_SOCKET;
	}
}