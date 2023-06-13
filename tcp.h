#pragma once

#include "transport.h"

namespace mtproto::transport {

	typedef unsigned long long socket_t;

	class invalid_socket : public std::exception {
	public:
		virtual const char* what() const {
			return "invalid connection!";
		}
	};

	class tcp : public transport {
	protected:
		socket_t m_socket;
		uint32_t m_ip;
		uint16_t m_port;
		void send_bytes(const char* data, int length);
		int receive_bytes(char* buffer, int length);
		void swap(uint32_t& value);
	public:
		virtual void connect() = 0;
		virtual void close();
		virtual void send(mtproto::data::binary_buffer&& buffer) = 0;
		virtual bool is_connected();
		virtual mtproto::data::binary_buffer receive() = 0;
		~tcp();
	};

	class tcp_intermediate : public tcp {
	public:
		tcp_intermediate() = delete;
		tcp_intermediate(const char* address, uint16_t port);
		tcp_intermediate(uint32_t ip, uint16_t port);
		virtual void connect();
		virtual void send(mtproto::data::binary_buffer&& buffer);
		virtual mtproto::data::binary_buffer receive();
	};
}