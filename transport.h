#pragma once

#include <memory>
#include "buffer.h"

namespace mtproto::transport {

	class transport {
	public:
		virtual void connect() = 0;
		virtual bool is_connected() = 0;
		virtual void close() = 0;
		virtual void send(mtproto::data::binary_buffer&& buffer) = 0;
		virtual mtproto::data::binary_buffer receive() = 0;
	};

	typedef std::shared_ptr<transport> transport_t;
}