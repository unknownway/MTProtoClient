#pragma once

#include "buffer.h"

namespace mtproto::crypto {

	mtproto::data::binary_buffer sha1(const mtproto::data::binary_buffer& data);
	mtproto::data::binary_buffer sha256(const mtproto::data::binary_buffer& data);
}