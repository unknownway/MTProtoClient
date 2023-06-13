#pragma once

#include "buffer.h"

namespace mtproto::crypto {

	mtproto::data::binary_buffer compute_msg_key(const char* auth_key, const mtproto::data::binary_buffer& data, bool from_server = false);
	void kdf(const char* auth_key, const mtproto::data::binary_buffer& msg_key, const mtproto::data::binary_buffer& data, mtproto::data::binary_buffer& key, mtproto::data::binary_buffer& iv, bool from_server = false);
}