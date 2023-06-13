#pragma once

#include "buffer.h"

namespace mtproto::crypto {
	mtproto::data::binary_buffer ige256_encrypt(const mtproto::data::binary_buffer& data, const mtproto::data::binary_buffer& key, const mtproto::data::binary_buffer& iv);
	mtproto::data::binary_buffer ige256_decrypt(const mtproto::data::binary_buffer& data, const mtproto::data::binary_buffer& key, const mtproto::data::binary_buffer& iv);
	void pad_plaintext(mtproto::data::binary_buffer& data);
}