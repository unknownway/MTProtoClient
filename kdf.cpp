#include "sha.h"
#include "details/random.h"
#include "aes.h"
#include "kdf.h"
//#include <iostream>

namespace mtproto::crypto {

	static mtproto::data::binary_buffer generate_random(const size_t length) {
		mtproto::data::binary_buffer buffer;
		buffer.set_size(length);
		random_bytes((char*)buffer.get_data_pointer(), buffer.get_size());
		return buffer;
	}

	mtproto::data::binary_buffer compute_msg_key(const char* auth_key, const mtproto::data::binary_buffer& data, bool from_server) {
		const size_t x = from_server ? 8 : 0;
		mtproto::data::binary_buffer hash_arg(auth_key + 88 + x, 32);
		hash_arg.append(data);
		mtproto::data::binary_buffer msg_key_large = mtproto::crypto::sha256(hash_arg);
		msg_key_large.slice(8, 24);
		return msg_key_large;
	}

	void kdf(const char* auth_key, const mtproto::data::binary_buffer& msg_key, const mtproto::data::binary_buffer& data, mtproto::data::binary_buffer& key, mtproto::data::binary_buffer& iv, bool from_server) {
		const size_t x = from_server ? 8 : 0;
		mtproto::data::binary_buffer sha256_a(msg_key);
		sha256_a.append(auth_key + x, 36);
		sha256_a = mtproto::crypto::sha256(sha256_a);
		mtproto::data::binary_buffer sha256_b(auth_key + 40 + x, 36);
		sha256_b.append(msg_key);
		sha256_b = mtproto::crypto::sha256(sha256_b);
		//std::cout << "sha256_b: " << sha256_b << std::endl << "sha256_a: " << sha256_a << std::endl;
		mtproto::data::binary_buffer aes_key, aes_iv;
		aes_key.reserve(32);
		aes_iv.reserve(32);
		aes_key.append(sha256_a.get_data_pointer(), 8);
		aes_key.append(sha256_b.get_data_pointer() + 8, 16);
		aes_key.append(sha256_a.get_data_pointer() + 24, 8);
		aes_iv.append(sha256_b.get_data_pointer(), 8);
		aes_iv.append(sha256_a.get_data_pointer() + 8, 16);
		aes_iv.append(sha256_b.get_data_pointer() + 24, 8);
		key = std::move(aes_key);
		iv = std::move(aes_iv);
	}
}