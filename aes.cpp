#include "aes.h"
#include <openssl/aes.h>

namespace mtproto::crypto {
	
	static mtproto::data::binary_buffer ige256(const mtproto::data::binary_buffer& data, const mtproto::data::binary_buffer& key, const mtproto::data::binary_buffer& iv, bool encrypt) {
		if (data.get_size() % 16 != 0 || key.get_size() != 32 || iv.get_size() != 32) {
			throw std::invalid_argument("invalid argument's provided!");
		}
		AES_KEY aes_key;
		mtproto::data::binary_buffer transformed;
		transformed.set_size(data.get_size());
		char iv_[32];
		iv.copy(iv_, 32, 0);
		if (encrypt) {
			AES_set_encrypt_key((const unsigned char*)key.get_data_pointer(), 256, &aes_key);
			AES_ige_encrypt((const unsigned char*)data.get_data_pointer(), (unsigned char*)transformed.get_data_pointer(), data.get_size(), &aes_key, (unsigned char*)iv_, AES_ENCRYPT);
		}
		else {
			AES_set_decrypt_key((const unsigned char*)key.get_data_pointer(), 256, &aes_key);
			AES_ige_encrypt((const unsigned char*)data.get_data_pointer(), (unsigned char*)transformed.get_data_pointer(), data.get_size(), &aes_key, (unsigned char*)iv_, AES_DECRYPT);
		}
		return transformed;
	}

	mtproto::data::binary_buffer ige256_encrypt(const mtproto::data::binary_buffer& data, const mtproto::data::binary_buffer& key, const mtproto::data::binary_buffer& iv) {
		return ige256(data, key, iv, true);
	}

	mtproto::data::binary_buffer ige256_decrypt(const mtproto::data::binary_buffer& data, const mtproto::data::binary_buffer& key, const mtproto::data::binary_buffer& iv) {
		return ige256(data, key, iv, false);
	}

	void pad_plaintext(mtproto::data::binary_buffer& data) {
		if (data.get_size() % 16 != 0) {
			size_t padding = 16 - data.get_size() % 16;
			data.add_padding(padding);
		}
	}
}