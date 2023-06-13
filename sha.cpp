#include <openssl/sha.h>
#include "sha.h"

namespace mtproto::crypto {

	mtproto::data::binary_buffer sha1(const mtproto::data::binary_buffer& data) {
		SHA_CTX context;
		SHA1_Init(&context);
		SHA1_Update(&context, data.get_data_pointer(), data.get_size());
		mtproto::data::binary_buffer hash;
		hash.set_size(20);
		SHA1_Final((unsigned char*)hash.get_data_pointer(), &context);
		return hash;
	}

	mtproto::data::binary_buffer sha256(const mtproto::data::binary_buffer& data) {
		SHA256_CTX context;
		SHA256_Init(&context);
		SHA256_Update(&context, data.get_data_pointer(), data.get_size());
		mtproto::data::binary_buffer hash;
		hash.set_size(32);
		SHA256_Final((unsigned char*)hash.get_data_pointer(), &context);
		return hash;
	}
}