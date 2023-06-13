#include "rsa_key.h"
#include "binary_stream.h"
#include "sha.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <iostream>

namespace mtproto::crypto {

	rsa_key::rsa_key() : m_e(0), m_n() {}

	static bool is_big_endian() {
		static const uint16_t value = 0x0102;
		const char* ptr = (const char*)&value;
		return ptr[1] == 0x02;
	}

	uint32_t rsa_key::get_e_part() {
		return m_e;
	}

	std::vector<std::byte> rsa_key::get_n_part() {
		return m_n;
	}

	void rsa_key::load_from_file(const char* file_name) {
		FILE* config = fopen(file_name, "rb");
		if (!config) throw std::invalid_argument("invalid file was provided!");
		bool swap_required = !is_big_endian();
		fread(&m_e, 3, 1, config);
		if (!swap_required) {
			m_e = _byteswap_ulong(m_e) & 0xFFFFFF;
		}
		uint16_t key_size = 0;
		fread(&key_size, 2, 1, config);
		if (swap_required) {
			key_size = _byteswap_ushort(key_size);
		}
		m_n.resize(key_size);
		fread(&m_n[0], key_size, 1, config);
		fclose(config);
	}

	uint64_t rsa_key::compute_fingerprint() {
		mtproto::data::binary_stream stream;
		mtproto::data::binary_buffer n(m_n);
		uint32_t e = m_e;
		if (is_big_endian()) {
			e = _byteswap_ulong(e);
		}
		mtproto::data::binary_buffer e_bytes((const char*)&e, 3);
		stream.pack_string(n);
		stream.pack_string(e_bytes);
		auto& buffer = stream.get_buffer();
		mtproto::data::binary_buffer sha1_hash = mtproto::crypto::sha1(buffer);
		uint64_t fingerprint = 0;
		memcpy(&fingerprint, (const char*)sha1_hash.get_data_pointer() + 12, 8);
		if (is_big_endian()) {
			return _byteswap_uint64(fingerprint);
		}
		return fingerprint;
	}

	mtproto::data::binary_buffer rsa_key::encrypt(const mtproto::data::binary_buffer& data) {
		if (m_n.size() < 256) {
			throw std::runtime_error("invalid encrypt key!");
		}
		BN_CTX* context = BN_CTX_new();
		BIGNUM* plain_text = BN_new(), * e = BN_new(), * n = BN_new(), * result = BN_new();
		BN_bin2bn((const unsigned char*)data.get_data().data(), data.get_size(), plain_text);
		uint32_t e_value = m_e;
		if (is_big_endian()) {
			e_value = _byteswap_ulong(e_value);
		}
		BN_bin2bn((const unsigned char*)&e_value, 3, e);
		BN_bin2bn((const unsigned char*)m_n.data(), m_n.size(), n);
		BN_mod_exp_mont(result, plain_text, e, n, context, nullptr);
		BN_free(e);
		BN_free(n);
		BN_free(plain_text);
		mtproto::data::binary_buffer encrypted;
		encrypted.get_data().resize(BN_num_bytes(result));
		BN_bn2bin(result, (unsigned char*)encrypted.get_data().data());
		BN_free(result);
		return encrypted;
	}
}