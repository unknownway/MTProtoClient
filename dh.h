#pragma once

#include "buffer.h"
#include "binary_stream.h"
#include "details/random.h"
#include <openssl/bn.h>

namespace mtproto::crypto {

	class dh {
		mtproto::data::binary_buffer m_g_a, m_b, m_g_b, m_dh_prime, m_auth_key;
		uint32_t m_g;
	public:
		dh(uint32_t g, const mtproto::data::binary_buffer& g_a, const mtproto::data::binary_buffer& dh_prime) : m_g_a(g_a), m_g(g), m_dh_prime(dh_prime) {
			m_b.set_size(256);
			RAND_bytes((unsigned char*)m_b.get_data_pointer(), 256);
			BN_CTX* context = BN_CTX_new();
			BIGNUM* g_bn = BN_new();
			if (mtproto::data::binary_stream::is_little_endian) {
				m_g = _byteswap_ulong(m_g);
			}
			BN_bin2bn((const unsigned char*)&m_g, 4, g_bn);
			BIGNUM* dh_prime_bn = BN_new();
			BN_bin2bn((const unsigned char*)m_dh_prime.get_data_pointer(), m_dh_prime.get_size(), dh_prime_bn);
			BIGNUM* g_b_bn = BN_new();
			BIGNUM* b_bn = BN_new();
			BN_bin2bn((const unsigned char*)m_b.get_data_pointer(), m_b.get_size(), b_bn);
			BN_mod_exp_mont(g_b_bn, g_bn, b_bn, dh_prime_bn, context, nullptr);
			m_g_b.set_size(BN_num_bytes(g_b_bn));
			BN_bn2bin(g_b_bn, (unsigned char*)m_g_b.get_data_pointer());
			BIGNUM* g_a_bn = BN_new();
			BN_bin2bn((const unsigned char*)m_g_a.get_data_pointer(), m_g_a.get_size(), g_a_bn);
			BIGNUM* auth_key = BN_new();
			BN_mod_exp_mont(auth_key, g_a_bn, b_bn, dh_prime_bn, context, nullptr);
			m_auth_key.set_size(BN_num_bytes(auth_key));
			BN_bn2bin(auth_key, (unsigned char*)m_auth_key.get_data_pointer());
			BN_free(g_bn);
			BN_free(dh_prime_bn);
			BN_free(g_b_bn);
			BN_free(b_bn);
			BN_free(g_a_bn);
			BN_free(auth_key);
			BN_CTX_free(context);
		}

		mtproto::data::binary_buffer get_auth_key() const {
			return m_auth_key;
		}

		mtproto::data::binary_buffer get_g_b() const {
			return m_g_b;
		}

		mtproto::data::binary_buffer get_b() const {
			return m_b;
		}
	};
}