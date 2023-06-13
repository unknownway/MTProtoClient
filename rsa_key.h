#pragma once

#include "buffer.h"
#include <vector>
#include <stdexcept>
#include <stdio.h>

namespace mtproto::crypto {

	class rsa_key
	{
		std::vector<std::byte> m_n;
		uint32_t m_e;
	public:
		rsa_key();
		void load_from_file(const char* file_name);
		uint32_t get_e_part();
		std::vector<std::byte> get_n_part();
		uint64_t compute_fingerprint();
		mtproto::data::binary_buffer encrypt(const mtproto::data::binary_buffer& data);
	};

}