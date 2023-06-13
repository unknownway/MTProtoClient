#pragma once

#include "buffer.h"

namespace mtproto::session {

#pragma pack(push, 1)
	struct session_details {
		char auth_key[256];
		char auth_key_id[8];
		uint32_t dc;
		uint32_t ip;
		uint16_t port;
	};
#pragma pack(pop)

	void compute_auth_key_id(const char* auth_key, char* auth_key_id);
	void load_from_file(const char* file_name, session_details& session);
	void dump_to_file(const char* file_name, session_details& session);
}