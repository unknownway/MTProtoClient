#include <stdio.h>
#include <stdexcept>
#include "binary_stream.h"
#include "sha.h"
#include "mtproto_session_type.h"

namespace mtproto::session {

	static void swap_if_little_endian(session_details& session) {
		if (mtproto::data::binary_stream::is_little_endian) {
			session.dc = _byteswap_ulong(session.dc);
			session.ip = _byteswap_ulong(session.ip);
			session.port = _byteswap_ushort(session.port);
		}
	}

	void load_from_file(const char* file_name, session_details& session) {
		FILE* file = fopen(file_name, "rb");
		if (fread(&session, 1, sizeof(session_details), file) < sizeof(session_details)) {
			fclose(file);
			throw std::runtime_error("file is too small!");
		}
		swap_if_little_endian(session);
		fclose(file);
	}

	void dump_to_file(const char* file_name, session_details& session) {
		FILE* file = fopen(file_name, "wb");
		if (!file) throw std::runtime_error("unable to open file!");
		swap_if_little_endian(session);
		fwrite(&session, sizeof(session_details), 1, file);
		swap_if_little_endian(session);
		fclose(file);
	}

	void compute_auth_key_id(const char* auth_key, char* auth_key_id) {
		mtproto::data::binary_buffer auth_key_buffer(auth_key, 256);
		mtproto::data::binary_buffer auth_key_hash = mtproto::crypto::sha1(auth_key_buffer);
		auth_key_hash.copy(auth_key_id, 8, 12);
	}
}