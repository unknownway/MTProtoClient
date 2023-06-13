#pragma once

#include "buffer.h"
#include "mtproto_session_type.h"
#include "tl_packet.h"

namespace mtproto {

	namespace message {

		typedef struct _message_details {
			uint64_t server_salt;
			uint64_t session_id;
			uint64_t msg_id;
			uint32_t seq_no;
		} message_details;

		class UnencryptedMessage {
		public:
			static mtproto::data::binary_buffer write(mtproto::TLPacket& packet);
			static void skip_header(mtproto::data::binary_buffer& data);
		};

		class EncryptedMessage {
		public:
			static mtproto::data::binary_buffer write(const mtproto::session::session_details& session, const message_details& details, const mtproto::data::binary_buffer& payload);
			static mtproto::data::binary_buffer read(const mtproto::session::session_details& session, const mtproto::data::binary_buffer& payload, message_details& details);
		};
	}
}