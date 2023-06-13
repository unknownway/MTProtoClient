#include "message.h"
#include "binary_stream.h"
#include "kdf.h"
#include "aes.h"
#include "details/random.h"
//#include <iostream>

namespace mtproto {

	namespace message {

		mtproto::data::binary_buffer UnencryptedMessage::write(mtproto::TLPacket& packet) {
			mtproto::data::binary_stream stream;
			stream.pack_int64(0x00);
			stream.pack_int64(0x00);
			auto data = packet.write();
			stream.pack_int32(data.get_size());
			data.get_data().insert(data.get_data().begin(), stream.get_buffer().get_data().begin(), stream.get_buffer().get_data().end());
			return data;
		}

		void UnencryptedMessage::skip_header(mtproto::data::binary_buffer& data) {
			if (data.get_size() <= 20) throw std::invalid_argument("message size too few!");
			data.slice(20, data.get_size());
		}

		mtproto::data::binary_buffer EncryptedMessage::write(const mtproto::session::session_details& session, const message_details& details, const mtproto::data::binary_buffer& payload) {
			mtproto::data::binary_stream encrypted_header;
			encrypted_header.pack_int64(details.server_salt);
			encrypted_header.pack_int64(details.session_id);
			encrypted_header.pack_int64(details.msg_id);
			encrypted_header.pack_int32(details.seq_no);
			encrypted_header.pack_int32(payload.get_size());
			encrypted_header.pack_bytes(payload);
			auto& encrypted_header_buffer = encrypted_header.get_buffer();
			mtproto::data::binary_buffer random_data;
			random_data.add_padding(12);
			encrypted_header_buffer.append(random_data);
			mtproto::crypto::pad_plaintext(encrypted_header_buffer);
			mtproto::data::binary_buffer aes_key, aes_iv;
			mtproto::data::binary_buffer msg_key = mtproto::crypto::compute_msg_key(session.auth_key, encrypted_header_buffer);
			mtproto::crypto::kdf(session.auth_key, msg_key, encrypted_header_buffer, aes_key, aes_iv);
			//std::cout << "msg_key: " << msg_key << std::endl;
			//std::cout << "aes_key: " << aes_key << std::endl << "aes_iv: " << aes_iv << std::endl;
			encrypted_header_buffer = mtproto::crypto::ige256_encrypt(encrypted_header_buffer, aes_key, aes_iv);
			mtproto::data::binary_stream encapsulated_header;
			encapsulated_header.pack_bytes(session.auth_key_id, 8);
			encapsulated_header.pack_bytes(msg_key);
			encapsulated_header.pack_bytes(encrypted_header_buffer);
			return encapsulated_header.get_buffer();
		}
		mtproto::data::binary_buffer EncryptedMessage::read(const mtproto::session::session_details& session, const mtproto::data::binary_buffer& payload, message_details& details) {
			if (payload.get_size() < 20) throw std::invalid_argument("invalid payload was given!");
			mtproto::data::binary_buffer msg_key(payload.get_data_pointer() + 8, 16);
			mtproto::data::binary_buffer aes_key, aes_iv, encrypted_payload(payload.get_data_pointer() + 24, payload.get_size() - 24);
			mtproto::crypto::kdf(session.auth_key, msg_key, payload, aes_key, aes_iv, true);
			encrypted_payload = mtproto::crypto::ige256_decrypt(encrypted_payload, aes_key, aes_iv);
			mtproto::data::binary_stream stream;
			stream.set_buffer(std::move(encrypted_payload));
			size_t offset = 0;
			details.server_salt = stream.unpack_int64(offset);
			offset += 8;
			details.session_id = stream.unpack_int64(offset);
			offset += 8;
			details.msg_id = stream.unpack_int64(offset);
			offset += 8;
			details.seq_no = stream.unpack_int64(offset);
			offset += 4;
			uint32_t message_length = stream.unpack_int32(offset);
			offset += 4;
			stream.get_buffer().slice(offset, offset + message_length);
			return stream.get_buffer();
		}
	}
}