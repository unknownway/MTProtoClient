#pragma once

#include "tl_packet.h"
#include "binary_stream.h"
#include "session.h"
#include <stdexcept>

namespace mtproto {

	namespace base_objects {

		using namespace mtproto::data;

		class not_implemented_error : public std::exception {
		public:
			virtual const char* what() const {
				return "this function is not implemented in this object!";
			}
		};

		class ReqPQ : public TLPacket {
		public:
			char nonce[16];

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0xbe7e8ef1);
				stream.pack_bytes(nonce, 16);
				return stream.get_buffer();
			}

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}
		};

		class ResPQ : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			uint64_t pq;
			std::vector<uint64_t> fingerprints;

			binary_buffer write() const {
				throw not_implemented_error();
			}

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				memcpy(nonce, stream.unpack_bytes(16, 4).get_data().data(), 16);
				memcpy(server_nonce, stream.unpack_bytes(16, 20).get_data().data(), 16);
				size_t offset = 36;
				binary_buffer pq_bytes = stream.unpack_string(offset);
				memcpy(&pq, pq_bytes.get_data().data(), 8);
				if (binary_stream::is_little_endian) {
					pq = _byteswap_uint64(pq);
				}
				uint32_t vector_size = stream.unpack_vector_size(offset);
				offset += 8;
				for (uint32_t i = 0; i < vector_size; i++) {
					fingerprints.push_back(stream.unpack_int64(offset));
					offset += 8;
				}
			}
		};

		class PQInnerDataDC : public TLPacket {
		public:
			uint64_t pq;
			uint32_t p;
			uint32_t q;
			char nonce[16];
			char server_nonce[16];
			char new_nonce[32];
			int dc;

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0xa9f55f95);
				uint64_t pq_value = pq, p_value = p, q_value = q;
				if (binary_stream::is_little_endian) {
					pq_value = _byteswap_uint64(pq_value);
					p_value = _byteswap_ulong(p_value);
					q_value = _byteswap_ulong(q_value);
				}
				binary_buffer buffer;
				buffer.set_data((const char*)&pq_value, 8);
				stream.pack_string(buffer);
				buffer.set_data((const char*)&p_value, 4);
				stream.pack_string(buffer);
				buffer.set_data((const char*)&q_value, 4);
				stream.pack_string(buffer);
				stream.pack_bytes(nonce, 16);
				stream.pack_bytes(server_nonce, 16);
				stream.pack_bytes(new_nonce, 32);
				stream.pack_int32(dc);
				return stream.get_buffer();
			}
		};

		class ReqDHParams : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			uint32_t p;
			uint32_t q;
			uint64_t fingerprint;
			binary_buffer encrypted_data;

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0xd712e4be);
				stream.pack_bytes(nonce, 16);
				stream.pack_bytes(server_nonce, 16);
				uint64_t p_value = p, q_value = q;
				if (binary_stream::is_little_endian) {
					p_value = _byteswap_ulong(p_value);
					q_value = _byteswap_ulong(q_value);
				}
				binary_buffer buffer;
				buffer.set_data((const char*)&p_value, 4);
				stream.pack_string(buffer);
				buffer.set_data((const char*)&q_value, 4);
				stream.pack_string(buffer);
				stream.pack_int64(fingerprint);
				stream.pack_string(encrypted_data);
				return stream.get_buffer();
			}
		};

		class ServerDHParamsOk : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			binary_buffer encrypted_answer;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				size_t offset = 4;
				binary_buffer bytes = stream.unpack_bytes(16, offset);
				bytes.copy(nonce, 16);
				offset += 16;
				bytes = stream.unpack_bytes(16, offset);
				bytes.copy(server_nonce, 16);
				offset += 16;
				encrypted_answer = stream.unpack_string(offset);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class ServerDHInnerData : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			uint32_t g;
			binary_buffer dh_prime;
			binary_buffer g_a;
			uint32_t server_time;

			void read(immutable_data_view data) {
				size_t offset = 4;
				binary_stream_reader stream(data);
				auto packet_id = stream.unpack_int32(0);
				stream.unpack_bytes(16, offset).copy(nonce, 16);
				offset += 16;
				stream.unpack_bytes(16, offset).copy(server_nonce, 16);
				offset += 16;
				g = stream.unpack_int32(offset);
				offset += 4;
				dh_prime = stream.unpack_string(offset);
				g_a = stream.unpack_string(offset);
				server_time = stream.unpack_int32(offset);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class SetClientDHParams : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			binary_buffer encrypted_data;
			
			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0xf5045f1f);
				stream.pack_bytes(nonce, 16);
				stream.pack_bytes(server_nonce, 16);
				stream.pack_string(encrypted_data);
				return stream.get_buffer();
			}
		};

		class ClientDHInnerData : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			uint64_t retry_id;
			binary_buffer g_b;

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0x6643b654);
				stream.pack_bytes(nonce, 16);
				stream.pack_bytes(server_nonce, 16);
				stream.pack_int64(retry_id);
				stream.pack_string(g_b);
				return stream.get_buffer();
			}
		};

		class DHGenOk : public TLPacket {
		public:
			char nonce[16];
			char server_nonce[16];
			char new_nonce_hash1[16];

			binary_buffer write() const {
				throw not_implemented_error();
			}

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				size_t offset = 4;
				stream.unpack_bytes(16, offset).copy(nonce, 16);
				offset += 16;
				stream.unpack_bytes(16, offset).copy(server_nonce, 16);
				offset += 16;
				stream.unpack_bytes(16, offset).copy(new_nonce_hash1, 16);
			}
		};

		class container : public TLPacket {
		public:
			std::vector<mtproto::session::message_t> objects;

			static bool is_container(const mtproto::data::binary_buffer& buffer) {
				uint32_t packet_id;
				memcpy(&packet_id, buffer.get_data_pointer(), 4);
				if (!mtproto::data::binary_stream::is_little_endian) {
					packet_id = _byteswap_ulong(packet_id);
				}
				return packet_id == 0x73f1f8dc;
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				if (stream.unpack_int32(0) != 0x73f1f8dc) throw std::invalid_argument("invalid packet was given!");
				uint32_t objects_count = stream.unpack_int32(4);
				size_t offset = 8;
				objects.reserve(objects_count);
				for (int i = 0; i < objects_count; i++) {
					uint64_t msg_id = stream.unpack_int64(offset);
					offset += 8;
					uint32_t seq_no = stream.unpack_int32(offset);
					offset += 4;
					uint32_t length = stream.unpack_int32(offset);
					offset += 4;
					mtproto::data::binary_buffer data = stream.unpack_bytes(length, offset);
					mtproto::message::message_details details;
					details.msg_id = msg_id;
					details.seq_no = seq_no;
					details.server_salt = 0;
					details.session_id = 0;
					mtproto::session::message_t new_message(std::move(details), std::move(data));
					objects.push_back(std::move(new_message));
					offset += length;
				}
			}
		};

		class help_getConfig : public TLPacket {
		public:

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0xc4f9186b);
				return stream.get_buffer();
			}
		};

		class Ping : public TLPacket {
		public:

			uint64_t ping_id;

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0x347773c5);
				stream.pack_int64(ping_id);
				return stream.get_buffer();
			}
		};

		class Pong : public TLPacket {
		public:

			uint64_t msg_id;
			uint64_t ping_id;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				msg_id = stream.unpack_int64(4);
				ping_id = stream.unpack_int64(12);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class bad_server_salt : public TLPacket {
		public:

			uint64_t bad_msg_id;
			uint32_t bad_msg_seq_no;
			uint32_t error_code;
			uint64_t new_server_salt;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				bad_msg_id = stream.unpack_int64(4);
				bad_msg_seq_no = stream.unpack_int32(12);
				error_code = stream.unpack_int32(16);
				new_server_salt = stream.unpack_int64(20);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class bad_msg_notification : public TLPacket {
		public:

			uint64_t bad_msg_id;
			uint32_t bad_msg_seq_no;
			uint32_t error_code;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				bad_msg_id = stream.unpack_int64(4);
				bad_msg_seq_no = stream.unpack_int32(12);
				error_code = stream.unpack_int32(16);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class MsgAcks : public TLPacket {
		public:

			std::vector<uint64_t> acks;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				uint32_t acks_count = stream.unpack_int32(8);
				size_t offset = 12;
				for (int i = 0; i < acks_count; i++) {
					acks.push_back(stream.unpack_int32(offset));
					offset += 4;
				}
			}

			binary_buffer write() const {
				binary_stream stream;
				stream.pack_int32(0x62d6b459);
				stream.pack_int32(0x1cb5c415);
				stream.pack_int32(acks.size());
				for (int i = 0; i < acks.size(); i++) {
					stream.pack_int32(acks[i]);
				}
				return stream.get_buffer();
			}
		};

		class RpcResult : public TLPacket {
		public:
			
			uint64_t req_msg_id;
			mtproto::data::binary_buffer result;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				req_msg_id = stream.unpack_int64(4);
				result = stream.unpack_bytes(stream.get_buffer().get_size() - 12, 12);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class Gzipped : public TLPacket {
		public:

			mtproto::data::binary_buffer packed;

			void read(immutable_data_view data) {
				binary_stream_reader stream(data);
				size_t offset = 4;
				packed = stream.unpack_string(offset);
			}

			binary_buffer write() const {
				throw not_implemented_error();
			}
		};

		class InitConnection : public TLPacket {
		public:

			uint32_t api_id;
			std::string device_model;
			std::string system_version;
			std::string app_version;
			std::string system_lang_code;
			std::string lang_pack;
			std::string lang_code;
			mtproto::data::binary_buffer query;

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				mtproto::data::binary_stream stream;
				stream.pack_int32(0xc1cd5ea9);
				stream.pack_int32(0x00000000);
				stream.pack_int32(api_id);
				stream.pack_string(device_model);
				stream.pack_string(system_version);
				stream.pack_string(app_version);
				stream.pack_string(system_lang_code);
				stream.pack_string(lang_pack);
				stream.pack_string(lang_code);
				stream.pack_bytes(query);
				return stream.get_buffer();
			}
		};

		class InvokeWithLayer : public TLPacket {
		public:

			uint32_t layer;
			mtproto::data::binary_buffer query;

			void read(immutable_data_view data) {
				throw not_implemented_error();
			}

			binary_buffer write() const {
				mtproto::data::binary_stream stream;
				stream.pack_int32(0xda9b0d0d);
				stream.pack_int32(layer);
				stream.pack_bytes(query);
				return stream.get_buffer();
			}
		};
	}
}