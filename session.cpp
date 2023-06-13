#include <iostream>
#include <chrono>
#include "session.h"
#include "mtproto_objects.h"
#include "gzip.h"

namespace mtproto::session {
	session::session(const session_details& details, mtproto::transport::transport_t transport) : m_details(details), m_transport(transport) {}
	session::session(const session_details& details) : m_details(details) {
		m_transport = std::make_shared<mtproto::transport::tcp_intermediate>(mtproto::transport::tcp_intermediate(details.ip, details.port));
	}
	
	void session::initialize() {
		m_server_salt.store(mtproto::crypto::random_int(0x00, 0xFFFFFFFFFFFFFFFF));
		m_session_id = mtproto::crypto::random_int(0x00, 0xFFFFFFFFFFFFFFFF);
		m_transport->connect();
		m_is_working.store(true);
		std::thread receiver(packet_receiver, shared_from_this());
		receiver.detach();
		m_service_threads.push_back(std::move(receiver));
		mtproto::base_objects::Ping ping;
		ping.ping_id = 0x7fff;
		send_packet(ping);
	}

	uint32_t session::gen_seq_no(bool content_related) {
		uint32_t seq_no = m_seq_no.load() * 2;
		if (content_related) {
			++m_seq_no;
			seq_no += 1;
		}
		return seq_no;
	}

	void session::process_message(message_t& message, std::shared_ptr<session> current_session) {
		if (mtproto::base_objects::container::is_container(message.payload)) {
			mtproto::base_objects::container container;
			container.read(std::move(message.payload));
			for (auto& entry : container.objects) {
				entry.details.server_salt = message.details.server_salt;
				entry.details.session_id = message.details.session_id;
				process_message(entry, current_session);
			}
		}
		else {
			if (message.details.seq_no % 2 != 0) {
				current_session->m_acks.push_ack(message.details.msg_id);
			}
			const uint32_t packet_id = mtproto::TLPacket::get_packet_id(message.payload);
			if (packet_id == 0xedab447b) { // bad server salt
				mtproto::base_objects::bad_server_salt bad_server_salt;
				mtproto::data::binary_buffer buffer = message.payload;
				bad_server_salt.read(std::move(buffer));
				current_session->m_server_salt.store(bad_server_salt.new_server_salt);
				std::cout << "new server salt: " << bad_server_salt.new_server_salt << std::endl;
				incoming_message save_message(bad_server_salt.bad_msg_id, std::move(message.payload));
				current_session->m_incoming_messages.push(std::move(save_message));
			}
			else if (packet_id == 0xa7eff811) { // bad msg notification
				mtproto::base_objects::bad_msg_notification bad_msg_notification;
				mtproto::data::binary_buffer buffer = message.payload;
				bad_msg_notification.read(std::move(buffer));
				incoming_message save_message(bad_msg_notification.bad_msg_id, std::move(buffer));
				current_session->m_incoming_messages.push(std::move(save_message));
			}
			else if (packet_id == 0x9ec20908) { // new session created
				std::cout << "new session created!" << std::endl;
			}
			else if (packet_id == 0xf35c6d01) { // rpc_result
				mtproto::base_objects::RpcResult rpc_result;
				rpc_result.read(std::move(message.payload));
				incoming_message save_message(rpc_result.req_msg_id, std::move(rpc_result.result));
				current_session->m_incoming_messages.push(std::move(save_message));
			}
			else if (packet_id == 0x3072cfa1) { // gzip
				mtproto::base_objects::Gzipped gzipped;
				gzipped.read(std::move(message.payload));
				mtproto::data::binary_buffer unpacked = mtproto::gzip::inflate(gzipped.packed);
				message.payload = std::move(unpacked);
				process_message(message, current_session);
			}
			else if (packet_id == 0x347773c5) { // pong
				mtproto::base_objects::Pong pong;
				pong.read(std::move(message.payload));
				incoming_message save_message(pong.msg_id, mtproto::data::binary_buffer());
				current_session->m_incoming_messages.push(std::move(save_message));
			}
			//std::cout << std::hex << packet_id << std::dec << std::endl;
		}
	}

	void session::packet_receiver(std::shared_ptr<session> current_session) {
		while (current_session->m_is_working.load()) {
			try {
				mtproto::data::binary_buffer received = current_session->m_transport->receive();
				mtproto::message::message_details details;
				mtproto::data::binary_buffer buffer = mtproto::message::EncryptedMessage::read(current_session->m_details, received, details);
				message_t received_message(std::move(details), std::move(buffer));
				process_message(received_message, current_session);
				if (current_session->m_acks.get_size() > 8) {
					auto msg_ids = current_session->m_acks.get_all_acks();
					mtproto::base_objects::MsgAcks acks;
					acks.acks = std::move(msg_ids);
					current_session->send_packet_via_transport(acks, false);
				}
			}
			catch (mtproto::transport::invalid_socket& error) {
				if (!current_session->m_is_working.load()) return;
				current_session->m_transport->connect();
				current_session->m_seq_no.store(0);
			}
			catch (std::exception& e) {
				std::cout << e.what() << std::endl;
				// just continue receiving...
			}
		}
	}

	std::shared_ptr<session> session::create(const session_details& details) {
		session* new_session = new session(details);
		return std::shared_ptr<session>(new_session);
	}

	std::shared_ptr<session> session::create(const session_details& details, mtproto::transport::transport_t transport) {
		session* new_session = new session(details, transport);
		return std::shared_ptr<session>(new_session);
	}

	void session::close() {
		m_is_working.store(false);
		m_transport->close();
		m_incoming_messages.clear();
		m_seq_no.store(0);
		m_session_id = 0;
	}

	uint64_t session::send_packet_via_transport(const mtproto::TLPacket& object, bool content_related) {
		mtproto::message::message_details details;
		details.msg_id = m_msg_id();
		uint64_t msg_id = details.msg_id;
		details.seq_no = gen_seq_no(content_related);
		details.server_salt = m_server_salt.load();
		details.session_id = m_session_id;
		mtproto::data::binary_buffer serialized = object.write();
		mtproto::data::binary_buffer encapsulated_packet = mtproto::message::EncryptedMessage::write(m_details, details, serialized);
		m_transport->send(std::move(encapsulated_packet));
		return msg_id;
	}

	uint64_t session::get_current_time() {
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
	}

	mtproto::data::binary_buffer session::send_packet(const mtproto::TLPacket& object, bool content_related, bool wait_response) {
		uint64_t msg_id = send_packet_via_transport(object, content_related);
		if (wait_response) {
			uint64_t end_time = get_current_time() + receive_timeout_milliseconds;
			while (get_current_time() < end_time) {
				incoming_message message;
				if (m_incoming_messages.try_pop(message)) {
					if (message.msg_id == msg_id) {
						return message.payload;
					}
				}
				std::this_thread::yield();
			}
		}
		return mtproto::data::binary_buffer();
	}

	session::~session() {
		close();
	}

	//mtproto::data::binary_buffer session::send_packet(const mtproto::TLPacket& object, bool content_related, bool wait_response) {
	//	mtproto::data::binary_buffer serialized = object.write();
	//	m_outgoing_messages.push_back(std::move(serialized));
	//	return mtproto::data::binary_buffer();
	//}
}