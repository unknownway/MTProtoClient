#pragma once

#include <atomic>
#include <vector>
#include <mutex>
#include "tl_packet.h"
#include "buffer.h"
#include "mtproto_session_type.h"
#include "tcp.h"
#include "msg_id.h"
#include "message.h"
#include "details/random.h"

namespace mtproto::session {

	typedef struct _message {
		mtproto::message::message_details details;
		mtproto::data::binary_buffer payload;

		_message(mtproto::message::message_details&& message_details, mtproto::data::binary_buffer&& data) : details(std::move(message_details)), payload(std::move(data)) {}
	} message_t;
	
	typedef struct _incoming_message {
		uint64_t msg_id;
		mtproto::data::binary_buffer payload;

		_incoming_message() : msg_id(0) {}
		_incoming_message(uint64_t message_id, mtproto::data::binary_buffer&& data) : msg_id(message_id), payload(std::move(data)) {}
	} incoming_message;

	namespace detail {
		class acks {
			std::mutex m_guard;
			std::vector<uint64_t> m_msg_ids;
		public:
			uint64_t get_size() {
				std::lock_guard<std::mutex> guard(m_guard);
				return m_msg_ids.size();
			}

			void push_ack(uint64_t msg_id) {
				std::lock_guard<std::mutex> guard(m_guard);
				m_msg_ids.push_back(msg_id);
			}

			std::vector<uint64_t> get_all_acks() {
				std::lock_guard<std::mutex> guard(m_guard);
				std::vector<uint64_t> msg_ids = std::move(m_msg_ids);
				m_msg_ids.clear();
				return msg_ids;
			}
		};

		template <typename T>
		class threadsafe_vector {
			std::mutex m_guard;
			std::vector<T> m_vector;
		public:
			threadsafe_vector() {}
			void push(T&& element) {
				std::lock_guard<std::mutex> lock(m_guard);
				m_vector.push_back(std::move(element));
			}
			void push(const T& element) {
				std::lock_guard<std::mutex> lock(m_guard);
				m_vector.push_back(element);
			}
			size_t get_size() {
				std::lock_guard<std::mutex> lock(m_guard);
				return m_vector.size();
			}
			bool try_pop(T& element) {
				std::lock_guard<std::mutex> lock(m_guard);
				if (m_vector.size() > 0) {
					element = m_vector[0];
					m_vector.pop_back();
					return true;
				}
				return false;
			}
			void clear() {
				std::lock_guard<std::mutex> lock(m_guard);
				m_vector.clear();
			}
			std::mutex& get_guard() {
				return m_guard;
			}
		};
	}

	class session : public std::enable_shared_from_this<session> {
		static constexpr uint64_t receive_timeout_milliseconds = 10000;
		session_details m_details;
		mtproto::transport::transport_t m_transport;
		std::atomic<bool> m_is_working = false;
		detail::acks m_acks;
		detail::threadsafe_vector<incoming_message> m_incoming_messages;
		std::vector<std::thread> m_service_threads;
		msg_id m_msg_id;
		std::atomic<uint64_t> m_server_salt = 0;
		uint64_t m_session_id = 0;
		std::atomic<uint32_t> m_seq_no = 0;
		uint32_t gen_seq_no(bool content_related);
		uint64_t send_packet_via_transport(const mtproto::TLPacket& object, bool content_related = true);
		static uint64_t get_current_time();
		static void packet_receiver(std::shared_ptr<session> current_session);
		static void process_message(message_t& message, std::shared_ptr<session> current_session);
		session(const session_details& details, mtproto::transport::transport_t transport);
		session(const session_details& details);

	public:
		session() = delete;
		session(const session&) = delete;
		session(session&&) noexcept = delete;
		session& operator=(const session&) = delete;
		session& operator=(session&&) = delete;
		static std::shared_ptr<session> create(const session_details& details);
		static std::shared_ptr<session> create(const session_details& details, mtproto::transport::transport_t transport);
		void initialize();
		void close();
		mtproto::data::binary_buffer send_packet(const mtproto::TLPacket& object, bool content_related = true, bool wait_response = true);
		void disconnect() {
			m_transport->close();
		}
		~session();
	};

	typedef std::shared_ptr<session> session_type;
}