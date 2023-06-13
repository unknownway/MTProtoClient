#pragma once

#include <stdint.h>
#include <time.h>
#include "details/random.h"

namespace mtproto::session {

	class msg_id {

		uint64_t m_last_time;
		int64_t m_difference;

		uint64_t get_current_time() {
			return time(0);
		}

	public:

		msg_id() : m_last_time(0), m_difference(0) {}

		msg_id(const msg_id& object) : m_last_time(object.m_last_time), m_difference(object.m_difference) {}

		msg_id(msg_id&& object) noexcept : m_last_time(object.m_last_time), m_difference(object.m_difference) {} // just copy primitive values, because there are no reasons to move values

		uint64_t operator()() {
			uint64_t current_time = get_current_time();
			current_time += m_difference;
			current_time <<= 32;
			if (current_time <= m_last_time) {
				current_time += m_last_time - current_time;
				current_time += mtproto::crypto::random_int(100, 1000);
				if (current_time % 4 != 0) {
					current_time += 4 - current_time % 4;
				}
				m_last_time = current_time;
			}
			else {
				if (current_time % 4 != 0) {
					current_time += 4 - current_time % 4;
				}
				m_last_time = current_time;
			}
			return current_time;
		}

		void set_server_time(uint64_t server_msg_id) {
			server_msg_id >>= 32;
			int64_t current_time = get_current_time();
			int64_t difference = current_time - server_msg_id;
			if (difference < 300 && difference > -300) {
				m_difference = 0;
			}
			else {
				m_difference = difference;
			}
		}
	};
}