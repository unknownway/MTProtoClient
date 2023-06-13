#pragma once

#include "buffer.h"
#include "binary_stream.h"

namespace mtproto {

	class TLPacket {
	public:
		virtual void read(mtproto::data::immutable_data_view data) = 0;
		virtual mtproto::data::binary_buffer write() const = 0;
		static uint32_t get_packet_id(const mtproto::data::binary_buffer& packet) {
			uint32_t packet_id;
			memcpy(&packet_id, packet.get_data_pointer(), 4);
			if (!mtproto::data::binary_stream::is_little_endian) {
				packet_id = _byteswap_ulong(packet_id);
			}
			return packet_id;
		}
	};
}