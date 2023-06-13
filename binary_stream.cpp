#include "binary_stream.h"

namespace mtproto {

	namespace data {

		static bool check_byte_order() {
			static const uint16_t value = 0x0102;
			const char* ptr = (const char*)&value;
			if (ptr[0] == 0x02) {
				return true;
			}
			return false;
		}

		bool binary_stream::is_little_endian = check_byte_order();

		binary_stream::binary_stream(binary_buffer&& buffer) noexcept : m_buffer(std::move(buffer)) {}

		void binary_stream::pack_int16(uint16_t value) {
			if (!is_little_endian)
				value = _byteswap_ushort(value);
			m_buffer.append((char*)&value, 2);
		}

		void binary_stream::pack_int32(uint32_t value) {
			if (!is_little_endian)
				value = _byteswap_ulong(value);
			m_buffer.append((char*)&value, 4);
		}

		void binary_stream::pack_int64(uint64_t value) {
			if (!is_little_endian)
				value = _byteswap_uint64(value);
			m_buffer.append((char*)&value, 8);
		}

		void binary_stream::pack_bytes(const binary_buffer& bytes) {
			m_buffer.append((const char*)bytes.get_data().data(), bytes.get_size());
		}

		void binary_stream::pack_bytes(const char* data, size_t size) {
			m_buffer.append((const char*)data, size);
		}

		void binary_stream::pack_string(immutable_data_view data) {
			if (data.get_size() < 254) {
				char short_size = data.get_size() & 0xFF;
				m_buffer.append(&short_size, 1);
				m_buffer.append(data.get_data(), data.get_size());
				m_buffer.add_padding(calculate_padding(1 + static_cast<size_t>(short_size)));
			}
			else {
				char short_size = 254;
				m_buffer.append(&short_size, 1);
				uint32_t large_data_size = data.get_size() & 0xFFFFFF;
				if (!is_little_endian) {
					large_data_size = _byteswap_ulong(large_data_size);
				}
				m_buffer.append((const char*)&large_data_size, 3);
				m_buffer.append(data.get_data(), large_data_size);
				m_buffer.add_padding(calculate_padding(4 + static_cast<size_t>(large_data_size)));
			}
		}

		void binary_stream::check_offset(size_t offset) {
			if (offset > m_buffer.get_size()) {
				throw std::invalid_argument("buffer is too few for this offset!");
			}
		}


		void binary_stream_reader::check_offset(size_t offset) {
			if (offset > m_buffer.get_size()) {
				throw std::invalid_argument("buffer is too few for this offset!");
			}
		}

		binary_buffer& binary_stream::get_buffer() {
			return m_buffer;
		}

		void binary_stream::set_buffer(binary_buffer&& buffer) {
			m_buffer = std::move(buffer);
		}

		uint16_t binary_stream::unpack_int16(size_t offset) {
			check_offset(offset + 2);
			uint16_t value;
			memcpy(&value, m_buffer.get_data().data() + offset, 2);
			if (!is_little_endian)
				value = _byteswap_ushort(value);
			return value;
		}

		uint32_t binary_stream::unpack_int32(size_t offset) {
			check_offset(offset + 4);
			uint32_t value;
			memcpy(&value, m_buffer.get_data().data() + offset, 4);
			if (!is_little_endian)
				value = _byteswap_ulong(value);
			return value;
		}

		uint64_t binary_stream::unpack_int64(size_t offset) {
			check_offset(offset + 8);
			uint64_t value;
			memcpy(&value, m_buffer.get_data().data() + offset, 8);
			if (!is_little_endian)
				value = _byteswap_uint64(value);
			return value;
		}

		uint32_t binary_stream::unpack_vector_size(size_t offset) {
			check_offset(offset + 8);
			if (unpack_int32(offset) != 0x1cb5c415) {
				throw std::invalid_argument("invalid vector was provided!");
			}
			return unpack_int32(offset + 4);
		}

		binary_buffer binary_stream::unpack_bytes(size_t length, size_t offset) {
			check_offset(offset + length);
			std::vector<std::byte> bytes(m_buffer.get_data().data() + offset, m_buffer.get_data().data() + offset + length);
			binary_buffer new_buffer(std::move(bytes));
			return new_buffer;
		}

		size_t binary_stream::calculate_padding(size_t length) {
			if (length % 4 == 0) return 0;
			return 4 - length % 4;
		}

		binary_buffer binary_stream::unpack_string(size_t& offset) {
			check_offset(offset);
			uint8_t flag = (uint8_t)m_buffer.get_data()[offset];
			if (flag < 254) {
				size_t total_length = 1LL + static_cast<size_t>(flag);
				total_length += calculate_padding(total_length);
				check_offset(total_length);
				binary_buffer data;
				data.get_data().insert(data.get_data().begin(), m_buffer.get_data().begin() + offset + 1, m_buffer.get_data().begin() + offset + 1 + flag);
				offset += total_length;
				return data;
			}
			else {
				uint32_t large_data_length = 0;
				memcpy(&large_data_length, m_buffer.get_data().data() + offset + 1, 3);
				if (!is_little_endian)
					large_data_length = _byteswap_ulong(large_data_length);
				size_t total_length = 4LL + static_cast<size_t>(large_data_length);
				total_length += calculate_padding(total_length);
				check_offset(total_length);
				binary_buffer data;
				data.get_data().insert(data.get_data().begin(), m_buffer.get_data().begin() + offset + 4, m_buffer.get_data().begin() + offset + 4 + large_data_length);
				offset += total_length;
				return data;
			}
		}

		uint16_t binary_stream_reader::unpack_int16(size_t offset) {
			check_offset(offset + 2);
			uint16_t value;
			memcpy(&value, m_buffer.get_data() + offset, 2);
			if (!binary_stream::is_little_endian)
				value = _byteswap_ushort(value);
			return value;
		}

		uint32_t binary_stream_reader::unpack_int32(size_t offset) {
			check_offset(offset + 4);
			uint32_t value;
			memcpy(&value, m_buffer.get_data() + offset, 4);
			if (!binary_stream::is_little_endian)
				value = _byteswap_ulong(value);
			return value;
		}

		uint64_t binary_stream_reader::unpack_int64(size_t offset) {
			check_offset(offset + 8);
			uint64_t value;
			memcpy(&value, m_buffer.get_data() + offset, 8);
			if (!binary_stream::is_little_endian)
				value = _byteswap_uint64(value);
			return value;
		}

		uint32_t binary_stream_reader::unpack_vector_size(size_t offset) {
			check_offset(offset + 8);
			if (unpack_int32(offset) != 0x1cb5c415) {
				throw std::invalid_argument("invalid vector was provided!");
			}
			return unpack_int32(offset + 4);
		}

		binary_buffer binary_stream_reader::unpack_bytes(size_t length, size_t offset) {
			check_offset(offset + length);
			std::vector<std::byte> bytes((std::byte*)m_buffer.get_data() + offset, (std::byte*)m_buffer.get_data() + offset + length);
			binary_buffer new_buffer(std::move(bytes));
			return new_buffer;
		}

		size_t binary_stream_reader::calculate_padding(size_t length) {
			if (length % 4 == 0) return 0;
			return 4 - length % 4;
		}

		binary_buffer binary_stream_reader::unpack_string(size_t& offset) {
			check_offset(offset);
			uint8_t flag = (uint8_t)m_buffer.get_data()[offset];
			if (flag < 254) {
				size_t total_length = 1LL + static_cast<size_t>(flag);
				total_length += calculate_padding(total_length);
				check_offset(total_length);
				binary_buffer data;
				data.get_data().insert(data.get_data().begin(), (std::byte*)m_buffer.get_data() + offset + 1, (std::byte*)m_buffer.get_data() + offset + 1 + flag);
				offset += total_length;
				return data;
			}
			else {
				uint32_t large_data_length = 0;
				memcpy(&large_data_length, m_buffer.get_data() + offset + 1, 3);
				if (!binary_stream::is_little_endian)
					large_data_length = _byteswap_ulong(large_data_length);
				size_t total_length = 4LL + static_cast<size_t>(large_data_length);
				total_length += calculate_padding(total_length);
				check_offset(total_length);
				binary_buffer data;
				data.get_data().insert(data.get_data().begin(), (std::byte*)m_buffer.get_data() + offset + 4, (std::byte*)m_buffer.get_data() + offset + 4 + large_data_length);
				offset += total_length;
				return data;
			}
		} 

		binary_stream_reader::binary_stream_reader(immutable_data_view buffer) : m_buffer(buffer) {}

		immutable_data_view& binary_stream_reader::get_buffer() {
			return m_buffer;
		}
	}
}