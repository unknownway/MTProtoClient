#pragma once

#include <stdint.h>
#include <stdexcept>
#include "buffer.h"

namespace mtproto {

	namespace data {

		class binary_stream
		{
			binary_buffer m_buffer;
			void check_offset(size_t offset);
		public:
			binary_stream(binary_buffer&& buffer) noexcept;
			binary_stream() = default;
			static bool is_little_endian;
			binary_buffer& get_buffer();
			void set_buffer(binary_buffer&& buffer);
			void pack_int16(uint16_t value);
			void pack_int32(uint32_t value);
			void pack_int64(uint64_t value);
			void pack_bytes(const binary_buffer& bytes);
			void pack_bytes(const char* data, size_t size);
			void pack_string(immutable_data_view data);

			uint16_t unpack_int16(size_t offset);
			uint32_t unpack_int32(size_t offset);
			uint64_t unpack_int64(size_t offset);
			uint32_t unpack_vector_size(size_t offset);
			binary_buffer unpack_bytes(size_t length, size_t offset);
			binary_buffer unpack_string(size_t& offset);

			size_t calculate_padding(size_t length);
		};

		class binary_stream_reader {
			immutable_data_view m_buffer;
			void check_offset(size_t offset);
		public:
			binary_stream_reader(immutable_data_view buffer);
			binary_stream_reader() = delete;
			immutable_data_view& get_buffer();
			uint16_t unpack_int16(size_t offset);
			uint32_t unpack_int32(size_t offset);
			uint64_t unpack_int64(size_t offset);
			uint32_t unpack_vector_size(size_t offset);
			binary_buffer unpack_bytes(size_t length, size_t offset);
			binary_buffer unpack_string(size_t& offset);

			size_t calculate_padding(size_t length);
		};

	}
}
