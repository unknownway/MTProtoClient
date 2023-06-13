#include "buffer.h"

namespace mtproto {

	namespace data {

		static bool is_printable(char c) {
			if (c >= 0x20 && c < 0x7f) {
				return true;
			}
			return false;
		}

		static char tetrad_to_sym(char c) {
			c = c & 0xF;
			if (c <= 9) {
				return c + '0';
			}
			switch (c) {
			case 0xA:
				return 'a';
			case 0xB:
				return 'b';
			case 0xC:
				return 'c';
			case 0xD:
				return 'd';
			case 0xE:
				return 'e';
			case 0xF:
				return 'f';
			}
		}

		static void write_byte_code(char c, char* buffer) {
			const char* prefix = "\\x";
			memcpy(buffer, prefix, 2);
			buffer += 2;
			*buffer = tetrad_to_sym(c >> 4);
			++buffer;
			*buffer = tetrad_to_sym(c);
			++buffer;
			*buffer = '\0';
		}

		void dump_bytes(std::ostream& stream, const char* data, size_t size) {
			stream << "b\"";
			for (int i = 0; i < size; i++) {
				char c = data[i];
				if (is_printable(c)) {
					if (c == '"') {
						stream << '\\';
						stream << '"';
					}
					else if (c == '\\') {
						stream << "\\\\";
					}
					else {
						stream << c;
					}
				}
				else {
					char byte_code[5];
					write_byte_code(c, byte_code);
					stream << byte_code;
				}
			}
			stream << "\"";
		}

		std::ostream& operator<<(std::ostream& lhs, const binary_buffer& rhs) {
			lhs << "b\"";
			for (const auto byte : rhs.get_data()) {
				char c = (char)byte;
				if (is_printable(c)) {
					if (c == '"') {
						lhs << '\\';
						lhs << '"';
					}
					else if (c == '\\') {
						lhs << "\\\\";
					}
					else {
						lhs << c;
					}
				}
				else {
					char byte_code[5];
					write_byte_code(c, byte_code);
					lhs << byte_code;
				}
			}
			lhs << "\"";
			return lhs;
		}
	}
}