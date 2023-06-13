#include "endian.h"
#include <stdlib.h>

static int swap_required = -1;

static int is_little_endian() {
	static const uint16_t value = 0x0102;
	const char* ptr = (const char*)&value;
	if (ptr[0] == 0x02) {
		return 1;
	}
	return 0;
}

static void init() {
	if (swap_required == -1) {
		swap_required = is_little_endian();
	}
}

uint32_t swap_bytes_32(uint32_t value) {
	init();
	if (swap_required == 1) {
		#ifdef __GNUC__
		return __builtin_bswap32(value);
		#else 
		return _byteswap_ulong(value);
		#endif

	}
	return value;
}

uint64_t swap_bytes_64(uint64_t value) {
	init();
	if (swap_required == 1) {
		#ifdef __GNUC__
		return __builtin_bswap64(value);
		#else 
		return _byteswap_uint64(value);
		#endif	
	}
	return value;
}