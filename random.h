#ifndef _RANDOM_H_
#define _RANDOM_H_

#include <openssl/rand.h>

namespace mtproto::crypto {

	uint64_t random_int(uint64_t min, uint64_t max);
	void random_bytes(char* data, size_t length);

}

#endif