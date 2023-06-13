#include "random.h"

namespace mtproto::crypto {

    uint64_t random_int(uint64_t min, uint64_t max) {
        uint64_t random_value = 0;
        RAND_bytes((unsigned char*)&random_value, sizeof(random_value));
        random_value = min + random_value % (max - min);
        return random_value;
    }

    void random_bytes(char* data, size_t length) {
        RAND_bytes((unsigned char*)data, length);
    }
}