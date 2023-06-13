#ifndef _BRENT_H_
#define _BRENT_H_

#include <stdint.h>

namespace mtproto {

    namespace crypto {

        typedef struct _brent_pq {
            uint64_t pq;
            uint32_t p;
            uint32_t q;
        } brent_pq;

        void decompose(brent_pq* pq);
    }
}

#endif