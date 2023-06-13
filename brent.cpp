#include <stdint.h>
#include <inttypes.h>
#include <openssl/bn.h>
#include "random.h"
#include "endian.h"
#include "brent.h"

typedef BIGNUM* brent_t;

#define CLEANUP_BRENT_CONTEXT() { BN_free(q); BN_free(N); BN_free(ONE); BN_free(y); BN_free(c); BN_free(m); BN_free(r); BN_free(x); BN_free(k); BN_free(sub_result); BN_free(max_loop_value); BN_free(i); }

brent_t random_bignum(uint64_t min, uint64_t max) {
    uint64_t value = mtproto::crypto::random_int(min, max);
    value = swap_bytes_64(value);
    brent_t number = BN_new();
    BN_bin2bn((const unsigned char*)&value, sizeof(uint64_t), number);
    return number;
}

brent_t bignum_from_string(const char* number) {
    brent_t bignum = 0;
    BN_dec2bn(&bignum, number);
    return bignum;
}

brent_t bignum_from_uint32(uint32_t number) {
    number = swap_bytes_32(number);
    return BN_bin2bn((const unsigned char*)&number, sizeof(uint32_t), 0);
}

brent_t bignum_from_uint64(uint64_t number) {
    number = swap_bytes_64(number);
    return BN_bin2bn((const unsigned char*)&number, sizeof(uint64_t), 0);
}

brent_t bignum_clone(brent_t number) {
    brent_t bignum = BN_new();
    BN_copy(bignum, number);
    return bignum;
}

uint32_t uint32_from_bignum(brent_t number) {
    uint32_t native_number = 0;
    BN_bn2bin(number, (unsigned char*)&native_number);
    return swap_bytes_32(native_number);
}

uint64_t uint64_from_bignum(brent_t number) {
    uint64_t native_number = 0;
    BN_bn2bin(number, (unsigned char*)&native_number);
    return swap_bytes_64(native_number);
}

void bignum_mul(brent_t a, brent_t b, BN_CTX* context) {
    if(!BN_mul(a, a, b, context)) {
        abort();
    }
}

brent_t bignum_mod(brent_t a, brent_t b, BN_CTX* context) {
    brent_t reminder = BN_new();
    BN_div(0, reminder, a, b, context);
    return reminder;
}

void bignum_abs(brent_t a) {
    //static const BIGNUM* ZERO = bignum_from_uint32(0);
    //if(BN_cmp(a, ZERO) < 0) {
   //     BN_clear_bit(a, BN_num_bits(a) - 1);
   // }
   BN_set_negative(a, 0);
}

void bignum_increment(brent_t a) {
    BN_add_word(a, 1);
}

brent_t bignum_min(brent_t a, brent_t b) {
    if (BN_cmp(a, b) == -1) {
        return a;
    } else {
        return b;
    }
}

void print_bignum(const char* var_name, const brent_t number) {
	printf("%s: %s\n", var_name, BN_bn2dec(number));
}

uint32_t brent(uint64_t pq) {
    if (pq % 2 == 0) {
        return 2;
    }
    pq = swap_bytes_64(pq);
    brent_t N = BN_bin2bn((const unsigned char*)&pq, sizeof(pq), 0);
    BN_CTX* context = BN_CTX_new();
    brent_t y = random_bignum(1, pq-1), c = random_bignum(1, pq-1), m = random_bignum(1, pq-1);
    brent_t g = bignum_from_uint32(1), r = bignum_from_uint32(1), q = bignum_from_uint32(1);
    brent_t x = bignum_clone(y);
    brent_t ys = BN_new();
    brent_t k = BN_new();
    brent_t sub_result = BN_new();
    brent_t max_loop_value = BN_new();
    brent_t i = BN_new();
    const brent_t ONE = bignum_from_uint32(1);
    while(BN_cmp(g, ONE) == 0) {
        BN_copy(x, y);
        BN_zero(i);
        for (; BN_cmp(i, r) == -1; bignum_increment(i)) {
            bignum_mul(y, y, context);
            BN_div(0, y, y, N, context);
            BN_add(y, y, c);
            BN_div(0, y, y, N, context);
        }
        BN_zero(k);
        while (BN_cmp(k, r) == -1 && BN_cmp(g, ONE) == 0) {
            BN_copy(ys, y);
            BN_zero(sub_result);
            BN_sub(sub_result, r, k);
            brent_t min_value_ptr = bignum_min(m, sub_result);
            BN_copy(max_loop_value, min_value_ptr);
            BN_zero(i);
            for(; BN_cmp(i, max_loop_value) == -1; bignum_increment(i)) {
                bignum_mul(y, y, context);
                BN_div(0, y, y, N, context);
                BN_add(y, y, c);
                BN_div(0, y, y, N, context);
                BN_zero(sub_result);
                BN_sub(sub_result, x, y);
                bignum_abs(sub_result);
                BN_mul(q, q, sub_result, context);
                BN_div(0, q, q, N, context);
            }
            BN_gcd(g, q, N, context);
            BN_add(k, k, m);
        }
        BN_mul_word(r, 2);
        if (BN_cmp(g, N) == 0) {
            while (1) {
                bignum_mul(ys, ys, context);
                BN_div(0, ys, ys, N, context);
                BN_add(ys, ys, c);
                BN_div(0, ys, ys, N, context);
                BN_zero(sub_result);
                BN_sub(sub_result, x, ys);
                BN_gcd(g, sub_result, N, context);
                if (BN_cmp(g, ONE) == 1) {
                    CLEANUP_BRENT_CONTEXT()
                    uint32_t value = uint32_from_bignum(g);
                    BN_free(g);
                    return value;
                }
            }
        }
    }
    BN_CTX_free(context);
    CLEANUP_BRENT_CONTEXT()
    uint32_t value = uint32_from_bignum(g);
    BN_free(g);
    return value;
}

namespace mtproto {

    namespace crypto {

        void decompose(brent_pq* pq) {
            uint32_t p = brent(pq->pq);
            uint32_t q = pq->pq / p;
            if (p > q) {
                uint32_t temp = p;
                p = q;
                q = temp;
            }
            pq->p = p;
            pq->q = q;
        }
    }
}