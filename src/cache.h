#ifndef _hash_h_
#define _hash_h_

#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <netinet/in.h>

#include "khash.h"

#define hash_data_size    10000000

typedef struct {
	struct in_addr key;
	uint32_t val;
} hash4_t;

typedef struct {
	struct in6_addr key;
	uint32_t val;
} hash6_t;

KHASH_MAP_INIT_INT(iv4, hash4_t)
KHASH_MAP_INIT_INT(iv6, hash6_t)

khash_t(iv4) *h4;
khash_t(iv6) *h6;

static inline uint32_t addr6_hash(const struct in6_addr *a) {
	return (a->s6_addr32[3] ^ a->s6_addr32[2] ^
	        a->s6_addr32[1] ^ a->s6_addr32[0]);
}

#if 0
static inline uint32_t addr6_hash(const struct in6_addr *a) {
	const unsigned long *ul = (const unsigned long *)a;
	unsigned long x = ul[0] ^ ul[1];
	return (uint32_t)(x ^ (x >> 32));
}
#endif


static inline uint32_t addr6_eq(const struct in6_addr *a, const struct in6_addr *b) {
	return ((a->s6_addr32[3] == b->s6_addr32[3]) &&
	        (a->s6_addr32[2] == b->s6_addr32[2]) &&
	        (a->s6_addr32[1] == b->s6_addr32[1]) &&
	        (a->s6_addr32[0] == b->s6_addr32[0]));
}

#endif /* _hash_h_ */

