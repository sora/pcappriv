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

//typedef struct {
//	uint32_t key;
//	uint32_t val;
//} hash_v4_t;
#define hash_eq(a, b) ((a).key == (b).key)
#define hash_func(a) ((a).key)

//KHASH_INIT(iv4, hash_v4_t, char, 0, hash_func, hash_eq)
KHASH_MAP_INIT_INT(iv4, uint32_t)

khash_t(iv4) *h;

#endif /* _hash_h_ */
