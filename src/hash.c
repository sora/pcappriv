#include "hash.h"

void hash_init() {
	h4 = kh_init(iv4);
	h6 = kh_init(iv6);
}

void hash_release() {
	kh_destroy(iv4, h4);
	kh_destroy(iv6, h6);
}

void hash_put4(struct in_addr ik, uint32_t i) {
	int ret;
	khint_t k;
	hash4_t v4 = {ik, i};

	k = kh_put(iv4, h4, ik.s_addr, &ret);
	if (!ret)
		kh_del(iv4, h4, k);
	kh_value(h4, k) = v4;
}

uint32_t hash_get4(struct in_addr ik) {
	int is_missing;
	khint_t k;
	hash4_t v4;

	k = kh_get(iv4, h4, ik.s_addr);
	is_missing = (k == kh_end(h4));
	if (is_missing)
		printf("4:val is missing: %d\n", k);

	v4 = kh_value(h4, k);
	if (v4.key.s_addr != ik.s_addr)
		printf("4:key is mismatch: %d, %d\n", v4.key.s_addr, ik.s_addr);

	return v4.val;
}

void hash_put6(struct in6_addr ik, uint32_t i) {
	int ret;
	khint_t k;
	hash6_t v6 = {ik, i};

	k = kh_put(iv6, h6, addr6_hash(ik), &ret);
	if (!ret)
		kh_del(iv6, h6, k);
	kh_value(h6, k) = v6;
}

uint32_t hash_get6(struct in6_addr ik) {
	int is_missing;
	khint_t k;
	hash6_t v6;

	k = kh_get(iv6, h6, addr6_hash(ik));
	is_missing = (k == kh_end(h6));
	if (is_missing)
		printf("6:val is missing: %d\n", k);

	v6 = kh_value(h6, k);
	if (!addr6_eq(v6.key, ik))
		printf("6:key is mismatch: %d, %d\n", addr6_hash(v6.key), addr6_hash(ik));

	return v6.val;
}

void test4() {
	struct in_addr addr4;
	uint32_t i, ret;

	for (i = 0; i < hash_data_size; ++i) {
		addr4.s_addr = i;
		hash_put4(addr4, i+4);
		ret = hash_get4(addr4);
		if (ret != i+4)
			printf("get: key = %d, i = %d, ret = %d\n", addr4.s_addr, i, ret);
	}
	printf("test4: pass\n");
}

void test6() {
	struct in6_addr addr6;
	uint32_t i;
	int ret;

	for (i = 0; i < hash_data_size; ++i) {
		addr6.s6_addr32[3] = 1;
		addr6.s6_addr32[2] = i;
		addr6.s6_addr32[1] = i;
		addr6.s6_addr32[0] = i;
		hash_put6(addr6, i+6);
		ret = hash_get6(addr6);
		if (ret != i+6)
			printf("get: key = %d, i = %d, ret = %d\n", addr6_hash(addr6), i+6, ret);
	}
	printf("test6: pass\n");
}

void bench(void (*f)(void)) {
	clock_t t0, t1;
	t0  = clock();
	(*f)();
	t1  = clock();
	printf("[bench] %.3lf sec\n", (double)(t1 - t0) / CLOCKS_PER_SEC);
}

int main(int argc, char *argv[]) {
	hash_init();
	bench(test4);
	bench(test6);
	hash_release();

	return 0;
}

