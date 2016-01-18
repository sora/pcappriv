#include "hash.h"

void hash_init() {
	h = kh_init(iv4);
}

void hash_release() {
	kh_destroy(iv4, h);
}

void hash_put4(struct in_addr ik, uint32_t i) {
	int ret;
	khint_t k;

	k = kh_put(iv4, h, ik.s_addr, &ret);
	if (!ret)
		kh_del(iv4, h, k);
	//printf("k: %d, i: %d\n", (int)k, i);
	kh_value(h, k) = i;
}

int hash_get4(struct in_addr ik) {
	int is_missing;
	khint_t k;

	k = kh_get(iv4, h, ik.s_addr);
	is_missing = (k == kh_end(h));

	if (is_missing)
		printf("val is missing: %d\n", k);

	return (int)kh_value(h, k);
}


// temorary
void test() {
	struct in_addr addr4;
	int data_size = 10000000;
	uint32_t i;
	int ret;


	for (i = 0; i < data_size; ++i) {
		addr4.s_addr = i;
		hash_put4(addr4, i+4);
		ret = hash_get4(addr4);
		if (ret != i+4)
			printf("get: key = %d, i = %d, ret = %d\n", addr4.s_addr, i, ret);
	}
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
	bench(test);
	hash_release();

	return 0;
}

