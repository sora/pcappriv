#include "hash.h"

void hash_init() {
	h = kh_init(iv4);
}

void hash_release() {
	kh_destroy(iv4, h);
}

void hash_put4(struct in_addr *ik, uint32_t *iv) {
	int ret;
	uint32_t k;
	hash_v4_t x;

	x.key = ik->s_addr;
	x.val = *iv;

	k = kh_put(iv4, h, x, &ret);
	if (!ret)
		kh_del(iv4, h, k);
	kh_value(h, k) = *iv;
}

int hash_get4(struct in_addr *ik) {
	int k, is_missing;
	hash_v4_t x;

	x.key = ik->s_addr;

	k = kh_get(iv4, h, x);
	is_missing = (k == kh_end(h));

	if (!is_missing)
		printf("val is missing: %d\n", k);

	return k;
}


// temorary
void test() {
	struct in_addr data;
	int data_size = 10000000;
	uint32_t i;
	int ret;

	data.s_addr = 1111;

	for (i = 0; i < data_size; ++i) {
		hash_put4(&data, &i);
		printf("put: key = %d, val = %d\n", data.s_addr, i);
		ret = hash_get4(&data);
		printf("get: key = %d, val = %d\n", data.s_addr, ret);
	}
	//printf("[hash_test] size: %u (sizeof=%ld)\n", kh_size(h), sizeof(hash_v4_t));
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

