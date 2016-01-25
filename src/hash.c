#include "pcappriv.h"

void cache_init()
{
	h4 = kh_init(iv4);
	h6 = kh_init(iv6);
}

void cache_release()
{
	kh_destroy(iv4, h4);
	kh_destroy(iv6, h6);
}

void cache_put4(const struct in_addr *ikey, const struct in_addr *ival)
{
	int ret;
	khint_t k;
	const hash4_t v4 = { *ikey, *ival };

	k = kh_put(iv4, h4, ikey->s_addr, &ret);
	pr_debug("v4: %s, %s\n", inet_ntoa(v4.key), inet_ntoa(v4.val));
	if (!ret) {
		kh_del(iv4, h4, k);
		pr_err("cache_put4: failed kh_put\n");
	} else {
		kh_value(h4, k) = v4;
	}
	return;
}

int cache_get4(struct in_addr *addr)
{
	int is_missing, ret = 0;
	khint_t k;
	hash4_t v4;

	k = kh_get(iv4, h4, addr->s_addr);
	is_missing = (k == kh_end(h4));
	if (is_missing) {
		pr_debug("4:val is missing: %d", k);
	} else {
		v4 = kh_value(h4, k);
		if (v4.key.s_addr != addr->s_addr) {
			pr_err("4:key is mismatch: %d, %d", v4.key.s_addr, addr->s_addr);
		} else {
			memcpy(addr, &v4.val, sizeof(struct in_addr));
			ret = 1;
		}
	}
	return ret;
}

void cache_put6(const struct in6_addr *ikey, const struct in6_addr *ival)
{
	int ret;
	khint_t k;
	hash6_t v6;
  
	addr6_copy(&v6.key, ikey);
	addr6_copy(&v6.val, ival);

	k = kh_put(iv6, h6, addr6_hash(ikey), &ret);
	if (!ret) {
		kh_del(iv6, h6, k);
		pr_debug("cache_put6: failed kh_put");
	} else {
		kh_value(h6, k) = v6;
	}
	return;
}

int cache_get6(struct in6_addr *addr)
{
	int is_missing, ret = 0;
	khint_t k;
	hash6_t v6;

	k = kh_get(iv6, h6, addr6_hash(addr));
	is_missing = (k == kh_end(h6));
	if (is_missing) {
		pr_debug("6:val is missing: %d", k);
	} else {
		v6 = kh_value(h6, k);
		if (!addr6_eq(&v6.key, addr)) {
			pr_debug("6:key is mismatch: %d, %d", addr6_hash(&v6.key), addr6_hash(addr));
			//pr_in6(&v6.key);
			//pr_in6(addr);
		} else {
			memcpy(addr, &v6.val, sizeof(struct in6_addr));
			ret = 1;
		}
	}
	return ret;
}

