#include "pcappriv.h"

void anon_init(struct anon_keys *anon)
{
	anon->key = anon_key_new();
	anon_key_set_passphase(anon->key, anon->passphase);
	anon->key6 = anon_key_new();
	anon_key_set_passphase(anon->key6, anon->passphase);
}

void anon_release(struct anon_keys *anon)
{
	anon_ipv4_delete(anon->ip);
	anon_key_delete(anon->key);
	anon_ipv6_delete(anon->ip6);
	anon_key_delete(anon->key6);
}

void anon4(struct anon_keys *anon, struct in_addr *addr)
{
	struct in_addr anon_ip;

	if (!cache_get4(addr)) {
		anon->ip = anon_ipv4_new();
		anon_ipv4_set_key(anon->ip, anon->key);
		anon_ipv4_map_pref(anon->ip, addr->s_addr, &anon_ip.s_addr);

		cache_put4(addr, &anon_ip);
		memcpy(addr, &anon_ip, sizeof(struct in_addr));
	}
}

void anon6(struct anon_keys *anon, struct in6_addr *addr)
{
	struct in6_addr anon_ip;

	if (!cache_get6(addr)) {
		anon->ip6 = anon_ipv6_new();
		anon_ipv6_set_key(anon->ip6, anon->key6);
		anon_ipv6_map_pref(anon->ip6, *addr, &anon_ip);

		cache_put6(addr, &anon_ip);
		memcpy(addr, &anon_ip, sizeof(struct in6_addr));
	}
}

