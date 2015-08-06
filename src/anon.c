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

inline struct in_addr anon4(struct anon_keys *anon,
		const struct pcap_pkt *pkt)
{

	struct in_addr anon_ip;

	anon->ip = anon_ipv4_new();
	anon_ipv4_set_key(anon->ip, anon->key);
	anon_ipv4_map_pref(anon->ip, pkt->ip4.ip_src.s_addr, &anon_ip.s_addr);

	return anon_ip;
}

inline struct in6_addr anon6(struct anon_keys *anon,
		const struct pcap_pkt *pkt)
{
	struct in6_addr anon_ip6;

	anon->ip6 = anon_ipv6_new();
	anon_ipv6_set_key(anon->ip6, anon->key6);
	anon_ipv6_map_pref(anon->ip6, pkt->ip6.ip6_src, &anon_ip6);

	return anon_ip6;
}

