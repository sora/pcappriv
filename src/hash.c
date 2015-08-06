#include "pcappriv.h"

int get_hash(const struct pcap_pkt *pkt, unsigned int subnet) {
	struct in_addr src, dst, mask;
	int ret = 0;

	if (pkt->eth.ether_type == ETHERTYPE_IP) {
		mask.s_addr = BITMASK4(subnet);
		src.s_addr = pkt->ip4.ip_src.s_addr & htonl(mask.s_addr);
		dst.s_addr = pkt->ip4.ip_dst.s_addr & htonl(mask.s_addr);

		// temorary
		ret = ((src.s_addr >> 24) & 0xFF) ^ ((src.s_addr >> 16) & 0xFF) ^
		      ((src.s_addr >>  8) & 0xFF) ^  (src.s_addr        & 0xFF) ^
		      ((dst.s_addr >> 24) & 0xFF) ^ ((dst.s_addr >> 16) & 0xFF) ^
		      ((dst.s_addr >>  8) & 0xFF) ^  (dst.s_addr        & 0xFF);
	}

	return ret;
}

