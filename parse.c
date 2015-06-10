#include "pcappriv.h"

void set_global_pcaphdr(struct pcap_hdr_s *ghdr, const char *buf)
{
	const char *ptr = buf;

	ghdr->magic_number = *(unsigned int *)ptr;
	ptr += sizeof(ghdr->magic_number);
	ghdr->version_major = *(unsigned short *)ptr;
	ptr += sizeof(ghdr->version_major);
	ghdr->version_minor = *(unsigned short *)ptr;
	ptr += sizeof(ghdr->version_minor);
	ghdr->thiszone = *(int *)ptr;
	ptr += sizeof(ghdr->thiszone);
	ghdr->sigfigs = *(unsigned int *)ptr;
	ptr += sizeof(ghdr->sigfigs);
	ghdr->snaplen = *(unsigned int *)ptr;
	ptr += sizeof(ghdr->snaplen);
	ghdr->network = *(unsigned int *)ptr;
}

void set_pcaphdr(struct pcap_pkt *pkt, const char *buf)
{
	struct pcaprec_hdr_s *pcap;
	pcap = &pkt->pcap;

	pcap->ts_sec = *(unsigned int *)buf;
	buf += sizeof(pcap->ts_sec);
	pcap->ts_usec = *(unsigned short *)buf;
	buf += sizeof(pcap->ts_usec);
	pcap->incl_len = *(unsigned short *)buf;
	buf += sizeof(pcap->incl_len);
	pcap->orig_len = *(int *)buf;
}

void set_ethhdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ether_header *eth;
	eth = &pkt->eth;

	eth->ether_dhost[5] = *(char *)buf; ++buf;
	eth->ether_dhost[4] = *(char *)buf; ++buf;
	eth->ether_dhost[3] = *(char *)buf; ++buf;
	eth->ether_dhost[2] = *(char *)buf; ++buf;
	eth->ether_dhost[1] = *(char *)buf; ++buf;
	eth->ether_dhost[0] = *(char *)buf; ++buf;
	eth->ether_shost[5] = *(char *)buf; ++buf;
	eth->ether_shost[4] = *(char *)buf; ++buf;
	eth->ether_shost[3] = *(char *)buf; ++buf;
	eth->ether_shost[2] = *(char *)buf; ++buf;
	eth->ether_shost[1] = *(char *)buf; ++buf;
	eth->ether_shost[0] = *(char *)buf; ++buf;
	eth->ether_type = ntohs(*(short *)buf);
}

void set_ip4hdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ip *ip4;
	ip4 = &pkt->ip4;

	ip4->ip_v = (*(unsigned char *)buf >> 4) & 0xF;
	buf += sizeof(unsigned char) + sizeof(ip4->ip_tos);
	ip4->ip_len = *(unsigned short *)buf;
	buf += sizeof(ip4->ip_len) + sizeof(ip4->ip_id) + sizeof(ip4->ip_off) +
			sizeof(ip4->ip_ttl);
	ip4->ip_p = *(unsigned char *)buf;
	buf += sizeof(ip4->ip_p) + sizeof(ip4->ip_sum);
	ip4->ip_src = *(struct in_addr *)buf;
	buf += sizeof(ip4->ip_src);
	ip4->ip_dst = *(struct in_addr *)buf;
}

void set_ip6hdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ip6_hdr *ip6;
	ip6 = &pkt->ip6;

	ip6->ip6_ctlun.ip6_un2_vfc = *(unsigned int *)buf;
	buf += sizeof(ip6->ip6_ctlun.ip6_un2_vfc) + sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = *(unsigned short *)buf;
	buf += sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen)+
			sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) +
			sizeof(ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
	ip6->ip6_src = *(struct in6_addr *)buf;
	buf += sizeof(ip6->ip6_src);
	ip6->ip6_dst = *(struct in6_addr *)buf;
}

