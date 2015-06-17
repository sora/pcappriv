#ifndef _pcappriv_h_
#define _pcappriv_h_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <sys/stat.h>

#define PCAP_MAGIC         (0xa1b2c3d4)
#define PCAP_VERSION_MAJOR (0x2)
#define PCAP_VERSION_MINOR (0x4)
#define PCAP_SNAPLEN       (0xFFFF)
#define PCAP_NETWORK       (0x1)      // linktype_ethernet

#define PKT_SIZE_MAX    (0x1FFF)
#define PKT_SIZE_MIN    (0x1F)

#define debug 1

#define BITMASK4(v)	(((1 << (v)) - 1) << (32 - (v)))

#define pr_err(S, ...) fprintf(stderr, \
                     "\x1b[1m\x1b[31merror:\x1b[0m " S "\n", ##__VA_ARGS__)
#define pr_warn(S, ...) fprintf(stderr, \
                     "\x1b[1m\x1b[33mwarning:\x1b[0m " S "\n", ##__VA_ARGS__)
#define pr_debug(S, ...) if(debug) fprintf(stderr, \
                     "\x1b[1m\x1b[90mdebug:\x1b[0m " S "\n", ##__VA_ARGS__)

#define INFO_ETH(X) \
pr_debug("INFO_ETH> " \
	"ether_dhost: %02x:%02x:%02x:%02x:%02x:%02x, " \
	"ether_shost: %02x:%02x:%02x:%02x:%02x:%02x, " \
	"ether_type: %04x", \
	(unsigned char)X.eth.ether_dhost[0], (unsigned char)X.eth.ether_dhost[1], \
	(unsigned char)X.eth.ether_dhost[2], (unsigned char)X.eth.ether_dhost[3], \
	(unsigned char)X.eth.ether_dhost[4], (unsigned char)X.eth.ether_dhost[5], \
	(unsigned char)X.eth.ether_shost[0], (unsigned char)X.eth.ether_shost[1], \
	(unsigned char)X.eth.ether_shost[2], (unsigned char)X.eth.ether_shost[3], \
	(unsigned char)X.eth.ether_shost[4], (unsigned char)X.eth.ether_shost[5], \
	X.eth.ether_type);

#define INFO_IP4(X) \
pr_debug("INFO_IP4> " \
	"ver:%d, len:%d, proto:%X, srcip:%s, dstip:%s", \
	(int)X.ip4.ip_v, (int)ntohs(X.ip4.ip_len), X.ip4.ip_p, \
	inet_ntoa(X.ip4.ip_src), inet_ntoa(X.ip4.ip_dst));

int caught_signal;

/* pcap v2.4 global header */
struct pcap_hdr_s {
	unsigned int   magic_number;   /* magic number */
	unsigned short version_major;  /* major version number */
	unsigned short version_minor;  /* minor version number */
	int            thiszone;       /* GMT to local correction */
	unsigned int   sigfigs;        /* accuracy of timestamps */
	unsigned int   snaplen;        /* max length of captured packets, in octets */
	unsigned int   network;        /* data link type */
} __attribute__((packed));

/* pcap v2.4 packet header */
struct pcaprec_hdr_s {
	unsigned int ts_sec;         /* timestamp seconds */
	unsigned int ts_usec;        /* timestamp microseconds */
	unsigned int incl_len;       /* number of octets of packet saved in file */
	unsigned int orig_len;       /* actual length of packet */
} __attribute__((packed));

/* packet */
struct pcap_pkt {
	struct pcaprec_hdr_s pcap;
	struct ether_header eth;
	struct ip ip4;
	struct ip6_hdr ip6;
};


/*
 * set_global_pcaphdr
 */
static inline void set_global_pcaphdr(struct pcap_hdr_s *ghdr, const char *buf)
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

/*
 * set_pcaphdr
 */
static inline void set_pcaphdr(struct pcap_pkt *pkt, const char *buf)
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

/*
 * set_ethhdr
 */
static inline void set_ethhdr(struct pcap_pkt *pkt, const char *buf)
{
	struct ether_header *eth;
	eth = &pkt->eth;

	eth->ether_dhost[5] = buf[0x0];
	eth->ether_dhost[4] = buf[0x1];
	eth->ether_dhost[3] = buf[0x2];
	eth->ether_dhost[2] = buf[0x3];
	eth->ether_dhost[1] = buf[0x4];
	eth->ether_dhost[0] = buf[0x5];

	eth->ether_shost[5] = buf[0x6];
	eth->ether_shost[4] = buf[0x7];
	eth->ether_shost[3] = buf[0x8];
	eth->ether_shost[2] = buf[0x9];
	eth->ether_shost[1] = buf[0xa];
	eth->ether_shost[0] = buf[0xb];

	eth->ether_type = ntohs(*(short *)&buf[0xc]);
}

/*
 * set_ip4hdr
 */
static inline void set_ip4hdr(struct pcap_pkt *pkt, const char *buf)
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

/*
 * set_ip6hdr
 */
static inline void set_ip6hdr(struct pcap_pkt *pkt, const char *buf)
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

/*
 * set_arp
 */
static inline void set_arp(struct pcap_pkt *pkt, const char *buf)
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


void set_signal (int);
void sig_handler (int);

int get_hash (const struct pcap_pkt *, unsigned int);


#endif

