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
                     "\x1b[1m\x1b[33mwarnn:\x1b[0m " S "\n", ##__VA_ARGS__)
#define pr_debug(S, ...) if(debug) fprintf(stderr, \
                     "\x1b[1m\x1b[90mdebug:\x1b[0m " S "\n", ##__VA_ARGS__)

#define INFO_ETH(X) \
pr_debug("INFO_ETH> " \
	"ether_dhost: %02x:%02x:%02x:%02x:%02x:%02x, " \
	"ether_shost: %02x:%02x:%02x:%02x:%02x:%02x, " \
	"ether_type: %04x", \
	(unsigned char)X.eth.ether_dhost[5], (unsigned char)X.eth.ether_dhost[4], \
	(unsigned char)X.eth.ether_dhost[3], (unsigned char)X.eth.ether_dhost[2], \
	(unsigned char)X.eth.ether_dhost[1], (unsigned char)X.eth.ether_dhost[0], \
	(unsigned char)X.eth.ether_shost[5], (unsigned char)X.eth.ether_shost[4], \
	(unsigned char)X.eth.ether_shost[3], (unsigned char)X.eth.ether_shost[2], \
	(unsigned char)X.eth.ether_shost[1], (unsigned char)X.eth.ether_shost[0], \
	X.eth.ether_type);

#if 0
#define INFO_IP4(X) \
pr_debug("INFO_IP4> " \
	"ver:%d, len:%d, proto:%X, srcip:%s, dstip:%s", \
	(int)X.ip4.ip_v, (int)ntohs(X.ip4.ip_len), X.ip4.ip_p, \
	Inet_ntop(AF_INET, X.ip4.ip_src), \
	Inet_ntop(AF_INET, X.ip4.ip_dst));
#endif

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
 * INFO_IP4
 */
static inline void INFO_IP4(struct ip *ip4)
{
	char src[INET_ADDRSTRLEN] = { 0 };
	char dst[INET_ADDRSTRLEN] = { 0 };

	inet_ntop(AF_INET, &ip4->ip_src, src, sizeof(src));
	inet_ntop(AF_INET, &ip4->ip_dst, dst, sizeof(dst));

	pr_debug("INFO_IP4> "
	         "ver:%d, len:%d, proto:%X, srcip:%s, dstip:%s",
	         (int)ip4->ip_v, (int)ntohs(ip4->ip_len), ip4->ip_p, src, dst);
}

/*
 * INFO_IP6
 */
static inline void INFO_IP6(struct ip6_hdr *ip6)
{
	char src[INET6_ADDRSTRLEN] = { 0 };
	char dst[INET6_ADDRSTRLEN] = { 0 };

	inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
	inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

	pr_debug("INFO_IP6> "
	         "ver:%d, len:%d, proto:XX, srcip:%s, dstip:%s",
	         (int)((ip6->ip6_vfc >> 4) & 0xF), (int)ntohs(ip6->ip6_plen), src, dst);
}

/*
 * set_global_pcaphdr
 */
static inline void set_global_pcaphdr(struct pcap_hdr_s *ghdr, const char *buf)
{
	const struct pcap_hdr_s *h = (struct pcap_hdr_s *)buf;

	ghdr->magic_number  = h->magic_number;
	ghdr->version_major = h->version_major;
	ghdr->version_minor = h->version_minor;
	ghdr->thiszone      = h->thiszone;
	ghdr->sigfigs       = h->sigfigs;
	ghdr->snaplen       = h->snaplen;
	ghdr->network       = h->network;
}

/*
 * set_pcaphdr
 */
static inline void set_pcaphdr(struct pcap_pkt *pkt, const char *buf)
{
	const struct pcaprec_hdr_s *h = (struct pcaprec_hdr_s *)buf;

	pkt->pcap.ts_sec   = h->ts_sec;
	pkt->pcap.ts_usec  = h->ts_usec;
	pkt->pcap.incl_len = h->incl_len;
	pkt->pcap.orig_len = h->orig_len;
}

/*
 * set_ethhdr
 */
static inline void set_ethhdr(struct pcap_pkt *pkt, const char *buf)
{
	pkt->eth.ether_dhost[5] = buf[0x0];
	pkt->eth.ether_dhost[4] = buf[0x1];
	pkt->eth.ether_dhost[3] = buf[0x2];
	pkt->eth.ether_dhost[2] = buf[0x3];
	pkt->eth.ether_dhost[1] = buf[0x4];
	pkt->eth.ether_dhost[0] = buf[0x5];

	pkt->eth.ether_shost[5] = buf[0x6];
	pkt->eth.ether_shost[4] = buf[0x7];
	pkt->eth.ether_shost[3] = buf[0x8];
	pkt->eth.ether_shost[2] = buf[0x9];
	pkt->eth.ether_shost[1] = buf[0xa];
	pkt->eth.ether_shost[0] = buf[0xb];

	pkt->eth.ether_type = ntohs(*(short *)&buf[0xc]);
}

/*
 * set_ip4hdr
 */
static inline void set_ip4hdr(struct pcap_pkt *pkt, const char *buf)
{
	const struct ip *p = (struct ip *)buf;

	pkt->ip4.ip_v   = p->ip_v;
	pkt->ip4.ip_len = p->ip_len;
	pkt->ip4.ip_p   = p->ip_p;
	pkt->ip4.ip_src = p->ip_src;
	pkt->ip4.ip_dst = p->ip_dst;
}

/*
 * set_ip6hdr
 */
static inline void set_ip6hdr(struct pcap_pkt *pkt, const char *buf)
{
	const struct ip6_hdr *p = (struct ip6_hdr *)buf;

	pkt->ip6.ip6_vfc  = p->ip6_vfc;
	pkt->ip6.ip6_plen = p->ip6_plen;
	pkt->ip6.ip6_src  = p->ip6_src;
	pkt->ip6.ip6_dst  = p->ip6_dst;
}

/*
 * set_arp
 */
static inline void set_arp(struct pcap_pkt *pkt, const char *buf)
{
	const struct ip *p = (struct ip *)buf;

	pkt->ip4.ip_v   = p->ip_v;
	pkt->ip4.ip_len = p->ip_len;
	pkt->ip4.ip_p   = p->ip_p;
	pkt->ip4.ip_src = p->ip_src;
	pkt->ip4.ip_dst = p->ip_dst;
}


void set_signal (int);
void sig_handler (int);

int get_hash (const struct pcap_pkt *, unsigned int);

#endif

