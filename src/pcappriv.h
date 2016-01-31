#ifndef _pcappriv_h_
#define _pcappriv_h_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#ifdef __FreeBSD__
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <sys/stat.h>

#include <libanon.h>
#include "khash.h"

#ifdef __FreeBSD__
#define s6_addr8  __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#endif


#define PCAP_MAGIC         (0xa1b2c3d4)
#define PCAP_VERSION_MAJOR (0x2)
#define PCAP_VERSION_MINOR (0x4)
#define PCAP_SNAPLEN       (0xFFFF)
#define PCAP_NETWORK       (0x1)      // linktype_ethernet

#define PKT_SIZE_MAX    (0xFFFF)
#define PKT_SIZE_MIN    (0x1F)

#define hash_data_size    10000000

#define warn  1
#define debug 0

#define BITMASK4(v)	(((1 << (v)) - 1) << (32 - (v)))

#define pr_err(S, ...) fprintf(stderr, \
                     "\x1b[1m\x1b[31merror:\x1b[0m " S "\n", ##__VA_ARGS__)
#define pr_warn(S, ...) if(warn) fprintf(stderr, \
                     "\x1b[1m\x1b[33mwarn :\x1b[0m " S "\n", ##__VA_ARGS__)
#define pr_debug(S, ...) if(debug) fprintf(stderr, \
                     "\x1b[1m\x1b[90mdebug:\x1b[0m " S "\n", ##__VA_ARGS__)

#define INFO_ETH(X) \
pr_debug("INFO_ETH> " \
	"ether_dhost: %02x:%02x:%02x:%02x:%02x:%02x, " \
	"ether_shost: %02x:%02x:%02x:%02x:%02x:%02x, " \
	"ether_type: %04x", \
	(unsigned char)X->eth.ether_dhost[0], (unsigned char)X->eth.ether_dhost[1], \
	(unsigned char)X->eth.ether_dhost[2], (unsigned char)X->eth.ether_dhost[3], \
	(unsigned char)X->eth.ether_dhost[4], (unsigned char)X->eth.ether_dhost[5], \
	(unsigned char)X->eth.ether_shost[0], (unsigned char)X->eth.ether_shost[1], \
	(unsigned char)X->eth.ether_shost[2], (unsigned char)X->eth.ether_shost[3], \
	(unsigned char)X->eth.ether_shost[4], (unsigned char)X->eth.ether_shost[5], \
	X->eth.ether_type);

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
	union {
		struct ip ip4;
		struct ip6_hdr ip6;
	};
} __attribute__((packed));

/* cryptopan */
struct anon_keys {
	char passphase[0xFF];
	anon_key_t *key;
	anon_ipv4_t *ip;
	anon_key_t *key6;
	anon_ipv6_t *ip6;
};

/* khash */
typedef struct {
	struct in_addr key;
	struct in_addr val;
} hash4_t;

typedef struct {
	struct in6_addr key;
	struct in6_addr val;
} hash6_t;

/*
 * INFO_IP4
 */
static inline void INFO_IP4(int pkt_count, struct ip *ip4)
{
	char src[INET_ADDRSTRLEN] = { 0 };
	char dst[INET_ADDRSTRLEN] = { 0 };

	inet_ntop(AF_INET, &ip4->ip_src, src, sizeof(src));
	inet_ntop(AF_INET, &ip4->ip_dst, dst, sizeof(dst));

	pr_debug("INFO_IP4> cnt:%d "
	         "ver:%d, origlen:%d, proto:%X, srcip:%s, dstip:%s",
	         pkt_count, (int)ip4->ip_v, (int)ntohs(ip4->ip_len), ip4->ip_p, src, dst);
}

/*
 * INFO_IP6
 */
static inline void INFO_IP6(int pkt_count, struct ip6_hdr *ip6)
{
	char src[INET6_ADDRSTRLEN] = { 0 };
	char dst[INET6_ADDRSTRLEN] = { 0 };

	inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
	inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

	pr_debug("INFO_IP6> cnt:%d "
	         "ver:%d, origlen:%d, proto:XX, srcip:%s, dstip:%s",
	         pkt_count, (int)((ip6->ip6_vfc >> 4) & 0xF), (int)ntohs(ip6->ip6_plen), src, dst);
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
static inline void set_pcaphdr(struct pcaprec_hdr_s *pcap, const char *buf)
{
	const struct pcaprec_hdr_s *h = (struct pcaprec_hdr_s *)buf;

	pcap->ts_sec   = h->ts_sec;
	pcap->ts_usec  = h->ts_usec;
	pcap->incl_len = h->incl_len;
	pcap->orig_len = h->orig_len;
}


static inline void eth_copy(char *dst, const char *src)
{
	unsigned short *a = (unsigned short *)dst;
	const unsigned short *b = (const unsigned short *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}

/*
 * set_ethhdr
 */
static inline void set_ethhdr(struct ether_header *eth, const char *buf)
{
	eth_copy((char *)eth->ether_dhost, (const char *)&buf[0x0]);
	eth_copy((char *)eth->ether_shost, (const char *)&buf[0x6]);
	eth->ether_type = ntohs(*(short *)&buf[0xc]);
}

/*
 * set_ip4hdr
 */
static inline void set_ip4hdr(struct ip *ip4, const char *buf)
{
	const struct ip *p = (struct ip *)buf;

	ip4->ip_v   = p->ip_v;
	ip4->ip_len = p->ip_len;
	ip4->ip_p   = p->ip_p;
	ip4->ip_src = p->ip_src;
	ip4->ip_dst = p->ip_dst;
}

/*
 * set_ip6hdr
 */
static inline void set_ip6hdr(struct ip6_hdr *ip6, const char *buf)
{
	const struct ip6_hdr *p = (struct ip6_hdr *)buf;

	ip6->ip6_vfc  = p->ip6_vfc;
	ip6->ip6_plen = p->ip6_plen;
	ip6->ip6_src.s6_addr32[3] = p->ip6_src.s6_addr32[3];
	ip6->ip6_src.s6_addr32[2] = p->ip6_src.s6_addr32[2];
	ip6->ip6_src.s6_addr32[1] = p->ip6_src.s6_addr32[1];
	ip6->ip6_src.s6_addr32[0] = p->ip6_src.s6_addr32[0];
	ip6->ip6_dst.s6_addr32[3] = p->ip6_dst.s6_addr32[3];
	ip6->ip6_dst.s6_addr32[2] = p->ip6_dst.s6_addr32[2];
	ip6->ip6_dst.s6_addr32[1] = p->ip6_dst.s6_addr32[1];
	ip6->ip6_dst.s6_addr32[0] = p->ip6_dst.s6_addr32[0];
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

/*
 * addr6_hash
 */
static inline uint32_t addr6_hash(const struct in6_addr *ip6) {
	return (ip6->s6_addr32[3] ^ ip6->s6_addr32[2] ^
	        ip6->s6_addr32[1] ^ ip6->s6_addr32[0]);
}

/*
 * addr6_eq
 */
static inline uint32_t addr6_eq(const struct in6_addr *a, const struct in6_addr *b) {
	return ((a->s6_addr32[3] == b->s6_addr32[3]) &&
	        (a->s6_addr32[2] == b->s6_addr32[2]) &&
	        (a->s6_addr32[1] == b->s6_addr32[1]) &&
	        (a->s6_addr32[0] == b->s6_addr32[0]));
}

/*
 * addr6_copy
 */
static inline void addr6_copy(struct in6_addr *a, const struct in6_addr *b) {
	a->s6_addr32[3] = b->s6_addr32[3];
	a->s6_addr32[2] = b->s6_addr32[2];
	a->s6_addr32[1] = b->s6_addr32[1];
	a->s6_addr32[0] = b->s6_addr32[0];
}

static inline void pr_in6(const struct in6_addr *addr) {
	printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
	(int)addr->s6_addr[0], (int)addr->s6_addr[1],
	(int)addr->s6_addr[2], (int)addr->s6_addr[3],
	(int)addr->s6_addr[4], (int)addr->s6_addr[5],
	(int)addr->s6_addr[6], (int)addr->s6_addr[7],
	(int)addr->s6_addr[8], (int)addr->s6_addr[9],
	(int)addr->s6_addr[10], (int)addr->s6_addr[11],
	(int)addr->s6_addr[12], (int)addr->s6_addr[13],
	(int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

/* khash */
KHASH_MAP_INIT_INT(iv4, hash4_t)
KHASH_MAP_INIT_INT(iv6, hash6_t)

khash_t(iv4) *h4;
khash_t(iv6) *h6;


void set_signal (int);
void sig_handler (int);

// libanon
void anon4(struct anon_keys *, struct in_addr *);
void anon6(struct anon_keys *, struct in6_addr *);
void anon_init(struct anon_keys *);
void anon_release(struct anon_keys *);

// cache
void cache_init();
void cache_release();
void cache_put4(const struct in_addr *, const struct in_addr *);
int cache_get4(struct in_addr *);
void cache_put6(const struct in6_addr *, const struct in6_addr *);
int cache_get6(struct in6_addr *);

#endif

