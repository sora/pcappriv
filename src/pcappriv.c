#include "pcappriv.h"

/*
 * create_pcapfile
 */
static inline int create_pcapfile(char *fname, struct pcap_hdr_s *pcap_ghdr)
{
	int fd;

	fd = creat(fname, 0666);
	if (fd != -1) {
		// write pcap global header
		if (write(fd, pcap_ghdr, sizeof(struct pcap_hdr_s)) == -1) {
			return -1;
		}
		close(fd);
	}

	return fd;
}

/*
 * write_pktdata
 */
static inline int write_pktdata(char *fname, unsigned char *buf, struct pcap_pkt *pkt)
{
	int fd;

	fd = open(fname, O_WRONLY | O_APPEND);
	if (fd != -1) {
		if (write(fd, buf, sizeof(struct pcaprec_hdr_s)+pkt->pcap.orig_len) == -1) {
			return -1;
		}
	}
	close(fd);
	return fd;
}

/*
 * main
 */
int main(int argc, char *argv[])
{
	struct pcap_hdr_s pcap_ghdr;
	unsigned char ibuf[PKT_SIZE_MAX];
	struct pcap_pkt *pkt = (struct pcap_pkt *)&ibuf[0];
	int ifd, ofd, pkt_count = 0;
	char fname[0xFF];
	struct stat st;
	struct anon_keys anon;
	u_int16_t ethtype;

	unsigned int subnet = 24;

	strcpy(anon.passphase, "hoge");

	if (!(argc == 2 || argc == 3)) {
		pr_err("Usage: ./pcappriv ./recv.pcap 24: argc=%d", argc);
		return 1;
	}
	if (argc == 3)
		subnet = atoi(argv[2]);
	if (subnet >= 32) {
		pr_err("subnet is wrong format: %d", subnet);
		return 1;
	}

	ifd = open(argv[1], O_RDONLY);
	if (ifd < 0) {
		pr_err("cannot open pcap file: %s", argv[1]);
		return 1;
	}

	// check global pcap header
	if (read(ifd, ibuf, sizeof(struct pcap_hdr_s)) <= 0) {
		pr_err("input file is too short");
		return 1;
	}

	set_global_pcaphdr(&pcap_ghdr, (char *)ibuf);
	if ((pcap_ghdr.magic_number != PCAP_MAGIC)          ||
	    (pcap_ghdr.version_major != PCAP_VERSION_MAJOR) ||
	    (pcap_ghdr.version_minor != PCAP_VERSION_MINOR)) {
		pr_err("unsupported pcap format:\n"
		       "\tpcap_ghdr.magic_number=%X\n"
		       "\tpcap_ghdr.version_major=%X\n"
		       "\tpcap_ghdr.version_minor=%X",
		       (int)pcap_ghdr.magic_number, (int)pcap_ghdr.version_major,
		       (int)pcap_ghdr.version_minor);
		goto out;
	}

	// create output file
	strcpy(fname, "output.pcap");
	if ((stat(fname, &st)) != 0) {
		ofd = create_pcapfile(fname, &pcap_ghdr);
		if (ofd == -1) {
			pr_err("cannot create pcap file.");
			goto out;
		}
	}

	anon_init(&anon);
	cache_init();

	set_signal(SIGINT);

	while (1) {
		// read pcap header
		if (read(ifd, ibuf, sizeof(struct pcaprec_hdr_s)) <= 0)
			break;

		// checking packet size
		if ((pkt->pcap.orig_len < PKT_SIZE_MIN) || (pkt->pcap.orig_len > PKT_SIZE_MAX)) {
			pr_warn("Skip a packet: frame original length=%d", (int)pkt->pcap.orig_len);
			lseek(ifd, pkt->pcap.orig_len, SEEK_CUR); // skip the packet data
			continue;
		}

		// read packet data
		if (read(ifd, ibuf+sizeof(struct pcaprec_hdr_s), pkt->pcap.orig_len) <= 0)
			break;
		INFO_ETH(pkt);

		ethtype = ntohs(pkt->eth.ether_type);
		// ipv4 header
		if (ethtype == ETHERTYPE_IP) {
			INFO_IP4(pkt_count, &pkt->ip4);
			anon4(&anon, &pkt->ip4.ip_dst);
			anon4(&anon, &pkt->ip4.ip_src);

		// ipv6 header
		} else if (ethtype == ETHERTYPE_IPV6) {
			INFO_IP6(pkt_count, &pkt->ip6);
			anon6(&anon, &pkt->ip6.ip6_dst);
			anon6(&anon, &pkt->ip6.ip6_src);

		// ARP
		//} else if (ethtype == ETHERTYPE_ARP) {
		//	set_arp(&pkt, (char *)ibuf + ETHER_HDR_LEN);
		// unknown Ethernet Type
		} else {
			// temp: debug
			pr_warn("EtherType: %04X is not supported", ethtype);
		}

		// write packet data
		ofd = write_pktdata(fname, &ibuf[0], pkt);
		if (ofd == -1) {
			pr_err("cannot write pcap file,");
			break;
		}
		++pkt_count;

		if (caught_signal)
			break;
	}

out:
	anon_release(&anon);
	cache_release();
	close(ifd);
	return 0;
}

