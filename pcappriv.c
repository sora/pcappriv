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
		// write pcap packet header
		if (write(fd, &pkt->pcap, sizeof(pkt->pcap)) == -1) {
			return -1;
		}

		// write packet data
		if (write(fd, buf, pkt->pcap.orig_len) == -1) {
			return -1;
		}
		close(fd);
	}

	return fd;
}


/*
 * main
 */
int main(int argc, char *argv[])
{
	struct pcap_hdr_s pcap_ghdr;
	struct pcap_pkt pkt;
	unsigned char ibuf[PKT_SIZE_MAX];
	int ifd, ofd;
	char fname[0xFF];
	struct stat st;
	struct anon_keys anon;

	unsigned int subnet = 24;

	strcat(anon.passphase, "hoge");

	if (!(argc == 2 || argc == 3)) {
		pr_err("Usage: ./split_pcap ./recv.pcap 24: argc=%d", argc);
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
	//sprintf(fname, "%d", get_hash(&pkt, subnet));
	strcat(fname, "output.pcap");
	if ((stat(fname, &st)) != 0) {
		ofd = create_pcapfile(fname, &pcap_ghdr);
		if (ofd == -1) {
			pr_err("cannot create pcap file.");
			goto out;
		}
	}

	anon_init(&anon);

	set_signal(SIGINT);

	while (1) {

		// read pcap header
		if (read(ifd, ibuf, sizeof(struct pcaprec_hdr_s)) <= 0)
			break;

		// checking packet size
		set_pcaphdr(&pkt.pcap, (char *)ibuf);
		if ((pkt.pcap.orig_len < PKT_SIZE_MIN) || (pkt.pcap.orig_len > PKT_SIZE_MAX)) {
			pr_warn("frame length: frame_len=%d", (int)pkt.pcap.orig_len);
		}

		// ethernet header
		if (read(ifd, ibuf, pkt.pcap.orig_len) <= 0)
			break;
		set_ethhdr(&pkt.eth, (char *)ibuf);
		INFO_ETH(pkt);

		// ipv4 header
		if (pkt.eth.ether_type == ETHERTYPE_IP) {
			set_ip4hdr(&pkt.ip4, (char *)ibuf + ETHER_HDR_LEN);
			pkt.ip4.ip_src = anon4(&anon, &pkt);
			pkt.ip4.ip_dst = anon4(&anon, &pkt);
			INFO_IP4(&pkt.ip4);

		// ipv6 header
		} else if (pkt.eth.ether_type == ETHERTYPE_IPV6) {
			set_ip6hdr(&pkt.ip6, (char *)ibuf + ETHER_HDR_LEN);
			pkt.ip6.ip6_src = anon6(&anon, &pkt);
			pkt.ip6.ip6_dst = anon6(&anon, &pkt);
			INFO_IP6(&pkt.ip6);
		// ARP
		//} else if (pkt.eth.ether_type == ETHERTYPE_ARP) {
		//	set_arp(&pkt, (char *)ibuf + ETHER_HDR_LEN);
		// unknown Ethernet Type
		} else {
			// temp: debug
			pr_warn("EtherType: %04X is not supported", pkt.eth.ether_type);
		}

		// write packet data
		ofd = write_pktdata(fname, &ibuf[0], &pkt);
		if (ofd == -1) {
			pr_err("cannot write pcap file,");
			break;
		}

		if (caught_signal)
			break;
	}

out:
	anon_release(&anon);
	close(ifd);
	return 0;
}

