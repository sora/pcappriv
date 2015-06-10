#include "pcappriv.h"

int main(int argc, char *argv[])
{
	struct pcap_hdr_s pcap_ghdr;
	struct pcap_pkt pkt;
	unsigned char ibuf[PKT_SIZE_MAX];
	int ifd, ofd;
	char fname[0xFF];
	struct stat st;

	unsigned int subnet = 24;

	if (!(argc == 2 || argc == 3)) {
		printf("Usage: ./split_pcap ./recv.pcap 24: argc=%d\n", argc);
		return 1;
	}
	if (argc == 3)
		subnet = atoi(argv[2]);
	if (subnet >= 32) {
		printf("subnet is wrong format: %d\n", subnet);
		return 1;
	}


	ifd = open(argv[1], O_RDONLY);
	if (ifd < 0) {
		fprintf(stderr, "cannot open pcap file: %s\n", argv[1]);
		return 1;
	}

	set_signal(SIGINT);

	// check global pcap header
	if (read(ifd, ibuf, sizeof(struct pcap_hdr_s)) <= 0) {
		fprintf(stderr, "input file is too short\n");
		return 1;
	}

	set_global_pcaphdr(&pcap_ghdr, (char *)ibuf);
	if (pcap_ghdr.magic_number != PCAP_MAGIC) {
		printf("unsupported pcap format: pcap_ghdr.magic_number=%X\n",
				(int)pcap_ghdr.magic_number);
		return 1;
	}
	if (pcap_ghdr.version_major != PCAP_VERSION_MAJOR) {
		printf("unsupported pcap format: pcap_ghdr.version_major=%X\n",
				(int)pcap_ghdr.version_major);
		return 1;
	}
	if (pcap_ghdr.version_minor != PCAP_VERSION_MINOR) {
		printf("unsupported pcap format: pcap_ghdr.version_minor=%X\n",
				(int)pcap_ghdr.version_minor);
		return 1;
	}

	while (1) {
		// pcap header
		if (read(ifd, ibuf, sizeof(struct pcaprec_hdr_s)) <= 0)
			break;
		set_pcaphdr(&pkt, (char *)ibuf);
		if ((pkt.pcap.orig_len < PKT_SIZE_MIN) || (pkt.pcap.orig_len > PKT_SIZE_MAX)) {
			printf("[warn] frame length: frame_len=%d\n", (int)pkt.pcap.orig_len);
		}

		// ethernet header
		if (read(ifd, ibuf, pkt.pcap.orig_len) <= 0)
			break;
		set_ethhdr(&pkt, (char *)ibuf);

		// ipv4 header
		if (pkt.eth.ether_type == ETHERTYPE_IP) {
			set_ip4hdr(&pkt, (char *)ibuf + ETHER_HDR_LEN);
			//pkt.ip4.ip_src.s_addr &= htonl(mask.s_addr);
			//strcpy(fname, inet_ntoa(pkt.ip4.ip_src));
#if DEBUG
			printf("ip4> ver:%d, len:%d, proto:%X, srcip:%s, dstip:%s\n",
					(int)pkt.ip4.ip_v, (int)ntohs(pkt.ip4.ip_len), pkt.ip4.ip_p,
					inet_ntoa(pkt.ip4.ip_src), inet_ntoa(pkt.ip4.ip_src));
			printf("ip4> mask:%s\n", inet_ntoa(pkt.ip4.ip_src));
#endif
		// ipv6 header
		} else if (pkt.eth.ether_type == ETHERTYPE_IPV6) {
			set_ip6hdr(&pkt, (char *)ibuf + ETHER_HDR_LEN);
		// ARP
		} else if (pkt.eth.ether_type == ETHERTYPE_ARP) {
			;
		}

		//
		sprintf(fname, "%d", get_hash(&pkt, subnet));
		strcat(fname, ".pcap");

		// make pcap file
		if ((stat(fname, &st)) != 0) {
			printf("make file\n");
			ofd = open(fname, O_WRONLY | O_CREAT, 0666);
			write(ofd, &pcap_ghdr, sizeof(struct pcap_hdr_s));
			close(ofd);
		}

		// write packet data
		ofd = open(fname, O_WRONLY | O_APPEND);
		write(ofd, &pkt.pcap, sizeof(pkt.pcap));
		write(ofd, ibuf, pkt.pcap.orig_len);
		close(ofd);

		if (caught_signal)
			goto out;
	}

out:
	close(ifd);
	return 0;
}

