#include "pcappriv.h"

/*
 * main
 */
int main(int argc, char *argv[])
{
	struct pcap_hdr_s pcap_ghdr;
	unsigned char ibuf[PKT_SIZE_MAX];
	struct pcap_pkt *pkt = (struct pcap_pkt *)&ibuf[0];
	int ret, pkt_count = 0;
	FILE *ifp, *ofp = NULL;
	char fname[0xFF];
	struct anon_keys anon;
	u_int16_t ethtype;

	strcpy(anon.passphase, "hoge");

	if (argc != 2) {
		pr_err("Usage: ./pcappriv ./recv.pcap: argc=%d", argc);
		exit(EXIT_FAILURE);
	}

	ifp = fopen(argv[1], "rb");
	if (ifp == NULL) {
		pr_err("cannot open pcap file: %s", argv[1]);
		exit(EXIT_FAILURE);
	}

	// check global pcap header
	ret = fread(ibuf, sizeof(struct pcap_hdr_s), 1, ifp);
	if (ret < 1) {
		pr_err("size of fread is too short: pcap_hdr_s");
		exit(EXIT_FAILURE);
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
	ofp = fopen(fname, "wb");
	if (ofp == NULL) {
		pr_err("cannot create output pcap file.");
		goto out;
	}

	ret = fwrite(&pcap_ghdr, sizeof(struct pcap_hdr_s), 1, ofp);
	if (ret < 1) {
		pr_err("cannot write ghdr.");
		goto out;
	}

	anon_init(&anon);
	cache_init();
	set_signal(SIGINT);

	while (1) {
		// read pcap header
		ret = fread(ibuf, sizeof(struct pcaprec_hdr_s), 1, ifp);
		if (ret < 1) {
			pr_debug("size of fread is too short: pcaprec_hdr_s");
			break;
		}

		// checking packet size
		if ((pkt->pcap.orig_len < PKT_SIZE_MIN) || (pkt->pcap.orig_len > PKT_SIZE_MAX)) {
			pr_warn("Skip a packet: frame original length=%d", (int)pkt->pcap.orig_len);
			fseek(ifp, pkt->pcap.incl_len, SEEK_CUR); // skip the packet data
			continue;
		}

		// read packet data
		ret = fread(ibuf+sizeof(struct pcaprec_hdr_s), pkt->pcap.incl_len, 1, ifp);
		if (ret < 1) {
			pr_err("size of fread is too short: pcap data");
			break;
		}
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
		ret = fwrite(ibuf, sizeof(struct pcaprec_hdr_s) + pkt->pcap.incl_len, 1, ofp);
		if (ret < 1) {
			pr_err("cannot write pcap file: packet data");
			break;
		}
		++pkt_count;

		if (caught_signal)
			break;
	}

out:
	anon_release(&anon);
	cache_release();
	fclose(ifp);
	fclose(ofp);
	return 0;
}

