(cd ..; make clean)
(cd ..; make)
rm -f output.pcap
../pcappriv pcap/hige.pcap
