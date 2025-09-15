from scapy.all import rdpcap, DNS, DNSQR

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    dns_queries = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # qr=0 means query
            qname = pkt[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else "N/A"
            dns_queries.append(qname)
    return dns_queries

if __name__ == "__main__":
    queries = parse_pcap("6.pcap")
    print("DNS Queries found in 6.pcap:")
    for i, q in enumerate(queries[:10], start=1):  # show first 10
        print(f"{i}. {q}")
