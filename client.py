# client.py
# Reads 6.pcap, filters noisy domains, builds HHMMSSID headers (from packet timestamp),
# sends "HEADER|domain" to server, collects responses and writes report.csv.

import socket
from scapy.all import rdpcap, DNS, DNSQR
from datetime import datetime
import csv

# ----- Noise keywords: adjust if you see other local/IOT patterns -----
NOISE_KEYWORDS = [
    "local", "mdns", "apple", "brother", "pdl-datastream",
    "workstation", "airplay", "arpa", "in-addr", "localhost", "invalid"
]

def is_noise_domain(domain: str) -> bool:
    """Return True if domain contains any noise keyword."""
    d = domain.lower()
    return any(k in d for k in NOISE_KEYWORDS)

def header_from_pkt_time(pkt_time: float, seq_id: int) -> str:
    """
    Build HHMMSSID using the packet timestamp (pkt_time, unix seconds)
    and the sequence id (two digits, zero-padded). seq_id wraps at 100.
    """
    t = datetime.fromtimestamp(pkt_time)
    hh = f"{t.hour:02d}"
    mm = f"{t.minute:02d}"
    ss = f"{t.second:02d}"
    ident = f"{seq_id % 100:02d}"
    return f"{hh}{mm}{ss}{ident}"

def collect_clean_queries(pcap_file: str):
    """
    Read PCAP and return a list of (domain, raw_dns_bytes, pkt_time)
    but only for clean (non-noise) queries, preserving original order.
    """
    packets = rdpcap(pcap_file)
    clean = []

    for pkt in packets:
        # ensure packet has DNS and is a DNS query
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            # extract qname and normalize (strip trailing dot)
            qname = pkt[DNSQR].qname.decode().rstrip(".")
            if not is_noise_domain(qname):
                # raw DNS layer bytes (useful if you need to send full DNS bytes)
                raw_dns = bytes(pkt[DNS])
                pkt_time = float(getattr(pkt, "time", 0.0))  # scapy packet timestamp
                clean.append((qname, raw_dns, pkt_time))

    return clean

def run_client(pcap_file="6.pcap", server_host="127.0.0.1", server_port=9999):
    """
    Main client: collects clean queries, sends them with header to server,
    receives responses, writes report.csv.
    """
    # 1) collect only clean queries first
    clean_queries = collect_clean_queries(pcap_file)
    if not clean_queries:
        print("No clean DNS queries found in PCAP.")
        return

    results = []  # will store tuples (header, domain, resolved_ip)

    # For each clean query, build header (using packet timestamp) and send to server
    for seq, (domain, raw_dns, pkt_time) in enumerate(clean_queries):
        header = header_from_pkt_time(pkt_time, seq)   # HHMMSSID with seq over clean list
        # Use existing server protocol: "HEADER|domain"
        message = f"{header}|{domain}"

        try:
            # create a TCP connection for each query (keeps server code simple)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_host, server_port))
            sock.send(message.encode())

            # receive and decode response (expected "HEADER|domain|ip")
            resp = sock.recv(4096).decode(errors="ignore")
            sock.close()

            parts = resp.split("|")
            # basic validation
            if len(parts) == 3:
                results.append( (parts[0], parts[1], parts[2]) )
                print(f"[CLIENT] {parts[0]} | {parts[1]} -> {parts[2]}")
            else:
                # fallback if server returned something unexpected
                results.append( (header, domain, "ERR") )
                print(f"[CLIENT] Unexpected server response: {resp}")

        except Exception as e:
            # network errors should not crash the client
            print(f"[CLIENT] Error sending {domain}: {e}")
            results.append( (header, domain, "ERR") )

    # 3) write CSV report with sequential headers 00,01,02...
    with open("report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CustomHeader", "Domain", "ResolvedIP"])
        for row in results:
            writer.writerow(row)

    print("\n[CLIENT] Report saved to report.csv (clean queries only).")

if __name__ == "__main__":
    run_client("6.pcap")
