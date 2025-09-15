import socket
import json
import csv

# Load rules 
with open("rules.json") as f:
    RULES = json.load(f)

IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# Noise keywords (to filter out unnecessary IoT/mdns queries)
NOISE_KEYWORDS = [
    "local", "mdns", "apple", "Brother", "pdl-datastream",
    "workstation", "airplay", "arpa", "in-addr"
]

def get_time_period(hour):
    if 4 <= hour <= 11:
        return RULES["timestamp_rules"]["time_based_routing"]["morning"]
    elif 12 <= hour <= 19:
        return RULES["timestamp_rules"]["time_based_routing"]["afternoon"]
    else:
        return RULES["timestamp_rules"]["time_based_routing"]["night"]

def resolve_dns(custom_header, domain):
    hh = int(custom_header[:2])   # Extract hour
    query_id = int(custom_header[-2:])  # Extract ID
    period = get_time_period(hh)

    base = period["ip_pool_start"]
    ip_index = base + (query_id % period["hash_mod"])
    return IP_POOL[ip_index]

def is_noise(domain: str) -> bool:
    """Check if the domain should be filtered out."""
    d = domain.lower()
    return any(kw in d for kw in NOISE_KEYWORDS)

def run_server(host="127.0.0.1", port=9999):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[SERVER] Listening on {host}:{port}")

    # Open CSV file for logging results
    with open("resolved_dns.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["CustomHeader", "Domain", "ResolvedIP"])  # CSV header

        while True:
            conn, addr = sock.accept()
            data = conn.recv(4096).decode()
            if not data:
                conn.close()
                continue

            # Data format: "CUSTOMHEADER|DOMAIN"
            header, domain = data.split("|")

            if is_noise(domain):
                print(f"[FILTERED] Ignored noisy domain: {domain}")
                conn.close()
                continue

            ip = resolve_dns(header, domain)

            response = f"{header}|{domain}|{ip}"
            conn.send(response.encode())
            conn.close()

            # Log clean result into CSV
            writer.writerow([header, domain, ip])
            csvfile.flush()

            print(f"[RESOLVED] {domain} -> {ip}")

if __name__ == "__main__":
    run_server()
