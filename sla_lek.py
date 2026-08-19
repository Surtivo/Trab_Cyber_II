from scapy.all import rdpcap, DNSQR, DNS, IP, ICMP, TCP, UDP
from collections import defaultdict
from datetime import datetime

PCAP_FILE = "captura.pcap"

# =========================
# Estruturas
# =========================

dns_queries = []
icmp_activity = []
http_activity = []
connections = defaultdict(int)

# =========================
# Ler PCAP
# =========================

packets = rdpcap(PCAP_FILE)

print(f"[+] Total de pacotes: {len(packets)}\n")

# =========================
# Análise
# =========================

for pkt in packets:

    # -------------------------
    # DNS
    # -------------------------
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):

        try:
            domain = pkt[DNSQR].qname.decode()

            dns_queries.append({
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "domain": domain
            })

        except:
            pass

    # -------------------------
    # ICMP (ping)
    # -------------------------
    if pkt.haslayer(ICMP):

        icmp_activity.append({
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "type": pkt[ICMP].type
        })

    # -------------------------
    # TCP Connections
    # -------------------------
    if pkt.haslayer(TCP):

        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport

        key = f"{src} -> {dst}:{dport}"
        connections[key] += 1

        # -------------------------
        # HTTP simples
        # -------------------------
        if dport == 80 or pkt[TCP].sport == 80:

            http_activity.append({
                "src": src,
                "dst": dst,
                "port": dport
            })

# =========================
# Relatório
# =========================

print("=" * 50)
print("DNS QUERIES")
print("=" * 50)

for dns in dns_queries:
    print(f"[DNS] {dns['src']} -> {dns['domain']}")

print("\n")

# =========================

print("=" * 50)
print("ICMP ACTIVITY")
print("=" * 50)

for icmp in icmp_activity:

    icmp_type = icmp["type"]

    if icmp_type == 8:
        desc = "Echo Request (Ping)"
    elif icmp_type == 0:
        desc = "Echo Reply"
    else:
        desc = f"ICMP Type {icmp_type}"

    print(f"[ICMP] {icmp['src']} -> {icmp['dst']} | {desc}")

print("\n")

# =========================

print("=" * 50)
print("HTTP ACTIVITY")
print("=" * 50)

for http in http_activity:
    print(f"[HTTP] {http['src']} -> {http['dst']}")

print("\n")

# =========================

print("=" * 50)
print("TOP CONNECTIONS")
print("=" * 50)

sorted_conn = sorted(
    connections.items(),
    key=lambda x: x[1],
    reverse=True
)

for conn, count in sorted_conn[:20]:
    print(f"{conn} | packets={count}")

print("\n")

# =========================
# Detecção simples
# =========================

print("=" * 50)
print("SUSPECT BEHAVIOR")
print("=" * 50)

# Beaconing simples
for conn, count in sorted_conn:

    if count > 20:
        print(f"[!] Possible beaconing: {conn}")

# Domínios suspeitos
for dns in dns_queries:

    domain = dns["domain"]

    # Heurística simples
    if len(domain) > 30:
        print(f"[!] Suspicious long domain: {domain}")

    if domain.count("-") > 5:
        print(f"[!] Possible DGA domain: {domain}")

print("\n[+] Analysis complete.")
