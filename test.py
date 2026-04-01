from scapy.all import *
import logging
import random
from datetime import datetime

MALWARE_IP = "10.0.0.2"
dns_map = {}

logging.basicConfig(
    filename="gateway.log",
    level=logging.INFO,
    format="%(message)s"
)

def log(msg):
    print(msg)
    logging.info(msg)

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def fake_ip():
    return f"10.0.0.{random.randint(100,200)}"

# ---------------- DNS ----------------
def handle_dns(pkt):
    if pkt.haslayer(DNSQR) and pkt[IP].src == MALWARE_IP:

        domain = pkt[DNSQR].qname.decode()

        if domain not in dns_map:
            dns_map[domain] = fake_ip()

        ip_fake = dns_map[domain]

        log(f"{timestamp()} | DNS_QUERY | SRC={pkt[IP].src} | DOMAIN={domain} | RESOLVED={ip_fake}")

        resp = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
               UDP(dport=pkt[UDP].sport, sport=53)/ \
               DNS(id=pkt[DNS].id, qr=1, aa=1,
                   qd=pkt[DNS].qd,
                   an=DNSRR(rrname=domain, ttl=60, rdata=ip_fake))

        send(resp)

# ---------------- TCP ----------------
connections = {}

def handle_tcp(pkt):
    if pkt.haslayer(TCP) and pkt[IP].src == MALWARE_IP:

        if pkt[TCP].flags == "S":

            dst = pkt[IP].dst
            port = pkt[TCP].dport

            log(f"{timestamp()} | TCP_CONNECT | SRC={pkt[IP].src} | DST={dst}:{port}")

            connections[dst] = connections.get(dst, 0) + 1

            if connections[dst] > 5:
                print(f"⚠ Possível comportamento suspeito: {dst}")

            ip = IP(dst=pkt[IP].src, src=dst)
            tcp = TCP(
                sport=port,
                dport=pkt[TCP].sport,
                flags="SA",
                seq=1000,
                ack=pkt[TCP].seq + 1
            )

            send(ip/tcp)

# ---------------- SNIFF ----------------
sniff(
    filter="host 10.0.0.2 and (tcp or udp port 53)",
    prn=lambda pkt: (handle_dns(pkt), handle_tcp(pkt)),
    store=0
)
