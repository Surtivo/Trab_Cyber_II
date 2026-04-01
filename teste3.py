from scapy.all import *
import logging
import threading
import time
from datetime import datetime

# ---------------- CONFIG ----------------
GATEWAY_IP = "10.0.0.2"
VICTIM_IP = "10.0.0.1"
INTERFACE = "enp0s3"

http_streams = {}
http_timestamps = {}
TIMEOUT = 30

# ---------------- LOG ----------------
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

# ---------------- HEARTBEAT ----------------
def heartbeat():
    while True:
        print("🟢 Script rodando...")
        time.sleep(5)

threading.Thread(target=heartbeat, daemon=True).start()

# ---------------- DNS ----------------
def handle_dns(pkt):
    if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP):

        if pkt[IP].src != VICTIM_IP:
            return

        domain = pkt[DNSQR].qname.decode(errors="ignore")

        log(f"{timestamp()} | DNS_QUERY | SRC={pkt[IP].src} | DOMAIN={domain} | RESOLVED={GATEWAY_IP}")

        resp = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
               UDP(dport=pkt[UDP].sport, sport=53) / \
               DNS(
                   id=pkt[DNS].id,
                   qr=1,
                   aa=1,
                   qd=pkt[DNS].qd,
                   an=DNSRR(rrname=domain, ttl=60, rdata=GATEWAY_IP)
               )

        send(resp, verbose=0)

# ---------------- ICMP ----------------
def handle_icmp(pkt):
    if pkt.haslayer(ICMP) and pkt.haslayer(IP):

        if pkt[IP].src != VICTIM_IP:
            return

        if pkt[ICMP].type == 8:

            log(f"{timestamp()} | ICMP_PING | {pkt[IP].src} -> {pkt[IP].dst}")

            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

            data = b""
            if pkt.haslayer(Raw):
                data = pkt[Raw].load

            send(ip / icmp / data, verbose=0)

# ---------------- TCP LOG ----------------
def handle_tcp_log(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):

        if pkt[IP].src != VICTIM_IP:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        log(f"{timestamp()} | TCP | {src}:{sport} -> {dst}:{dport} | FLAGS={flags}")

# ---------------- HTTP REASSEMBLY ----------------
def handle_http(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    if pkt[IP].src != VICTIM_IP:
        return

    dport = pkt[TCP].dport
    if dport not in [80, 8080]:
        return

    flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, dport)

    payload = pkt[Raw].load

    if flow not in http_streams:
        http_streams[flow] = b""

    http_streams[flow] += payload
    http_timestamps[flow] = time.time()

    try:
        decoded = http_streams[flow].decode(errors="ignore")
    except:
        return

    if "\r\n\r\n" in decoded:

        headers, _, body = decoded.partition("\r\n\r\n")

        log(f"{timestamp()} | HTTP_FULL | {flow}")
        log(headers)

        if body:
            log(f"{timestamp()} | HTTP_BODY | {body[:200]}")

        log("-" * 60)

        del http_streams[flow]
        if flow in http_timestamps:
            del http_timestamps[flow]

# ---------------- CLEANUP ----------------
def cleanup():
    while True:
        now = time.time()
        for flow in list(http_streams.keys()):
            if now - http_timestamps.get(flow, 0) > TIMEOUT:
                del http_streams[flow]
        time.sleep(10)

threading.Thread(target=cleanup, daemon=True).start()

# ---------------- HANDLER ----------------
def packet_handler(pkt):
    if pkt.haslayer(DNSQR):
        handle_dns(pkt)
    elif pkt.haslayer(ICMP):
        handle_icmp(pkt)
    elif pkt.haslayer(TCP):
        handle_tcp_log(pkt)
        handle_http(pkt)

# ---------------- START ----------------
print("🚀 Gateway fake internet + analyzer iniciado...")

sniff(
    iface=INTERFACE,
    filter="udp port 53 or tcp or icmp",
    prn=packet_handler,
    store=0
)
