from scapy.all import *
import logging
import threading
import time
import re
from datetime import datetime

# ---------------- CONFIG ----------------
GATEWAY_IP = "10.0.0.2"
VICTIM_IP = "10.0.0.1"
INTERFACE = "enp0s3"

http_streams = {}
http_timestamps = {}

connection_times = {}
port_scan = {}
THREAT_SCORE = {}

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

# ---------------- SCORE ----------------
def add_score(src, value, reason):
    if src not in THREAT_SCORE:
        THREAT_SCORE[src] = 0

    THREAT_SCORE[src] += value

    log(f"{timestamp()} | SCORE | {src} +{value} ({reason}) | TOTAL={THREAT_SCORE[src]}")

    if THREAT_SCORE[src] >= 15:
        log(f"{timestamp()} | ALERT | POSSÍVEL MALWARE DETECTADO: {src}")

# ---------------- HEARTBEAT ----------------
def heartbeat():
    while True:
        print("Script rodando...")
        time.sleep(5)

threading.Thread(target=heartbeat, daemon=True).start()

# ---------------- DNS ----------------
def is_suspicious_domain(domain):
    return bool(re.match(r"[a-z0-9]{10,}", domain)) 

def handle_dns(pkt):
    if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP):

        if pkt[IP].src != VICTIM_IP:
            return

        domain = pkt[DNSQR].qname.decode(errors="ignore")

        log(f"{timestamp()} | DNS | {domain} -> {GATEWAY_IP}")

        if is_suspicious_domain(domain):
            log(f"{timestamp()} | ALERT | Domínio suspeito: {domain}")
            add_score(pkt[IP].src, 5, "dominio_suspeito")

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

            log(f"{timestamp()} | ICMP | {pkt[IP].src} -> {pkt[IP].dst}")

            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

            data = b""
            if pkt.haslayer(Raw):
                data = pkt[Raw].load

            send(ip / icmp / data, verbose=0)

# ---------------- TCP LOG ----------------
def detect_port_scan(src, dport):
    if src not in port_scan:
        port_scan[src] = set()

    port_scan[src].add(dport)

    if len(port_scan[src]) > 10:
        log(f"{timestamp()} | ALERT | Port scan detectado de {src}")
        add_score(src, 5, "port_scan")

def detect_beacon(flow):
    now = time.time()

    if flow not in connection_times:
        connection_times[flow] = []

    connection_times[flow].append(now)

    times = connection_times[flow]

    if len(times) >= 5:
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg = sum(intervals) / len(intervals)

        if max(intervals) - min(intervals) < 1:
            log(f"{timestamp()} | ALERT | Beaconing detectado em {flow}")
            add_score(flow[0], 5, "beaconing")

def handle_tcp_log(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):

        if pkt[IP].src != VICTIM_IP:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        flow = (src, sport, dst, dport)

        log(f"{timestamp()} | TCP | {src}:{sport} -> {dst}:{dport}")

        detect_port_scan(src, dport)
        detect_beacon(flow)

# ---------------- HTTP ----------------
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

            if len(body) > 500:
                log(f"{timestamp()} | ALERT | Possível exfiltração")
                add_score(flow[0], 10, "exfiltracao")

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
print("Gateway Analyzer iniciado...")

sniff(
    iface=INTERFACE,
    filter="udp port 53 or tcp or icmp",
    prn=packet_handler,
    store=0
)