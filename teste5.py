from scapy.all import *
import logging
import threading
import time
import re
import math
import statistics
from collections import Counter
from datetime import datetime

# ---------------- CONFIG ----------------
GATEWAY_IP = "10.0.0.2"
VICTIM_IP = "10.0.0.1"
INTERFACE = "enp0s3"

http_streams = {}
http_timestamps = {}

connection_times = {}
port_scan = {}
exfil_data = {}
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

# ---------------- DOMAIN ANALYSIS ----------------
def shannon_entropy(s):
    prob = [n/len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob)

def domain_score(domain):
    d = domain.lower().strip(".")
    labels = d.split(".")
    main = labels[-2] if len(labels) >= 2 else d

    entropy = shannon_entropy(main)
    digit_ratio = sum(c.isdigit() for c in main) / len(main)

    score = 0

    if entropy > 3.5:
        score += 3
    if digit_ratio > 0.3:
        score += 2
    if len(main) > 15:
        score += 2
    if labels[-1] in ["ru", "cn", "tk"]:
        score += 2

    return score

# ---------------- DNS ----------------
def handle_dns(pkt):
    if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP):

        if pkt[IP].src != VICTIM_IP:
            return

        domain = pkt[DNSQR].qname.decode(errors="ignore")

        log(f"{timestamp()} | DNS | {domain} -> {GATEWAY_IP}")

        score = domain_score(domain)
        if score >= 4:
            log(f"{timestamp()} | ALERT | Domínio suspeito: {domain} | score={score}")
            add_score(pkt[IP].src, score, "dominio_suspeito")

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

            data = pkt[Raw].load if pkt.haslayer(Raw) else b""
            send(ip / icmp / data, verbose=0)

# ---------------- PORT SCAN ----------------
def detect_port_scan(src, dport):
    now = time.time()

    if src not in port_scan:
        port_scan[src] = []

    port_scan[src].append((dport, now))
    port_scan[src] = [(p,t) for p,t in port_scan[src] if now - t < 5]

    ports = set(p for p,_ in port_scan[src])

    if len(ports) > 10:
        log(f"{timestamp()} | ALERT | Port scan rápido de {src}")
        add_score(src, 6, "port_scan_temporal")

# ---------------- BEACONING ----------------
def detect_beacon(flow):
    now = time.time()

    if flow not in connection_times:
        connection_times[flow] = []

    connection_times[flow].append(now)
    times = connection_times[flow]

    if len(times) >= 6:
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

        mean = statistics.mean(intervals)
        stdev = statistics.stdev(intervals)

        cv = stdev / mean if mean > 0 else 0

        if cv < 0.2:
            log(f"{timestamp()} | ALERT | Beaconing detectado em {flow}")
            add_score(flow[0], 7, "beaconing_cv")

# ---------------- EXFIL ----------------
def detect_exfil(flow, body):
    now = time.time()
    size = len(body)

    if flow not in exfil_data:
        exfil_data[flow] = []

    exfil_data[flow].append((size, now))
    exfil_data[flow] = [(s,t) for s,t in exfil_data[flow] if now - t < 10]

    total = sum(s for s,_ in exfil_data[flow])

    if total > 2000:
        log(f"{timestamp()} | ALERT | Exfiltração contínua detectada")
        add_score(flow[0], 10, "exfil_continua")

# ---------------- TCP LOG ----------------
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
            detect_exfil(flow, body)

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
print("Gateway Analyzer avançado iniciado...")

sniff(
    iface=INTERFACE,
    filter="udp port 53 or tcp or icmp",
    prn=packet_handler,
    store=0
)