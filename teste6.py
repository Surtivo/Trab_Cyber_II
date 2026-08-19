from scapy.all import *
import logging
import threading
import time
import statistics
from collections import defaultdict, Counter
from datetime import datetime

# ---------------- CONFIG ----------------
VICTIM_IP = "10.0.0.1"
INTERFACE = "enp0s3"

WINDOW = 20  # janela de correlação (segundos)

# ---------------- LOG ----------------
logging.basicConfig(filename="gateway.log", level=logging.INFO, format="%(message)s")

def log(msg):
    print(msg)
    logging.info(msg)

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------------- EVENT ENGINE ----------------
events = defaultdict(list)

WEIGHTS = {
    "beaconing": 7,
    "dga": 8,
    "port_scan": 6,
    "exfil": 10
}

def register_event(src, event_type):
    now = time.time()
    weight = WEIGHTS.get(event_type, 1)

    events[src].append({
        "type": event_type,
        "time": now,
        "weight": weight
    })

    log(f"{timestamp()} | EVENT | {src} | {event_type} | weight={weight}")

    classify(src)

# ---------------- CLASSIFICAÇÃO ----------------
def classify(src):
    now = time.time()

    # filtra janela
    recent = [e for e in events[src] if now - e["time"] < WINDOW]

    if not recent:
        return

    total_score = sum(e["weight"] for e in recent)
    types = set(e["type"] for e in recent)

    # prioridade por combinação
    if "exfil" in types and "beaconing" in types:
        level = "CRÍTICO"
    elif total_score >= 15:
        level = "ALTO"
    elif total_score >= 8:
        level = "MÉDIO"
    else:
        level = "BAIXO"

    log(f"{timestamp()} | CLASS | {src} | SCORE={total_score} | TYPES={types} | LEVEL={level}")

# ---------------- DNS (DGA behavior) ----------------
domain_history = defaultdict(list)

def detect_dga(src, domain):
    now = time.time()

    domain_history[src].append((domain, now))
    domain_history[src] = [(d,t) for d,t in domain_history[src] if now - t < 10]

    unique = set(d for d,_ in domain_history[src])

    if len(unique) > 10:
        log(f"{timestamp()} | ALERT | DGA behavior detectado")
        register_event(src, "dga")

def handle_dns(pkt):
    if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP):
        if pkt[IP].src != VICTIM_IP:
            return

        domain = pkt[DNSQR].qname.decode(errors="ignore")
        log(f"{timestamp()} | DNS | {domain}")

        detect_dga(pkt[IP].src, domain)

# ---------------- BEACONING ----------------
connection_times = defaultdict(list)

def detect_beacon(flow):
    now = time.time()

    connection_times[flow].append(now)

    if len(connection_times[flow]) >= 6:
        intervals = [connection_times[flow][i+1] - connection_times[flow][i]
                     for i in range(len(connection_times[flow])-1)]

        mean = statistics.mean(intervals)
        stdev = statistics.stdev(intervals)

        cv = stdev / mean if mean > 0 else 0

        if cv < 0.2:
            log(f"{timestamp()} | ALERT | Beaconing detectado")
            register_event(flow[0], "beaconing")

# ---------------- PORT SCAN ----------------
port_scan = defaultdict(list)

def detect_port_scan(src, dport):
    now = time.time()

    port_scan[src].append((dport, now))
    port_scan[src] = [(p,t) for p,t in port_scan[src] if now - t < 5]

    ports = set(p for p,_ in port_scan[src])

    if len(ports) > 10:
        log(f"{timestamp()} | ALERT | Port scan detectado")
        register_event(src, "port_scan")

# ---------------- EXFIL ----------------
exfil_data = defaultdict(list)

def detect_exfil(flow, size):
    now = time.time()

    exfil_data[flow].append((size, now))
    exfil_data[flow] = [(s,t) for s,t in exfil_data[flow] if now - t < 10]

    total = sum(s for s,_ in exfil_data[flow])

    if total > 2000:
        log(f"{timestamp()} | ALERT | Exfiltração detectada")
        register_event(flow[0], "exfil")

# ---------------- TCP ----------------
def handle_tcp(pkt):
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
    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
        return

    if pkt[IP].src != VICTIM_IP:
        return

    payload = pkt[Raw].load

    if b"POST" in payload or b"PUT" in payload:
        detect_exfil((pkt[IP].src, pkt[TCP].sport), len(payload))

# ---------------- HANDLER ----------------
def packet_handler(pkt):
    if pkt.haslayer(DNSQR):
        handle_dns(pkt)
    elif pkt.haslayer(TCP):
        handle_tcp(pkt)
        handle_http(pkt)

# ---------------- START ----------------
print("Analyzer com correlação iniciado...")

sniff(
    iface=INTERFACE,
    filter="udp port 53 or tcp",
    prn=packet_handler,
    store=0
)