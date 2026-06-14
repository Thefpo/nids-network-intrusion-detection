"""
NIDS - Network Intrusion Detection System
Core packet sniffer and detection engine
"""

import time
import json
import logging
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

# Configure logging
logging.basicConfig(
    filename='logs/nids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ─── Thresholds ───────────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 10   # unique ports/src in TIME_WINDOW seconds
BRUTE_FORCE_THRESHOLD = 5    # connections/src to same port in TIME_WINDOW seconds
DOS_THRESHOLD         = 100  # packets/src in TIME_WINDOW seconds
ICMP_FLOOD_THRESHOLD  = 50   # ICMP packets/src in TIME_WINDOW seconds
TIME_WINDOW           = 10   # seconds

# ─── In-memory state ──────────────────────────────────────────
traffic_stats   = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})
port_scan_track = defaultdict(lambda: defaultdict(list))   # src → port → [timestamps]
brute_force_track = defaultdict(lambda: defaultdict(list)) # src → port → [timestamps]
dos_track       = defaultdict(list)                         # src → [timestamps]
icmp_track      = defaultdict(list)                         # src → [timestamps]

alerts = []  # shared list, imported by app.py

def _purge_old(timestamps, window=TIME_WINDOW):
    now = time.time()
    return [t for t in timestamps if now - t < window]

def detect_port_scan(src, dst_port):
    now = time.time()
    port_scan_track[src][dst_port].append(now)
    port_scan_track[src][dst_port] = _purge_old(port_scan_track[src][dst_port])
    unique_ports = [p for p, ts in port_scan_track[src].items() if ts]
    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        return True
    return False

def detect_brute_force(src, dst_port):
    now = time.time()
    brute_force_track[src][dst_port].append(now)
    brute_force_track[src][dst_port] = _purge_old(brute_force_track[src][dst_port])
    if len(brute_force_track[src][dst_port]) >= BRUTE_FORCE_THRESHOLD:
        return True
    return False

def detect_dos(src):
    now = time.time()
    dos_track[src].append(now)
    dos_track[src] = _purge_old(dos_track[src])
    if len(dos_track[src]) >= DOS_THRESHOLD:
        return True
    return False

def detect_icmp_flood(src):
    now = time.time()
    icmp_track[src].append(now)
    icmp_track[src] = _purge_old(icmp_track[src])
    if len(icmp_track[src]) >= ICMP_FLOOD_THRESHOLD:
        return True
    return False

def fire_alert(alert_type, src, extra=""):
    alert = {
        "id": len(alerts) + 1,
        "type": alert_type,
        "src": src,
        "extra": extra,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity_map(alert_type)
    }
    alerts.append(alert)
    msg = f"[ALERT] {alert_type} | SRC: {src} | {extra}"
    logging.warning(msg)
    print(f"\033[91m{msg}\033[0m")

def severity_map(alert_type):
    high   = ["DoS Attack", "ICMP Flood", "Brute Force"]
    medium = ["Port Scan"]
    if alert_type in high:   return "HIGH"
    if alert_type in medium: return "MEDIUM"
    return "LOW"

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    size = len(pkt)

    # Update global traffic stats
    traffic_stats[src]["packets"] += 1
    traffic_stats[src]["bytes"]   += size

    # ── DoS detection (all protocols) ─────────────────────────
    if detect_dos(src):
        fire_alert("DoS Attack", src, f"{len(dos_track[src])} pkts in {TIME_WINDOW}s")

    # ── TCP ───────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
        traffic_stats[src]["ports"].add(dst_port)

        if detect_port_scan(src, dst_port):
            ports = list(port_scan_track[src].keys())[-5:]
            fire_alert("Port Scan", src, f"Ports: {ports}…")

        if dst_port in (22, 21, 3389, 23, 3306):
            if detect_brute_force(src, dst_port):
                fire_alert("Brute Force", src, f"Port {dst_port} hit {BRUTE_FORCE_THRESHOLD}+ times")

    # ── ICMP ──────────────────────────────────────────────────
    if pkt.haslayer(ICMP):
        if detect_icmp_flood(src):
            fire_alert("ICMP Flood", src, f"{len(icmp_track[src])} pings in {TIME_WINDOW}s")

def start_sniffing(interface=None, count=0):
    """
    Start sniffing. interface=None → scapy picks default.
    count=0 → sniff indefinitely.
    """
    iface = interface or _auto_iface()
    print(f"\033[92m[NIDS] Sniffing on interface: {iface}\033[0m")
    print("\033[93m[NIDS] Press Ctrl+C to stop.\033[0m\n")
    sniff(iface=iface, prn=process_packet, store=False, count=count)

def _auto_iface():
    ifaces = get_if_list()
    for preferred in ("eth0", "wlan0", "en0", "ens33"):
        if preferred in ifaces:
            return preferred
    return ifaces[0] if ifaces else "eth0"
