# 🛡️ NIDS — Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)](https://flask.palletsprojects.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5-orange)](https://scapy.net)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)](tests/)

A real-time **Network Intrusion Detection System** built with Python and Scapy. Monitors live network traffic, detects malicious patterns, and displays live alerts on a web dashboard.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Port Scan Detection** | Alerts when a host scans 10+ unique ports in 10 seconds |
| 💣 **DoS Detection** | Flags IPs sending 100+ packets in a 10-second window |
| 🔐 **Brute Force Detection** | Detects repeated hits on SSH (22), FTP (21), RDP (3389), Telnet (23), MySQL (3306) |
| 🏓 **ICMP Flood Detection** | Catches ping flood attacks |
| 📊 **Live Web Dashboard** | Real-time alerts table, charts, and traffic stats — auto-refreshes every 3 seconds |
| 🖥️ **CLI Mode** | Run without a browser — prints alerts to terminal and logs to file |
| 🧪 **Unit Tests** | Full test suite with `pytest` |

---

## 📸 Dashboard Preview

```
┌─────────────────────────────────────────────────────────┐
│ 🛡️ NIDS    Network Intrusion Detection System    ● LIVE │
├────────────┬────────────┬────────────┬───────────────────┤
│ 3 Alerts   │ 1 HIGH     │ 1 MEDIUM   │ 12 IPs Monitored  │
├────────────┴────────────┴────────────┴───────────────────┤
│  [Alerts by Type Chart]    [Top IPs by Packets Chart]    │
├──────────────────────────────────────────────────────────┤
│ # │ Time     │ Type       │ Severity │ Src IP  │ Details │
│ 3 │ 14:02:11 │ Brute Force│ HIGH     │ 10.0.0.5│ Port 22 │
│ 2 │ 14:01:55 │ Port Scan  │ MEDIUM   │ 10.0.0.3│ 12 ports│
│ 1 │ 14:01:40 │ DoS Attack │ HIGH     │ 10.0.0.2│ 102 pkts│
└──────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/Hunterx_/nids.git
cd nids
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3a. Run with Web Dashboard
```bash
sudo python3 src/app.py
# Open http://localhost:5000 in your browser
```

### 3b. Run in CLI Mode (no browser needed)
```bash
sudo python3 src/cli.py
# Optional flags:
sudo python3 src/cli.py --iface eth0
sudo python3 src/cli.py --iface wlan0 --count 1000
```

> **Note:** Root/sudo is required for raw packet capture on Linux/macOS.
> On Windows, install [Npcap](https://npcap.com) and run as Administrator.

---

## 📁 Project Structure

```
nids/
├── src/
│   ├── sniffer.py       # Core packet capture & detection engine
│   ├── app.py           # Flask web dashboard + background sniffer
│   └── cli.py           # CLI-only mode
├── templates/
│   └── index.html       # Dashboard HTML
├── static/
│   ├── css/style.css    # Dark-themed dashboard styles
│   └── js/dashboard.js  # Live charts & auto-refresh logic
├── tests/
│   └── test_detection.py # Pytest unit tests
├── logs/                # Auto-created: nids.log
├── requirements.txt
└── README.md
```

---

## 🔧 How It Works

```
Network Traffic
      │
      ▼
 Scapy Sniffer  (process_packet)
      │
      ├─► IP Layer? ─► Track DoS (packet rate per IP)
      │
      ├─► TCP? ──────► Track Port Scan (unique ports per IP)
      │              ► Track Brute Force (repeat hits on sensitive ports)
      │
      └─► ICMP? ─────► Track ICMP Flood (ping rate per IP)

All checks use a sliding TIME_WINDOW (default 10 seconds).
Detections → fire_alert() → alerts list → API → Dashboard
```

---

## ⚙️ Configuration

Edit thresholds at the top of `src/sniffer.py`:

```python
PORT_SCAN_THRESHOLD   = 10   # unique ports in TIME_WINDOW seconds
BRUTE_FORCE_THRESHOLD = 5    # connections to same sensitive port
DOS_THRESHOLD         = 100  # total packets from one IP
ICMP_FLOOD_THRESHOLD  = 50   # ICMP packets from one IP
TIME_WINDOW           = 10   # sliding window in seconds
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Expected output:
```
tests/test_detection.py::test_port_scan_not_triggered_below_threshold PASSED
tests/test_detection.py::test_port_scan_triggered_at_threshold         PASSED
tests/test_detection.py::test_brute_force_triggered_at_threshold       PASSED
...
14 passed in 0.12s
```

---

## 📖 Concepts Covered

This project demonstrates:
- **Packet Sniffing** — raw socket capture with Scapy
- **TCP/IP Protocol Analysis** — reading IP, TCP, UDP, ICMP headers
- **Sliding Window Algorithm** — time-based rate detection
- **Threat Detection Logic** — port scan, brute force, DoS, ICMP flood
- **REST API Design** — Flask JSON endpoints
- **Real-time Dashboard** — Chart.js, polling, DOM updates
- **Unit Testing** — pytest with state isolation

---

## 🔮 Future Improvements

- [ ] Email/Slack alert notifications
- [ ] GeoIP location of attacker IPs
- [ ] Persistent database storage (SQLite)
- [ ] Machine Learning anomaly detection
- [ ] Export alerts as CSV/PDF report
- [ ] Docker container support

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Adarsh saxena **  
Amity university noida   
[GitHub](https://github.com/Hunterx_) · [LinkedIn](https://linkedin.com/in/adarsh-saxena007)

---

> ⭐ If this project helped you, please give it a star!
