"""
NIDS - CLI Mode
Run without the web dashboard. Prints alerts to terminal and logs to file.
Usage: sudo python3 src/cli.py
       sudo python3 src/cli.py --iface eth0
       sudo python3 src/cli.py --iface eth0 --count 500
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from sniffer import start_sniffing, alerts

def main():
    parser = argparse.ArgumentParser(description="NIDS - Network Intrusion Detection System")
    parser.add_argument("--iface",  default=None,  help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("--count",  default=0, type=int, help="Packet count (0 = unlimited)")
    args = parser.parse_args()

    print("""
 ███╗   ██╗██╗██████╗ ███████╗
 ████╗  ██║██║██╔══██╗██╔════╝
 ██╔██╗ ██║██║██║  ██║███████╗
 ██║╚██╗██║██║██║  ██║╚════██║
 ██║ ╚████║██║██████╔╝███████║
 ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝
 Network Intrusion Detection System
 github.com/YOUR_USERNAME/nids
    """)

    try:
        start_sniffing(interface=args.iface, count=args.count)
    except KeyboardInterrupt:
        print(f"\n\n[NIDS] Stopped. Total alerts fired: {len(alerts)}")
    except PermissionError:
        print("[ERROR] Root/admin privileges required. Try: sudo python3 src/cli.py")
        sys.exit(1)

if __name__ == "__main__":
    main()
