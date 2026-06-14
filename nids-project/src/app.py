"""
NIDS - Flask Dashboard
Run this to start the web dashboard + background sniffer thread.
"""

import threading
from flask import Flask, render_template, jsonify
from sniffer import start_sniffing, alerts, traffic_stats

app = Flask(__name__, template_folder="../templates", static_folder="../static")

# ─── Routes ──────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/alerts")
def api_alerts():
    """Return latest 50 alerts as JSON."""
    return jsonify(list(reversed(alerts[-50:])))

@app.route("/api/stats")
def api_stats():
    """Return per-IP traffic summary."""
    data = []
    for ip, s in traffic_stats.items():
        data.append({
            "ip":      ip,
            "packets": s["packets"],
            "bytes":   s["bytes"],
            "ports":   len(s["ports"])
        })
    data.sort(key=lambda x: x["packets"], reverse=True)
    return jsonify(data[:20])

@app.route("/api/summary")
def api_summary():
    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_count = {}
    for a in alerts:
        severity_count[a["severity"]] = severity_count.get(a["severity"], 0) + 1
        type_count[a["type"]] = type_count.get(a["type"], 0) + 1
    return jsonify({
        "total_alerts":    len(alerts),
        "total_ips":       len(traffic_stats),
        "severity":        severity_count,
        "by_type":         type_count
    })

# ─── Background sniffer thread ───────────────────────────────

def run_sniffer():
    try:
        start_sniffing()
    except PermissionError:
        print("\033[91m[ERROR] Run as root/admin for packet capture.\033[0m")
    except Exception as e:
        print(f"\033[91m[ERROR] Sniffer crashed: {e}\033[0m")

if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()
    print("\033[92m[NIDS] Dashboard → http://localhost:5000\033[0m")
    app.run(debug=False, host="0.0.0.0", port=5000)
