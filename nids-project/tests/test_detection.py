"""
Tests for NIDS detection logic.
Run: pytest tests/
"""

import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Reset module-level state between tests
import importlib
import sniffer

def reset():
    sniffer.port_scan_track.clear()
    sniffer.brute_force_track.clear()
    sniffer.dos_track.clear()
    sniffer.icmp_track.clear()
    sniffer.alerts.clear()

# ─── Port Scan ────────────────────────────────────────────

def test_port_scan_not_triggered_below_threshold():
    reset()
    for port in range(sniffer.PORT_SCAN_THRESHOLD - 1):
        result = sniffer.detect_port_scan("1.1.1.1", port)
    assert result == False

def test_port_scan_triggered_at_threshold():
    reset()
    result = False
    for port in range(sniffer.PORT_SCAN_THRESHOLD):
        result = sniffer.detect_port_scan("2.2.2.2", port)
    assert result == True

def test_port_scan_different_ips_independent():
    reset()
    for port in range(sniffer.PORT_SCAN_THRESHOLD):
        sniffer.detect_port_scan("3.3.3.3", port)
    # Different IP should not be flagged
    assert sniffer.detect_port_scan("4.4.4.4", 80) == False

# ─── Brute Force ──────────────────────────────────────────

def test_brute_force_not_triggered_below_threshold():
    reset()
    result = False
    for _ in range(sniffer.BRUTE_FORCE_THRESHOLD - 1):
        result = sniffer.detect_brute_force("5.5.5.5", 22)
    assert result == False

def test_brute_force_triggered_at_threshold():
    reset()
    result = False
    for _ in range(sniffer.BRUTE_FORCE_THRESHOLD):
        result = sniffer.detect_brute_force("6.6.6.6", 22)
    assert result == True

def test_brute_force_separate_ports_independent():
    reset()
    for _ in range(sniffer.BRUTE_FORCE_THRESHOLD):
        sniffer.detect_brute_force("7.7.7.7", 22)
    # Port 3306 should still be clean
    assert sniffer.detect_brute_force("7.7.7.7", 3306) == False

# ─── DoS ──────────────────────────────────────────────────

def test_dos_not_triggered_below_threshold():
    reset()
    result = False
    for _ in range(sniffer.DOS_THRESHOLD - 1):
        result = sniffer.detect_dos("8.8.8.8")
    assert result == False

def test_dos_triggered_at_threshold():
    reset()
    result = False
    for _ in range(sniffer.DOS_THRESHOLD):
        result = sniffer.detect_dos("9.9.9.9")
    assert result == True

# ─── ICMP Flood ───────────────────────────────────────────

def test_icmp_not_triggered_below_threshold():
    reset()
    result = False
    for _ in range(sniffer.ICMP_FLOOD_THRESHOLD - 1):
        result = sniffer.detect_icmp_flood("10.0.0.1")
    assert result == False

def test_icmp_triggered_at_threshold():
    reset()
    result = False
    for _ in range(sniffer.ICMP_FLOOD_THRESHOLD):
        result = sniffer.detect_icmp_flood("10.0.0.2")
    assert result == True

# ─── Severity Map ─────────────────────────────────────────

def test_severity_high():
    assert sniffer.severity_map("DoS Attack") == "HIGH"
    assert sniffer.severity_map("Brute Force") == "HIGH"
    assert sniffer.severity_map("ICMP Flood") == "HIGH"

def test_severity_medium():
    assert sniffer.severity_map("Port Scan") == "MEDIUM"

# ─── Alert Firing ─────────────────────────────────────────

def test_fire_alert_appends_to_list():
    reset()
    sniffer.fire_alert("Port Scan", "192.168.1.1", "Test extra")
    assert len(sniffer.alerts) == 1
    a = sniffer.alerts[0]
    assert a["type"] == "Port Scan"
    assert a["src"]  == "192.168.1.1"
    assert a["severity"] == "MEDIUM"
