#!/usr/bin/env python3
"""Test the fingerprinting logic without root (bypasses SYN scan).
Run this on Mac to verify all 6 types work before testing on Kali."""

import socket
import ssl
import sys
sys.path.insert(0, ".")

# Import fingerprinting functions from tcpscan (skip scapy import)
import importlib.util
import types

# Load tcpscan module without executing scapy import
spec = importlib.util.spec_from_file_location("tcpscan", "tcpscan.py")
loader = spec.loader
source = loader.get_data("tcpscan.py").decode()
# Patch out scapy import so we don't need root
source = source.replace("from scapy.all import IP, TCP, sr1, send, conf", "# scapy skipped for test")
source = source.replace("logging.getLogger(\"scapy.runtime\").setLevel(logging.ERROR)", "")

mod = types.ModuleType("tcpscan")
exec(compile(source, "tcpscan.py", "exec"), mod.__dict__)

fingerprint = mod.fingerprint
sanitize = mod.sanitize
TYPE_LABELS = mod.TYPE_LABELS

# ── Test targets ──────────────────────────────────────────────────────────────
# Each tuple: (host, port, expected_type, description)
tests = [
    ("github.com",             22,  1, "SSH banner over TCP"),
    ("imap.gmail.com",        993,  2, "IMAP banner over TLS"),
    ("www.cs.stonybrook.edu",  80,  3, "HTTP server (GET over TCP)"),
    ("www.google.com",        443,  4, "HTTPS server (GET over TLS)"),
    # Type 5 needs a local netcat: nc -lkp 9999 &
    # ("127.0.0.1",           9999,  5, "Generic TCP (netcat)"),
    ("8.8.8.8",               853,  6, "DNS-over-TLS (generic TLS)"),
]

print("Testing fingerprinting logic (no SYN scan, no root needed)\n")
passed = 0
failed = 0

for host, port, expected, desc in tests:
    # First check port is actually reachable
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.close()
    except Exception as e:
        print(f"  SKIP  {host}:{port} ({desc}) — not reachable: {e}")
        continue

    typ, data, cn = fingerprint(host, port)
    label = TYPE_LABELS[typ]
    if cn and typ in (2, 4, 6):
        label += f" | CN {cn}"
    resp = sanitize(data) if data else "none"

    status = "PASS" if typ == expected else "FAIL"
    if status == "PASS":
        passed += 1
    else:
        failed += 1

    print(f"  {status}  {desc}")
    print(f"        Host: {host}:{port}")
    print(f"        Type: {label}")
    print(f"        Response: {resp[:80]}{'...' if resp and len(resp) > 80 else ''}")
    if typ != expected:
        print(f"        EXPECTED Type {expected}, GOT Type {typ}")
    print()

# Type 5: test with local netcat if running
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("127.0.0.1", 9999))
    s.close()
    typ, data, cn = fingerprint("127.0.0.1", 9999)
    label = TYPE_LABELS[typ]
    resp = sanitize(data) if data else "none"
    status = "PASS" if typ == 5 else "FAIL"
    if status == "PASS":
        passed += 1
    else:
        failed += 1
    print(f"  {status}  Generic TCP (local netcat on 9999)")
    print(f"        Type: {label}")
    print(f"        Response: {resp[:80]}")
    if typ != 5:
        print(f"        EXPECTED Type 5, GOT Type {typ}")
    print()
except Exception:
    print("  SKIP  Type 5 (Generic TCP) — start 'nc -lkp 9999 &' to test\n")

print(f"Results: {passed} passed, {failed} failed, {5 - passed - failed} skipped")
