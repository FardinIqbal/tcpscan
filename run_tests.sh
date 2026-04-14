#!/bin/bash
# run_tests.sh — Run tcpscan against test targets and capture traffic.
#
# Run this script on your Kali Linux VM as root.
# It starts tcpdump in the background, runs tcpscan against several targets
# to exercise all 6 port types, then stops tcpdump.
#
# Produces:
#   test.pcap  — packet capture of all probe traffic
#   test.out   — command lines and program output
#
# IMPORTANT: Review and adjust the target IPs/ports below to match your test
# environment. You should set up local servers on your VMs for thorough testing
# rather than scanning public hosts excessively.
#
# Usage:  sudo bash run_tests.sh

set -e

PCAP="test.pcap"
OUT="test.out"
TOOL="python3 tcpscan.py"

rm -f "$PCAP" "$OUT"

echo "Starting packet capture..."
tcpdump -i any -w "$PCAP" 2>/dev/null &
TCPDUMP_PID=$!
sleep 2  # let tcpdump initialize

run_scan() {
    local args="$*"
    echo "========================================" >> "$OUT"
    echo "\$ sudo $TOOL $args" >> "$OUT"
    echo "========================================" >> "$OUT"
    # Capture both stdout (results) and stderr (progress) into test.out
    $TOOL $args >> "$OUT" 2>&1
    echo "" >> "$OUT"
    echo "[done] $TOOL $args"
}

# ── Test targets ─────────────────────────────────────────────────────────────
# Adjust these to match your test environment.
#
# Recommended setup: start services on your Kali VM or a second VM, then
# scan them using the VM's IP or 127.0.0.1.
#
# Example local setup:
#   # Type 1 - TCP server-initiated (FTP banner):
#   docker run -d -p 21:21 stilliard/pure-ftpd
#
#   # Type 2 - TLS server-initiated (IMAPS):
#   docker run -d -p 993:993 dovecot/dovecot
#
#   # Type 3 - HTTP server:
#   python3 -m http.server 8080 &
#
#   # Type 4 - HTTPS server:
#   # (use openssl to create a self-signed cert, then run a simple HTTPS server)
#
#   # Type 5 - Generic TCP:
#   nc -lk -p 9999 &
#
#   # Type 6 - Generic TLS:
#   openssl s_server -accept 8853 -cert cert.pem -key key.pem -quiet &

# ── Public server examples (use sparingly) ───────────────────────────────────

# Type 1: TCP server-initiated (SMTP banner)
run_scan "-p 25 smtp.gmail.com"

# Type 2: TLS server-initiated (IMAPS)
run_scan "-p 993 imap.gmail.com"

# Type 3: HTTP server
run_scan "-p 80 www.cs.stonybrook.edu"

# Type 4: HTTPS server
run_scan "-p 443 www.cs.stonybrook.edu"

# Type 6: Generic TLS server (DNS-over-TLS)
run_scan "-p 853 8.8.8.8"

# Type 5: Generic TCP — requires a local server
# Start: nc -lk -p 9999 &
# run_scan "-p 9999 127.0.0.1"

# ── Alternative: scan multiple ports at once ─────────────────────────────────
# run_scan "-p 21,22,25,80,443,853,993 <your-vm-ip>"

# ── Stop capture ─────────────────────────────────────────────────────────────
echo "Stopping packet capture..."
sleep 2
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo ""
echo "Done. Files created:"
echo "  $PCAP — packet capture ($(du -h "$PCAP" | cut -f1))"
echo "  $OUT  — scan output"
echo ""
echo "Contents of $OUT:"
echo "─────────────────────"
cat "$OUT"
echo "─────────────────────"
echo ""
echo "Review the output. You need all 6 types covered."
echo "If Type 5 (Generic TCP) is missing, start 'nc -lk -p 9999 &' and re-run."
