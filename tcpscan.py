#!/usr/bin/env python3
"""tcpscan - TCP SYN scanner and service fingerprinting tool.

Performs a TCP SYN scan on specified ports, then fingerprints each open port
by attempting to identify the service type (TCP/TLS, server/client-initiated)
and collecting response data.

Usage:  sudo python3 tcpscan.py [-p port_range] <target>
"""

import argparse
import os
import socket
import ssl
import sys

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, sr1, send, conf


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
TIMEOUT = 2            # seconds — for SYN scan and service probes
MAX_RESPONSE = 1024    # bytes to capture per service

GET_PROBE     = b"GET / HTTP/1.0\r\n\r\n"
GENERIC_PROBE = b"\r\n\r\n\r\n\r\n"

TYPE_LABELS = {
    1: "(1) TCP server-initiated",
    2: "(2) TLS server-initiated",
    3: "(3) HTTP server",
    4: "(4) HTTPS server",
    5: "(5) Generic TCP server",
    6: "(6) Generic TLS server",
}


def info(msg):
    """Print informational message to stderr (keeps stdout clean for results)."""
    print(msg, file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# Port parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_ports(spec):
    """Parse port specification: '80', '1-100', '22,80,443', or '22,80-90,443'."""
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo < 1 or hi > 65535 or lo > hi:
                sys.exit(f"Error: invalid port range {lo}-{hi}")
            ports.extend(range(lo, hi + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                sys.exit(f"Error: invalid port number {p}")
            ports.append(p)
    return sorted(set(ports))


# ──────────────────────────────────────────────────────────────────────────────
# SYN scan
# ──────────────────────────────────────────────────────────────────────────────

def syn_scan(target, ports):
    """Send TCP SYN to each port; return sorted list of open (SYN-ACK) ports."""
    conf.verb = 0
    open_ports = []
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=TIMEOUT, verbose=0)
        if resp and resp.haslayer(TCP) and (resp[TCP].flags & 0x12) == 0x12:
            open_ports.append(port)
            # Send RST to tear down the half-open connection.
            send(
                IP(dst=target) / TCP(
                    dport=port,
                    sport=resp[TCP].dport,
                    flags="R",
                    seq=resp[TCP].ack,
                ),
                verbose=0,
            )
    return open_ports


# ──────────────────────────────────────────────────────────────────────────────
# Helpers: connections and I/O
# ──────────────────────────────────────────────────────────────────────────────

def _tcp(target, port):
    """Open a plain TCP socket to target:port. Caller must close."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((target, port))
        return s
    except Exception:
        s.close()
        raise


def _tls(target, port):
    """Open a TLS-wrapped connection. Returns (ssl_socket, CN | None). Caller must close."""
    s = _tcp(target, port)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ts = ctx.wrap_socket(s, server_hostname=target)
        ts.settimeout(TIMEOUT)
        cn = _extract_cn(ts.getpeercert(binary_form=True))
        return ts, cn
    except Exception:
        s.close()
        raise


def _recv(s):
    """Receive up to MAX_RESPONSE bytes with TIMEOUT. Returns bytes or None."""
    try:
        s.settimeout(TIMEOUT)
        d = s.recv(MAX_RESPONSE)
        return d if d else None
    except Exception:
        return None


def _send_recv(s, payload):
    """Send payload then receive response. Returns bytes or None."""
    try:
        s.sendall(payload)
        return _recv(s)
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Certificate CN extraction
# ──────────────────────────────────────────────────────────────────────────────

def _extract_cn(der):
    """Extract the Common Name (CN) from a DER-encoded X.509 certificate."""
    if not der:
        return None

    # Primary method: cryptography library (pre-installed on Kali Linux)
    try:
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.x509.oid import NameOID
        cert = load_der_x509_certificate(der)
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass

    # Fallback: locate the CN OID (2.5.4.3 → bytes 55 04 03) in raw DER
    try:
        idx = der.find(b"\x55\x04\x03")
        if idx >= 0:
            pos = idx + 3          # skip OID bytes
            length = der[pos + 1]  # length of the CN string
            return der[pos + 2 : pos + 2 + length].decode("utf-8", errors="replace")
    except Exception:
        pass

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Response sanitization
# ──────────────────────────────────────────────────────────────────────────────

def sanitize(data):
    """Replace non-printable bytes with '.', preserving printable ASCII + CR/LF/TAB.
    Matches the behavior of tcpdump -A. Capped at MAX_RESPONSE bytes."""
    out = []
    for b in data[:MAX_RESPONSE]:
        if 32 <= b <= 126 or b in (9, 10, 13):
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out).rstrip()


# ──────────────────────────────────────────────────────────────────────────────
# Service fingerprinting
# ──────────────────────────────────────────────────────────────────────────────

def fingerprint(target, port):
    """Determine the service type for an open port.

    Probe order — designed so TLS services are never misclassified as plain TCP.
    A TLS server *is* a TCP server, so TLS probes must be tried first to
    distinguish the two.

      1. Plain TCP connect → wait for server-initiated banner  → Type 1
      2. TLS connect        → wait for server-initiated banner  → Type 2
         If TLS handshake succeeded (port speaks TLS):
           3. Send GET over TLS  → response?                    → Type 4 (HTTPS)
           4. Send generic lines over TLS → (any result)        → Type 6 (Generic TLS)
         If TLS handshake failed (plain TCP only):
           5. Send GET over TCP  → response?                    → Type 3 (HTTP)
           6. Send generic lines over TCP → (any result)        → Type 5 (Generic TCP)

    Returns (type_number, response_bytes | None, common_name | None).
    """

    # ── 1. TCP server-initiated ──────────────────────────────────────────────
    try:
        s = _tcp(target, port)
        try:
            data = _recv(s)
            if data:
                return 1, data, None
        finally:
            s.close()
    except Exception:
        pass

    # ── 2. TLS server-initiated ──────────────────────────────────────────────
    tls_ok = False
    cn = None
    try:
        ts, cn = _tls(target, port)
        tls_ok = True
        try:
            data = _recv(ts)
            if data:
                return 2, data, cn
        finally:
            ts.close()
    except Exception:
        pass

    # ── TLS handshake succeeded → try TLS probes ────────────────────────────
    if tls_ok:
        # 3. HTTPS server (GET over TLS)
        try:
            ts, cn2 = _tls(target, port)
            try:
                data = _send_recv(ts, GET_PROBE)
                if data:
                    return 4, data, cn2 or cn
            finally:
                ts.close()
        except Exception:
            pass

        # 4. Generic TLS server (generic lines over TLS)
        try:
            ts, cn3 = _tls(target, port)
            try:
                data = _send_recv(ts, GENERIC_PROBE)
                return 6, data, cn3 or cn
            finally:
                ts.close()
        except Exception:
            pass

        # TLS handshake worked earlier but reconnection failed — still TLS
        return 6, None, cn

    # ── TLS handshake failed → try plain TCP probes ──────────────────────────

    # 5. HTTP server (GET over TCP)
    try:
        s = _tcp(target, port)
        try:
            data = _send_recv(s, GET_PROBE)
            if data:
                return 3, data, None
        finally:
            s.close()
    except Exception:
        pass

    # 6. Generic TCP server (generic lines over TCP)
    try:
        s = _tcp(target, port)
        try:
            data = _send_recv(s, GENERIC_PROBE)
            return 5, data, None
        finally:
            s.close()
    except Exception:
        pass

    return 5, None, None


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="tcpscan",
        description="TCP SYN scanner with service fingerprinting",
    )
    ap.add_argument(
        "-p", dest="ports",
        help="Ports to scan: single (80), range (1-100), list (22,80,443), "
             "or mixed (22,80-90,443). Default: common ports.",
    )
    ap.add_argument("target", help="Target IP address")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Error: tcpscan requires root privileges for SYN scanning.\n"
                 "Usage: sudo python3 tcpscan.py [-p ports] <target>")

    target = args.target
    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS

    # ── Phase 1: SYN scan ────────────────────────────────────────────────────
    info(f"Scanning {target} ({len(ports)} ports)...")
    open_ports = syn_scan(target, ports)

    if not open_ports:
        info("No open ports found.")
        return

    info(f"Open ports: {', '.join(map(str, open_ports))}\n")

    # ── Phase 2: Service fingerprinting ──────────────────────────────────────
    for port in open_ports:
        info(f"  Probing {target}:{port}...")
        typ, data, cn = fingerprint(target, port)

        label = TYPE_LABELS[typ]
        if cn and typ in (2, 4, 6):
            label += f" | CN {cn}"

        resp = sanitize(data) if data else "none"

        print(f"Host: {target}:{port}")
        print(f"Type: {label}")
        print(f"Response: {resp}")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        info("\nScan interrupted.")
        sys.exit(130)
