# tcpscan

> TCP SYN scanner with 6-type service fingerprinting

![Python 3.8+](https://img.shields.io/badge/python-3.8+-3776AB?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/license-MIT-green)

A TCP SYN scanner with 6-type service fingerprinting that correctly distinguishes TLS from plain TCP services through ordered probe logic. Dual X.509 certificate extraction with library and raw DER fallback. 2-phase scanning architecture: SYN discovery followed by behavioral probing.

## What it is

tcpscan is a network reconnaissance tool that operates in two phases. Phase 1 sends raw TCP SYN packets to target ports and identifies which are open by reading SYN-ACK responses. Phase 2 connects to each open port and runs an ordered sequence of probes (TCP banner, TLS banner, HTTP GET, generic probe) to classify the service into one of six types. The key insight: a TLS server is also a TCP server, so TLS probes must be attempted before plain TCP probes — otherwise TLS services are misclassified as plain TCP.

## Key features

- **Ordered probe logic** — TLS handshake is attempted before plain TCP probes. If the handshake succeeds, only TLS-based probes are used from that point. If it fails, the service is TCP-only. Prevents misclassifying TLS services as plain TCP.
- **6-type service classification** — TCP server-initiated (banner on connect), TLS server-initiated (banner on TLS), HTTP (GET over TCP), HTTPS (GET over TLS), Generic TCP, Generic TLS.
- **Dual X.509 certificate extraction** — primary path parses DER-encoded certificates via the `cryptography` library and pulls the Common Name. Fallback path manually searches raw DER bytes for the CN OID sequence (`0x55 0x04 0x03`) when the library fails.
- **SYN scanning via Scapy** — raw packet crafting, checks for flags `0x12` (SYN-ACK), sends RST to tear down half-open state.
- **Response sanitization** — non-printable bytes replaced with `.` (matching `tcpdump -A` behavior), capped at 1024 bytes for clean console display.
- **Flexible port specification** — single ports, ranges, comma-separated lists, or mixed (`22,80-90,443`).
- **Fresh connection per probe** — try/finally cleanup, 2s timeouts throughout. Informational messages to stderr, results to stdout for scriptability.

## Quick start

tcpscan requires **root privileges** for raw SYN packet transmission.

```bash
# Install dependencies
pip install scapy cryptography

# Scan default ports (21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080)
sudo python3 tcpscan.py 192.168.1.1

# Scan specific ports
sudo python3 tcpscan.py -p 22,80,443 github.com

# Scan a range
sudo python3 tcpscan.py -p 1-1024 10.0.0.5

# Mixed specification
sudo python3 tcpscan.py -p 22,80-90,443,8080 target.example.org
```

Example output:

```
Host: github.com:22
Type: (1) TCP server-initiated
Response: SSH-2.0-babeld-7de976b0

Host: google.com:443
Type: (4) HTTPS server | CN *.google.com
Response: HTTP/1.0 200 OK
Content-Type: text/html; charset=ISO-8859-1

Host: imap.gmail.com:993
Type: (2) TLS server-initiated | CN imap.gmail.com
Response: * OK Gimap ready for requests from ...
```

## Architecture

```
Target + Ports
      |
      v
Phase 1: SYN Scan (Scapy, raw sockets)
      |
      +-- SYN-ACK (flags 0x12) --> Open port list
      +-- No response / RST ----> Skip
      |
      v
Phase 2: Fingerprinting (per open port)
      |
      +-- TCP connect + wait
      |     +-- Banner received -----> Type 1: TCP server-initiated
      |     +-- No banner -----------> TLS handshake
      |                                 +-- Success + banner --> Type 2: TLS server-initiated
      |                                 +-- Success, TLS GET --> Type 4: HTTPS (response) / Type 6: Generic TLS (none)
      |                                 +-- Failed, TCP GET ---> Type 3: HTTP (response) / Type 5: Generic TCP (none)
```

RST is sent after each SYN-ACK to clean up half-open connections. Raw socket access requires root.

### The six service types

| Type | Name | Detection Method |
|------|------|-----------------|
| 1 | TCP server-initiated | Server sends a banner immediately after TCP connect (SSH, FTP, SMTP) |
| 2 | TLS server-initiated | Server sends data immediately after TLS handshake (IMAPS, POP3S) |
| 3 | HTTP server | Responds to `GET / HTTP/1.0` over plain TCP |
| 4 | HTTPS server | Responds to `GET / HTTP/1.0` over TLS |
| 5 | Generic TCP | Accepts TCP connection but no response to banner wait or GET |
| 6 | Generic TLS | Completes TLS handshake but no response to GET probe |

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.8+ |
| Network | Scapy (SYN scanning), `socket` (TCP connections) |
| TLS | `ssl` module (handshake, cert retrieval) |
| Cryptography | `cryptography` (X.509 CN extraction) |
| Binary parsing | `struct` (DER OID fallback) |

## Testing

tcpscan includes two test harnesses.

**Fingerprint test** (no root required, tests classification logic against live services):

```bash
python3 test_fingerprint.py
```

This imports the fingerprinting functions from `tcpscan` without loading Scapy (patching out the scapy import), then probes real services to verify type classification:

| Target | Port | Expected Type |
|--------|------|--------------|
| github.com | 22 | Type 1 (SSH banner) |
| imap.gmail.com | 993 | Type 2 (IMAP over TLS) |
| example.org | 80 | Type 3 (HTTP server) |
| www.google.com | 443 | Type 4 (HTTPS server) |
| 127.0.0.1 | 9999 | Type 5 (Generic TCP, requires `nc -lkp 9999`) |
| 8.8.8.8 | 853 | Type 6 (DNS-over-TLS) |

**Full integration test** (requires root, runs SYN scan + fingerprinting on a Linux VM):

```bash
sudo bash run_tests.sh
```

Starts `tcpdump`, runs scans against multiple targets to exercise all six types, and captures traffic to `test.pcap` for offline analysis.

## By the numbers

| Metric | Value |
|--------|-------|
| Service types fingerprinted | 6 |
| Scanning phases | 2 (SYN discovery + behavioral probing) |
| Certificate extraction | Dual strategy (cryptography library + raw DER OID fallback) |
| Port specification | Single, range, list, or mixed (e.g. `22,80-90,443`) |
| Response sanitization | Non-printable bytes replaced, capped at 1024 bytes |
| Timeout per probe | 2 seconds |
| Default ports scanned | 13 (21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080) |

## Project context

Part of a 5-project security research portfolio: [Secure Vault](https://github.com/FardinIqbal/secure-vault) (password manager), [NetSec Toolkit](https://github.com/FardinIqbal/netsec-toolkit) (certificate analyzer), [Argus](https://github.com/FardinIqbal/argus) (passive network sniffer), [x86 Exploit Lab](https://github.com/FardinIqbal/x86-exploit-lab) (buffer overflow research).

After building Argus for passive analysis, the natural next step was active reconnaissance. The probe ordering problem — distinguishing TLS from plain TCP when TLS servers are also TCP servers — turned out to be more interesting than expected, and is the design hinge of the tool.

## License

MIT — see [LICENSE](LICENSE).
