# Architectural Decision Records

Each entry documents a non-obvious engineering choice, its alternatives, and why I picked what I picked.

---

## ADR 1: TLS probe before HTTP probe

**Status:** accepted (the central insight of the project)

**Context:**
Port openness can be determined by SYN scan, but service identification requires sending a probe and inspecting the response. Different services respond to different probes; the question is what order to send them.

A naive approach sends an HTTP `GET` first because HTTP is the most common service. Two options:

1. **HTTP first**: send `GET / HTTP/1.0\r\n\r\n`. If the response starts with `HTTP/1.`, it is HTTP. If not, try the next probe.
2. **TLS first** (this design): send a TLS ClientHello. If the response is `0x16 0x03 ...`, it is TLS-wrapped. If not, try HTTP.

**Decision:**
TLS first.

**Consequences:**

- Pro: TLS-wrapped services (HTTPS, IMAPS, SMTPS, FTPS) respond cleanly to a TLS ClientHello and drop the connection on an HTTP probe.
- Pro: if HTTP went first, a TLS service would be misidentified as "non-HTTP" and require additional probes to recover.
- Pro: TLS responses are structurally distinct (a ServerHello with version bytes), so identification is unambiguous.
- Con: harmless TLS ClientHellos still appear on plain HTTP servers, but they get rejected and we move on cleanly.

The probe-ordering insight is the heart of the project. Most teaching materials present probes in arbitrary order; figuring out that TLS must go first to avoid double-misidentification was the engineering breakthrough of this exercise.

---

## ADR 2: Python threadpool for parallelism

**Status:** accepted

**Context:**
Scanning many ports sequentially is slow. Two options:

1. **Sequential**: simple, but a 100-port scan takes hundreds of seconds.
2. **Threadpool** (this design): `concurrent.futures.ThreadPoolExecutor` with a configurable pool size.
3. **asyncio**: async sockets, no threads.

**Decision:**
Threadpool.

**Consequences:**

- Pro: 50x faster than sequential for typical scans.
- Pro: simple. No async/await refactor.
- Pro: each thread is an independent unit; no shared state to synchronize.
- Con: thread overhead (each holds a stack and a socket). For thousands of concurrent scans, asyncio would scale better.
- Con: Python's GIL serializes CPU-bound work, but the workload is I/O-bound, so the GIL is not an issue here.

For the typical use case (scanning a handful of targets across a few hundred ports), threadpool is the right call. asyncio would be overkill.

---

## ADR 3: Pattern-based service identification

**Status:** accepted

**Context:**
Identifying services from probe responses. Two options:

1. **Pattern matching** (this design): a list of byte signatures with names; the first match wins.
2. **Regex**: more flexible matching.
3. **Heuristic ML**: train a classifier on labeled responses.

**Decision:**
Pattern.

**Consequences:**

- Pro: fast. Substring matching is O(n) per probe.
- Pro: simple. Add a new service by adding a pattern to the list.
- Pro: deterministic. Same response always identifies the same service.
- Con: cannot identify services with non-distinctive banners. Some services (echo, daytime) have ambiguous output.
- Con: pattern conflicts (SMTP and FTP both start with `220 `). Resolved by ordering: SMTP first, then FTP only if context distinguishes.

For 90%+ of services in the wild, pattern matching is sufficient. ML-based identification is a separate, more advanced project.

---

## ADR 4: Two-second connect timeout

**Status:** accepted

**Context:**
SYN-scan probes need a timeout. Too short and slow networks cause false negatives (filtered when port is actually open). Too long and slow scans become unbearable.

**Decision:**
Two seconds.

**Consequences:**

- Pro: covers most real-world latency. Internet round-trips rarely exceed 1 second; intra-datacenter is microseconds.
- Pro: total scan time stays manageable for typical port lists.
- Con: very slow networks (high-latency satellite, congested links) may report false filtered. Configurable via CLI flag.

Two seconds is a pragmatic default. Real network scanners (`nmap`) use adaptive timeouts based on observed RTT. For a study tool, fixed two seconds is good enough.

---

## ADR 5: Banner truncation at 1024 bytes

**Status:** accepted

**Context:**
Service banners are typically short (one line, < 100 bytes). HTTP responses can be much larger. Two options:

1. **Read everything**: gather the full response.
2. **Truncate at 1024 bytes** (this design): read up to 1024 bytes, then close the socket.

**Decision:**
Truncate.

**Consequences:**

- Pro: bounded memory per probe. No surprise multi-megabyte responses.
- Pro: identification only needs the first few bytes. Reading more is wasted work.
- Pro: faster. Closing the socket early signals the server we are done.
- Con: cannot extract detailed metadata (full HTTP headers, full TLS cert chain) from the response.

For service identification, 1024 bytes is plenty. Detailed analysis of identified services would be a separate tool.

---

## ADR 6: No UDP support

**Status:** accepted, deliberately deferred

**Context:**
UDP services exist (DNS, NTP, SNMP, syslog). Scanning UDP requires different logic: there is no SYN/ACK handshake, so openness is determined by either receiving an application-layer response (port is open) or receiving an ICMP Port Unreachable (port is closed).

**Decision:**
TCP only for now.

**Consequences:**

- Pro: simpler. Single state machine (TCP) vs two (TCP + UDP).
- Pro: covers the most common services. Web, mail, SSH, databases all use TCP.
- Con: cannot scan DNS, NTP, SNMP without separate tooling.

Future work: add UDP support with ICMP-based closed-port detection. Would require raw socket access and a UDP-specific probe library.
