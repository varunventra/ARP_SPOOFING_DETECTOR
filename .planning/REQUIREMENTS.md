# Requirements: ARP Spoofing Detector

**Defined:** 2026-05-05
**Core Value:** Real-time ARP spoofing detection with immediate console alerts — the tool must catch and surface an active ARP spoofing attack while it is happening, not after.

## v1 Requirements

### Capture

- [ ] **CAP-01**: Tool captures live ARP packets on a specified network interface using scapy with `store=False` and a `prn` callback
- [ ] **CAP-02**: Tool accepts `--iface` CLI argument and auto-detects available interfaces if not provided (via `scapy.get_if_list()`)
- [ ] **CAP-03**: Tool performs a root/sudo privilege check at startup and exits with a clear error message if not running as root
- [ ] **CAP-04**: Tool captures only ARP op=2 (reply) packets via scapy filter `"arp"` with in-code op check

### Detection

- [ ] **DET-01**: Tool maintains an in-memory IP→MAC mapping table (pandas DataFrame) that persists learned associations across the session
- [ ] **DET-02**: Tool bootstraps the ARP table from `arp-scan --localnet` output via subprocess at startup (baseline seeding)
- [ ] **DET-03**: Tool detects IP-MAC conflicts: when an ARP reply maps an IP to a different MAC than the known table entry, it flags a spoofing event
- [ ] **DET-04**: Tool filters out gratuitous ARPs (where `psrc == pdst`) to avoid false positives during normal boot/DHCP cycles
- [ ] **DET-05**: Tool records attack events with: timestamp, attacker MAC, victim IP, original (known) MAC, spoofed MAC, and attack type label

### Alert

- [ ] **ALT-01**: Tool prints a colored console alert (using `rich`) immediately when a spoofing event is detected, including all DET-05 fields
- [ ] **ALT-02**: Tool displays a live-updating terminal dashboard (rich `Live` / `Table`) showing the current ARP table and recent alerts during monitoring
- [ ] **ALT-03**: Tool writes all alerts to a persistent JSONL log file (default: `arp_detector.log`) with one JSON object per event
- [ ] **ALT-04**: Tool handles graceful shutdown on Ctrl+C, flushing the log and printing a session summary

### Visualization

- [ ] **VIZ-01**: Tool generates a networkx bipartite graph (IP nodes ↔ MAC nodes) rendered to a PNG file (`topology.png`) using matplotlib Agg backend
- [ ] **VIZ-02**: Graph highlights spoofed nodes in red and legitimate nodes in green
- [ ] **VIZ-03**: Tool regenerates and overwrites `topology.png` each time a new spoofing event is detected
- [ ] **VIZ-04**: Tool accepts `--visualize` flag to enable PNG generation (off by default to avoid WSL display issues)

### Logging & Reporting

- [ ] **LOG-01**: At session end (or on `--report` flag), tool generates a pandas-based summary report: total packets seen, attacks detected, unique attacker MACs, timeline of events
- [ ] **LOG-02**: Tool saves summary report as a CSV file (`attack_report.csv`) using pandas `to_csv()`
- [ ] **LOG-03**: Tool supports `--logfile <path>` argument to specify a custom log file location

### Shell Integration

- [ ] **SHL-01**: Tool includes a `baseline_scan.sh` shell script that runs `arp-scan --localnet` and formats output for loading into the detector
- [ ] **SHL-02**: Tool includes an `analyze_log.sh` shell script using `awk`/`grep` to parse `arp_detector.log` and print a human-readable attack summary
- [ ] **SHL-03**: Tool includes a `capture_raw.sh` shell script that runs `tcpdump -n arp` and saves to a `.pcap` file for offline analysis
- [ ] **SHL-04**: Python subprocess calls to shell tools use list-form args (not shell=True), include `timeout=` parameters, and handle CalledProcessError gracefully

### Demo Infrastructure

- [ ] **DEMO-01**: Project includes a `simulate_attack.py` script using scapy `sendp()` to craft and send a spoofed ARP reply (fake MAC claiming the gateway IP) for demo purposes
- [ ] **DEMO-02**: Project includes a `demo_capture.pcap` file (pre-recorded ARP attack traffic) as a fallback for offline demo using `rdpcap()`

## v2 Requirements

### Advanced Detection

- **ADV-01**: Rate-based detection — flag hosts sending anomalous numbers of ARP replies per second
- **ADV-02**: Passive arpwatch integration — compare against arpwatch database for additional baseline

### Blocking

- **BLK-01**: iptables rule injection to block attacker MAC when spoofing is confirmed (PRD marks this "advanced")
- **BLK-02**: ARP table poisoning defense — re-inject correct ARP entries via `arp -s` when attack detected

### Notifications

- **NOTF-01**: Email alert on attack detection
- **NOTF-02**: Desktop notification (OS-level popup)

### Reporting

- **RPT-01**: HTML report generation with embedded topology graph
- **RPT-02**: Interactive web dashboard for historical attack review

## Out of Scope

| Feature | Reason |
|---------|--------|
| iptables blocking (v1) | PRD marks it "advanced"; adds privilege/complexity risk for demo |
| Email / desktop notifications | Not required for course demo; adds infrastructure dependency |
| Web/GUI dashboard | CLI-only per PRD; web stack out of scope for scripting workshop |
| Windows-native support | WSL is the target; Win32 raw sockets are a separate problem |
| Database persistence | JSONL + CSV sufficient for course demo scope |
| Multi-subnet / routed networks | Course demo is single-subnet LAN/VM — no routing complexity needed |
| Live matplotlib animation | Conflicts with scapy threading; static PNG is sufficient and reliable |
| ML-based anomaly detection | Overkill for ARP spoofing; deterministic detection is correct approach |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CAP-01 | Phase 1 | Pending |
| CAP-02 | Phase 1 | Pending |
| CAP-03 | Phase 1 | Pending |
| CAP-04 | Phase 1 | Pending |
| DET-01 | Phase 1 | Pending |
| DET-02 | Phase 2 | Pending |
| DET-03 | Phase 2 | Pending |
| DET-04 | Phase 2 | Pending |
| DET-05 | Phase 2 | Pending |
| ALT-01 | Phase 2 | Pending |
| ALT-02 | Phase 2 | Pending |
| ALT-03 | Phase 2 | Pending |
| ALT-04 | Phase 2 | Pending |
| VIZ-01 | Phase 3 | Pending |
| VIZ-02 | Phase 3 | Pending |
| VIZ-03 | Phase 3 | Pending |
| VIZ-04 | Phase 3 | Pending |
| LOG-01 | Phase 3 | Pending |
| LOG-02 | Phase 3 | Pending |
| LOG-03 | Phase 3 | Pending |
| SHL-01 | Phase 4 | Pending |
| SHL-02 | Phase 4 | Pending |
| SHL-03 | Phase 4 | Pending |
| SHL-04 | Phase 4 | Pending |
| DEMO-01 | Phase 5 | Pending |
| DEMO-02 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 26 total
- Mapped to phases: 26
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-05*
*Last updated: 2026-05-05 after roadmap creation (5 phases)*
