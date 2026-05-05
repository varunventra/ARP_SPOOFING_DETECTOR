# Features: ARP Spoofing Detector

**Domain:** Network security tool — ARP spoofing detection
**Researched:** 2026-05-05
**Scope context:** B.Tech course demo (graded), CLI, Linux/WSL, Python + scapy + networkx/matplotlib

---

## Table Stakes

Features every functional ARP spoofing detector must have. Missing any of these = the tool doesn't work as claimed.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Live ARP packet capture | Core function — passive sniffing of the wire | Low | `scapy.sniff(filter="arp")` with promisc mode; requires root |
| In-memory IP-MAC mapping table | State needed to detect any conflict | Low | Python dict `{ip: mac}` built from observed ARP replies |
| Conflict detection on new ARP reply | Triggers alert when a known IP gets a different MAC | Low | Compare incoming `arp.psrc` / `arp.hwsrc` pair against table |
| Gratuitous ARP detection | Attacker sends unsolicited ARP replies — must catch these | Low | Detect `arp.op == 2` (is-at) with `arp.pdst == arp.psrc` or broadcast destination |
| Colored console alert | Immediate, visible notification during demo | Low | `colorama` or ANSI escape codes; RED for attack, GREEN for normal |
| Persistent log file | Record attacks for post-run review / report submission | Low | Append-only flat file written on each alert event |
| Baseline ARP table at startup | Bootstrap known-good IP-MAC state before monitoring | Medium | Parse `ip neigh` or `arp-scan` output via subprocess; prevents false positives from first-seen entries |
| Graceful shutdown | Ctrl+C stops sniffing cleanly, flushes log | Low | `try/except KeyboardInterrupt` around sniff loop |

---

## Differentiators

Features that separate a good demo from a great one. Each maps to a grading criterion (Python skill, shell integration, visualization).

| Feature | Value Proposition | Complexity | Grading Signal |
|---------|-------------------|------------|----------------|
| Static topology graph (matplotlib/networkx) | Visual proof the tool understands the network state — highly demo-able | Medium | matplotlib + networkx integration requirement |
| Shell script bootstrap (`arp-scan` + `awk`) | Demonstrates shell scripting competency as required by course | Low | Explicit course requirement — evaluator looks for this |
| Attack summary report (pandas DataFrame → CSV) | Structured post-run report using pandas; proves data analysis chops | Medium | pandas integration requirement |
| ARP request vs reply tracking | Distinguish passive table-building (requests) from active spoofing (unsolicited replies) | Low | Reduces false positives; shows understanding of ARP protocol |
| Packet rate anomaly note | Log when ARP packet rate spikes (>N packets/sec from same source) as a secondary indicator | Medium | Shows awareness of rate-based heuristics without full implementation |
| Topology update on attack (graph refresh) | Re-draw graph showing old MAC vs new (spoofed) MAC at a node — visually striking during demo | Medium | Makes visualization *meaningful*, not decorative |
| `tcpdump` parallel capture for evidence | Run tcpdump alongside scapy to produce a `.pcap` for replay / evidence | Low-Med | Uses tcpdump (course-required shell tool) with practical purpose |

---

## Anti-Features

Things to deliberately NOT build for this scope. Building these wastes time and risks destabilizing the demo.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Live animated graph (matplotlib animation loop) | `FuncAnimation` conflicts with scapy's sniff loop; threading required; high crash risk during demo | Static graph saved as PNG on each update, or terminal-mode static graph shown on Ctrl+C |
| iptables auto-blocking / mitigation | PRD explicitly defers this; adds root privilege complexity beyond capture; changes network state during demo | Log the attack; mention blocking as "v2 feature" verbally |
| Email / SMS / webhook alerting | Requires external infra (SMTP server, API keys); adds setup overhead with zero demo value | Console + log file is sufficient; reference notification systems as future extension |
| Web dashboard / Flask UI | CLI-only per PRD; web stack is a separate skill domain not being tested | Rich ANSI terminal output achieves visual impact without a web server |
| Database (SQLite / PostgreSQL) | Flat log file fully satisfies course demo; DB adds schema migration risk | Append CSV or JSONL log |
| Multi-subnet / VLAN awareness | Out of scope for single-subnet lab/VM environment | Hard-code to sniff on one interface; document the assumption |
| Machine learning anomaly detection | Sounds impressive but requires labeled training data and adds a non-deterministic element that may misbehave during demo | Deterministic rule-based detection is more reliable for a graded demo |
| Windows-native packet capture (Npcap/WinPcap) | WSL is the target; Windows-native capture is a separate implementation | Run exclusively under WSL; document this requirement upfront |

---

## Detection Algorithms

### Algorithm Comparison

| Algorithm | Mechanism | False Positive Risk | Complexity | Recommended? |
|-----------|-----------|---------------------|------------|--------------|
| **IP-MAC conflict detection** | Maintain a learned table `{IP: MAC}`; alert when existing entry contradicts incoming ARP reply | Low after baseline bootstrap | Low | YES — primary algorithm |
| **Gratuitous ARP detection** | Alert on ARP op=2 (reply) packets that were not solicited by a pending request | Medium (legitimate gARP exists: NIC reboot, VRRP/HSRP) | Low-Med | YES — secondary indicator, not standalone alarm |
| **Rate-based detection** | Count ARP packets per source MAC per second; alert when rate exceeds threshold | Medium (DHCP storms can trigger) | Medium | OPTIONAL — log as "high ARP rate" annotation, not hard alarm |
| **Static whitelist / ARP table file** | Pre-load a file of known-good IP-MAC pairs; alert on any deviation | Low if file is accurate | Low | OPTIONAL — useful for demo where topology is known |
| **arp-scan bootstrap comparison** | Run `arp-scan -l` at startup; treat result as ground truth; detect deviations | Low | Low-Med | YES — satisfies shell integration requirement AND reduces false positives |

### Recommended Approach

Use a **two-tier strategy**:

**Tier 1 — Bootstrap (before sniffing starts):**
Run `arp-scan -l` via subprocess, parse output with `awk` or Python string parsing, load result into the known-good table. This gives the tool a validated starting state and satisfies the shell scripting requirement.

**Tier 2 — Runtime conflict detection (during sniff loop):**
For every ARP reply (`arp.op == 2`) received:
1. Extract `(src_ip, src_mac)` from the packet.
2. If `src_ip` is in the known table AND `table[src_ip] != src_mac` → trigger SPOOF ALERT.
3. If `src_ip` not in table → add it (learning mode, log as "new host seen").

Flag gratuitous ARPs as a secondary note when the reply is unsolicited (no pending request in a request-tracking dict).

**Why not rate-based as primary?** Rate thresholds are environment-specific. In a VM/lab demo with synthetic attack traffic, a fixed threshold may either miss or false-alarm depending on the attacker tool used. Conflict detection is deterministic and always correct when a spoof occurs.

---

## Log / Report Format

### Per-Event Log Entry

Each detected attack appends one record. Recommended format: **JSONL (one JSON object per line)** for the primary log, with a CSV export via pandas for the summary report.

**JSONL log entry fields:**

```json
{
  "timestamp": "2026-05-05T14:23:11.482Z",
  "event_type": "SPOOF_DETECTED",
  "attacker_mac": "aa:bb:cc:dd:ee:ff",
  "victim_ip": "192.168.1.1",
  "legitimate_mac": "11:22:33:44:55:66",
  "spoofed_mac": "aa:bb:cc:dd:ee:ff",
  "packet_count": 1,
  "interface": "eth0",
  "notes": "Gratuitous ARP (unsolicited reply)"
}
```

**Why JSONL over plain text:**
- Machine-readable: pandas can load it with `pd.read_json(..., lines=True)` for the summary report
- Human-readable: each line is self-describing
- Grep-friendly: `grep SPOOF_DETECTED arp_detector.log` still works

**Why not syslog format:** Syslog adds a daemon dependency (rsyslogd). For a course demo, file-based logging is simpler and the evaluator can inspect it directly.

**Why not CSV as primary:** CSV struggles with variable-length fields (notes, nested data) and requires a schema header that complicates append-only writes. Use CSV only for the summary report (pandas export).

### Summary Report (on exit)

When the tool exits (Ctrl+C), generate a summary CSV via pandas:

| Column | Description |
|--------|-------------|
| `timestamp` | Attack detection time |
| `victim_ip` | IP address that was spoofed |
| `legitimate_mac` | Original known-good MAC |
| `spoofed_mac` | MAC sent by attacker |
| `event_count` | Number of times this IP-MAC conflict was seen |

Save as `arp_report_<timestamp>.csv`. Print summary stats to console (total attacks, unique victims, duration of monitoring session).

---

## Visualization Approach

### What to Build

A **static node-graph snapshot** using `networkx` + `matplotlib`, saved as `topology_<timestamp>.png` and optionally displayed inline on exit (or re-drawn on each new attack).

### Graph Structure

- **Nodes:** One per IP address observed on the network
- **Edges:** IP node connected to MAC address node(s) it has been associated with
- **Node colors:**
  - Blue: router/gateway (detected from ARP table or by IP heuristic: `.1` or `.254`)
  - Green: normal hosts (clean IP-MAC association)
  - Red: spoofed/victim nodes (IP with conflicting MAC mappings)
  - Orange: attacker node (MAC that sent a conflicting reply)
- **Edge styles:**
  - Solid black: current/active association
  - Dashed red: spoofed (overwritten) association
- **Labels:** Show both IP and short MAC (`aa:bb:...:ff`) on nodes

### What "Topology Change" Looks Like

Before attack: `192.168.1.1 -- 11:22:33:44:55:66` (solid green)

After spoof detected:
- Node `192.168.1.1` turns RED
- Add dashed red edge: `192.168.1.1 -- aa:bb:cc:dd:ee:ff` (attacker MAC)
- Original edge shown as faded/dashed to indicate it was the legitimate mapping
- Legend shows: "RED = spoofed IP", "DASHED = fraudulent mapping"

### Implementation Notes

- Use `networkx.draw_networkx()` with `pos = networkx.spring_layout(G)` for automatic layout
- Bipartite layout (`ip_nodes` on left, `mac_nodes` on right) is cleaner and more readable for small networks (< 20 nodes) — preferred for demo
- Re-draw by clearing `plt.clf()` and calling draw again; save with `plt.savefig()`
- Do NOT use `plt.show()` in the sniff loop — it blocks. Save to file; show only at end or in a separate thread
- For a WSL demo environment, save PNG and open with `xdg-open` or instruct evaluator to view the file

### Why Static PNG Over Live Animation

`matplotlib.animation.FuncAnimation` requires its own event loop, which conflicts with scapy's `sniff()` blocking call. Running both requires threading or multiprocessing — high complexity, high crash risk during a graded demo. Static PNG generated on attack detection is reliable and still visually compelling.

---

## Course Demo Completeness Checklist

What constitutes a "complete" detector for the graded demo vs production:

| Criterion | Course Demo | Production |
|-----------|-------------|------------|
| Detection accuracy | Correct on synthetic lab attack (e.g., `arpspoof`, `ettercap`) | Must handle real adversarial traffic, evasion |
| False positive rate | Acceptable if documented; 1-2 gARP false positives during demo is fine | Must be tuned; gARP from VRRP/HSRP must not alarm |
| Performance | Single-threaded is fine for < 100 hosts | Multi-threaded or async for high-traffic networks |
| Baseline source | `arp-scan` output at startup | Authenticated DHCP binding table or 802.1X integration |
| Log retention | One session, flat file | Rotated, centralized, SIEM-integrated |
| Alert channel | Console + log file | PagerDuty, SIEM, email, Slack |
| Mitigation | None (log only) | iptables/ACL block, DHCP snooping integration |
| Test coverage | Manual demo with attacker VM or `arpspoof` | Unit tests, integration tests, CI |

**Minimum viable demo (will pass grading):** Capture ARP → detect one conflict → print colored alert → write to log → show topology PNG with one red node.

**Strong demo (will score well):** All of the above + `arp-scan` bootstrap via shell script + pandas summary CSV + bipartite topology graph updated on attack + tcpdump running in parallel.

---

## Feature Dependencies

```
arp-scan bootstrap → IP-MAC table (populated at start)
    ↓
Live scapy sniff → IP-MAC conflict detection
    ↓
Conflict detected → Console alert (colorama)
                 → JSONL log append
                 → networkx graph update → PNG save
    ↓ (on exit)
pandas load JSONL → Summary CSV
                 → Console stats printout
```

Shell script dependency:
```
arp-scan (shell) → parsed by Python/awk → populates baseline table
tcpdump (shell)  → runs in background subprocess → produces .pcap (evidence)
```

---

## Sources

- Domain knowledge: ARP protocol (RFC 826), gratuitous ARP behavior (RFC 5227)
- Tool reference: arpwatch (LBNL), arp-scan man page, scapy documentation
- Pattern reference: Cain & Abel, ettercap, arpspoof attack signatures (well-documented in security literature)
- Confidence: HIGH for detection algorithms and log formats (established practice, unchanged since RFC 826); MEDIUM for visualization specifics (networkx API stable but layout recommendations from community patterns)
