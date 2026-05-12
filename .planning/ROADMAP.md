# Roadmap: ARP Spoofing Detector

**Milestone:** v1.0 — Course Demo
**Total phases:** 5
**Total requirements:** 26

## Phases

- [x] **Phase 1: Core Data Layer + Capture Skeleton** - Lay the foundation: threading model, ARP table, conflict logic, and capture loop — fully unit-testable without root or live network (completed 2026-05-09)
- [x] **Phase 2: Detection Pipeline + Alerting** - Wire capture into detection with baseline seeding, gratuitous ARP filtering, rich console alerts, JSONL logging, and graceful shutdown (completed 2026-05-09)
- [x] **Phase 3: Visualization + Reporting** - Generate networkx topology PNG on attack events and produce a pandas-based CSV summary report at session end (completed 2026-05-12)
- [ ] **Phase 4: Shell Integration** - Implement subprocess wrappers and three shell scripts (baseline_scan.sh, analyze_log.sh, capture_raw.sh) meeting course shell-scripting requirement
- [ ] **Phase 5: Integration + Demo Prep** - Assemble main.py full startup sequence, build simulate_attack.py, record demo_capture.pcap fallback, and validate end-to-end demo flow

## Phase Details

### Phase 1: Core Data Layer + Capture Skeleton

**Goal:** The data structures, threading architecture, and capture skeleton are in place and unit-testable before any network access is required.
**UI hint:** no
**Requirements:** CAP-01, CAP-02, CAP-03, CAP-04, DET-01

**Success Criteria:**
1. `arp_table.py` can be imported and its `update()` / `check_conflict()` methods exercised with synthetic IP/MAC dicts — no network access required
2. `capture.py` replays a `.pcap` file and delivers parsed packet dicts to the Queue without dropping packets
3. `detector.py` returns a conflict record when the same IP appears with two different MACs, and returns nothing for a first-seen entry
4. `capture.py` exits immediately with a clear error message when the process is not running as root (os.geteuid() check)
5. Running `capture.py --iface <name>` uses the specified interface; omitting `--iface` prints the auto-detected list from `get_if_list()` and uses the first non-loopback entry

**Key Decisions:**
- Threading model locked here: AsyncSniffer runs in a daemon thread; only the main thread writes to the DataFrame — no locks needed if this contract is respected
- `store=False` set on all `sniff()` calls — retrofitting later requires rewriting the capture loop
- `matplotlib.use("Agg")` added to `visualizer.py` stub in this phase — placing it after any `pyplot` import breaks all visualization

**Plans:** 3/3 plans complete

Plans:
- [x] 01-01-PLAN.md — Project scaffold + ARPTable class (DET-01) + visualizer Agg stub + test_arp_table.py
- [x] 01-02-PLAN.md — detector.py conflict logic + test_detector.py (first-seen, conflict, op filter, gratuitous ARP)
- [x] 01-03-PLAN.md — capture.py AsyncSniffer + Queue + root check + --iface CLI + test_capture.py + pcap fixture

---

### Phase 2: Detection Pipeline + Alerting

**Goal:** A running instance detects ARP spoofing events and immediately surfaces them as colored console alerts and JSONL log entries, with a live ARP table dashboard and clean Ctrl+C shutdown.
**UI hint:** no
**Requirements:** DET-02, DET-03, DET-04, DET-05, ALT-01, ALT-02, ALT-03, ALT-04

**Success Criteria:**
1. At startup, the tool calls `arp-scan --localnet` via subprocess and pre-populates the ARP table before the sniffer starts — a second ARP reply for any baseline IP does not generate a false alarm
2. When a spoofed ARP reply arrives (same IP, different MAC), a red `rich` Panel prints to the terminal within one packet-processing cycle, containing timestamp, attacker MAC, victim IP, original MAC, and attack type label
3. The `rich Live` dashboard updates in place showing the current ARP table rows and the last N alerts — the terminal does not scroll uncontrollably during a sustained attack
4. Every detected conflict is appended as a single JSON object to `arp_detector.log` (default path) immediately on detection — the file is readable with `cat` between events
5. Pressing Ctrl+C flushes the log, prints a session summary (packets seen, attacks detected, unique attacker MACs), and exits with code 0

**Key Decisions:**
- Gratuitous ARP filter (`psrc == pdst` guard) must be applied before table lookup — adding it after detection logic risks shipping false-positive-prone code to the demo
- DET-05 field set (timestamp, attacker MAC, victim IP, original MAC, spoofed MAC, attack type) is the contract between detector and logger/alert — locked here so both consumers use the same keys

**Plans:** 4/4 plans complete

Plans:
- [x] 02-01-PLAN.md — baseline.py: arp-scan subprocess wrapper seeds ARPTable (DET-02)
- [x] 02-02-PLAN.md — logger.py: JSONLLogger class + build_event() DET-05 contract (DET-05, ALT-03, ALT-04)
- [x] 02-03-PLAN.md — alerts.py: format_alert_panel() rich Panel builder (ALT-01)
- [x] 02-04-PLAN.md — main.py: full detection pipeline entry point + live dashboard (DET-03, DET-04, ALT-02, ALT-04)

---

### Phase 3: Visualization + Reporting

**Goal:** The tool generates a networkx topology PNG that visually marks spoofed nodes in red, and produces a pandas CSV summary report at session end.
**UI hint:** no
**Requirements:** VIZ-01, VIZ-02, VIZ-03, VIZ-04, LOG-01, LOG-02, LOG-03

**Success Criteria:**
1. Running the tool with `--visualize` produces a `topology.png` file using the matplotlib Agg backend — the file is a valid PNG viewable outside the terminal (no `plt.show()` call anywhere in the code path)
2. Nodes representing IPs or MACs involved in a detected spoofing event are rendered in red; all other nodes are rendered in green
3. `topology.png` is overwritten each time a new spoofing event is detected — the file on disk always reflects the most recent attack state
4. At session end (Ctrl+C or `--report` flag), a `attack_report.csv` is written containing total packets seen, attacks detected, unique attacker MACs, and a timeline of events — loadable with `pandas.read_csv()` without errors
5. Passing `--logfile <path>` redirects all JSONL log output to the specified path — the default `arp_detector.log` is not created if a custom path is given

**Key Decisions:**
- Bipartite layout (IP nodes left, MAC nodes right) chosen over spring layout — cleaner for small networks and deterministic across renders
- Visualization is off by default (`--visualize` flag required) to avoid WSL2 `$DISPLAY` failures during demo setup

**Plans:** 3/3 plans complete

Plans:
- [x] 03-01-PLAN.md — visualizer.py: implement draw_topology() bipartite PNG generator + test_visualizer.py (VIZ-01, VIZ-02, VIZ-03)
- [x] 03-02-PLAN.md — reporter.py: new module generate_report() pandas CSV writer + test_reporter.py (LOG-01, LOG-02)
- [x] 03-03-PLAN.md — wiring: --visualize/--report/--logfile args in capture.py + call sites in main.py (VIZ-04, LOG-03)

---

### Phase 4: Shell Integration

**Goal:** Three shell scripts and a Python subprocess wrapper module satisfy the course shell-scripting requirement, each independently testable against saved output files.
**UI hint:** no
**Requirements:** SHL-01, SHL-02, SHL-03, SHL-04

**Success Criteria:**
1. `scripts/baseline_scan.sh` runs `arp-scan --localnet`, formats the output as `IP<TAB>MAC` lines, and the detector's baseline loader parses the file correctly on a saved copy of real `arp-scan` output
2. `scripts/analyze_log.sh` accepts `arp_detector.log` as input and prints a human-readable attack summary (attack count, unique IPs, timeline) using only `awk` and `grep` — runnable standalone without Python
3. `scripts/capture_raw.sh` starts `tcpdump -n arp` and writes to a `.pcap` file whose path is configurable via a script argument
4. All Python subprocess calls to shell tools use list-form arguments (not `shell=True`), include a `timeout=` parameter, and print a clear error message on `CalledProcessError` without crashing the detector

**Key Decisions:**
- `shell=True` is prohibited in all subprocess calls — this is both a security constraint and a testability constraint; locked here before any subprocess code is written

**Plans:** 2 plans

Plans:
- [ ] 04-01-PLAN.md — Three shell scripts (baseline_scan.sh, analyze_log.sh, capture_raw.sh) + fixture files (SHL-01, SHL-02, SHL-03)
- [ ] 04-02-PLAN.md — test_shell_scripts.py: fixture-based script tests + SHL-04 subprocess compliance verification

---

### Phase 5: Integration + Demo Prep

**Goal:** The fully assembled tool runs end-to-end from startup to shutdown with a self-contained simulated attack, and a pre-recorded pcap exists as a reliable offline fallback.
**UI hint:** no
**Requirements:** DEMO-01, DEMO-02

**Success Criteria:**
1. `sudo python3 main.py --iface <iface>` completes the full startup sequence (root check → interface detection → arp-scan baseline → tcpdump Popen → AsyncSniffer start → rich.Live loop) without errors on a fresh WSL2 session
2. Running `sudo python3 simulate_attack.py` in a second terminal triggers visible red alerts in the detector after the second crafted packet, demonstrating live detection
3. `demo_capture.pcap` exists and the detector can replay it offline (without root or a live interface) using `rdpcap()`, producing the same alerts as the live simulation
4. The tool exits cleanly after Ctrl+C: log is flushed, `topology.png` is saved (if `--visualize` was set), `analyze_log.sh` summary is printed, and the process returns exit code 0

**Key Decisions:**
- Demo relies on `simulate_attack.py` (self-contained scapy `sendp()`) — WSL2 Hyper-V NAT means real LAN ARP traffic does not reach the WSL2 interface; the demo cannot depend on physical devices

**Plans:** TBD

---

## Requirement Coverage

| Requirement | Phase | Description |
|-------------|-------|-------------|
| CAP-01 | Phase 1 | Live ARP capture via scapy AsyncSniffer with store=False and prn callback |
| CAP-02 | Phase 1 | --iface CLI arg + auto-detect via get_if_list() |
| CAP-03 | Phase 1 | Root privilege check at startup |
| CAP-04 | Phase 1 | Filter to ARP op=2 replies only |
| DET-01 | Phase 1 | In-memory IP→MAC pandas DataFrame persisting across session |
| DET-02 | Phase 2 | Bootstrap ARP table from arp-scan --localnet at startup |
| DET-03 | Phase 2 | Detect IP-MAC conflict (ARP reply with different MAC than known entry) |
| DET-04 | Phase 2 | Filter gratuitous ARPs (psrc == pdst) to avoid false positives |
| DET-05 | Phase 2 | Record attack event with timestamp, attacker MAC, victim IP, original MAC, spoofed MAC, attack type |
| ALT-01 | Phase 2 | Colored rich console alert on detection |
| ALT-02 | Phase 2 | Live-updating rich dashboard (ARP table + recent alerts) |
| ALT-03 | Phase 2 | Persistent JSONL log file (arp_detector.log) |
| ALT-04 | Phase 2 | Graceful Ctrl+C shutdown with log flush and session summary |
| VIZ-01 | Phase 3 | networkx bipartite graph → matplotlib Agg → topology.png |
| VIZ-02 | Phase 3 | Spoofed nodes in red, legitimate nodes in green |
| VIZ-03 | Phase 3 | Regenerate topology.png on each new spoofing event |
| VIZ-04 | Phase 3 | --visualize flag to enable PNG generation (off by default) |
| LOG-01 | Phase 3 | pandas summary report at session end (packets, attacks, unique MACs, timeline) |
| LOG-02 | Phase 3 | Save summary as attack_report.csv via pandas to_csv() |
| LOG-03 | Phase 3 | --logfile <path> argument for custom log location |
| SHL-01 | Phase 4 | baseline_scan.sh: arp-scan --localnet output formatted for detector |
| SHL-02 | Phase 4 | analyze_log.sh: awk/grep parse JSONL log, print human-readable summary |
| SHL-03 | Phase 4 | capture_raw.sh: tcpdump -n arp → .pcap file |
| SHL-04 | Phase 4 | subprocess calls use list-form args, timeout=, CalledProcessError handling |
| DEMO-01 | Phase 5 | simulate_attack.py: craft and send spoofed ARP replies via scapy sendp() |
| DEMO-02 | Phase 5 | demo_capture.pcap: pre-recorded attack traffic for offline demo via rdpcap() |

**Coverage:** 26/26 v1 requirements mapped ✓

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Core Data Layer + Capture Skeleton | 3/3 | Complete   | 2026-05-09 |
| 2. Detection Pipeline + Alerting | 4/4 | Complete    | 2026-05-09 |
| 3. Visualization + Reporting | 3/3 | Complete    | 2026-05-12 |
| 4. Shell Integration | 0/2 | Not started | - |
| 5. Integration + Demo Prep | 0/? | Not started | - |
