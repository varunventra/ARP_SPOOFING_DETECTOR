# Architecture: ARP Spoofing Detector

**Researched:** 2026-05-05
**Confidence:** HIGH — components and patterns are well-established for this class of tool

---

## Component Map

| Component | Module | Responsibility |
|-----------|--------|----------------|
| **Packet Capture Engine** | `capture.py` | Wraps `scapy.sniff()` in a background thread; filters for ARP packets only (filter="arp"); emits parsed packet dicts to a shared queue |
| **ARP Table Manager** | `arp_table.py` | Owns a `pandas.DataFrame` keyed on IP address, columns: `ip`, `mac`, `first_seen`, `last_seen`, `count`; provides `update(ip, mac)` and `get_conflicts()` methods |
| **Detection Engine** | `detector.py` | Consumes updates from the ARP Table Manager; compares incoming IP→MAC against stored mapping; flags conflicts (same IP, different MAC = spoofing candidate) |
| **Alert System** | `alerts.py` | Receives conflict events; prints colored console output using `colorama` or `rich`; writes structured lines to the log file |
| **Logger / Reporter** | `logger.py` | Writes timestamped CSV/JSON lines to `arp_spoofing.log`; provides `generate_report()` that shells out to `awk`/`grep` for summary stats |
| **Visualization Engine** | `visualizer.py` | Builds a `networkx` graph from the ARP table; renders with `matplotlib`; highlights conflicted nodes in red; updates on demand (not continuously, to avoid blocking) |
| **Shell Integration Layer** | `shell_tools.py` | Thin wrappers around `subprocess.run()` for `arp-scan`, `tcpdump`, `awk`, `grep`; returns parsed output as Python dicts/lists |
| **CLI Entrypoint** | `main.py` | Parses args (`argparse`); orchestrates startup sequence; owns the main loop; coordinates threads; renders live dashboard via `rich.Live` |

---

## Data Flow

```
[Network Interface]
       |
       | raw packets (scapy sniff, BPF filter="arp")
       v
[Packet Capture Engine]  ← runs in background Thread
       |
       | parsed dict: {ip, mac, op, timestamp}
       | pushed into threading.Queue
       v
[Main Loop]  ← reads Queue, dispatches
       |
       |---> [ARP Table Manager]
       |           |
       |           | conflict detected? YES
       |           v
       |     [Detection Engine]
       |           |
       |     ------+------
       |     |           |
       v     v           v
  [Alert System]    [Logger]
  (console color)   (log file)
       |
       | on-demand / interval
       v
  [Visualizer]  (matplotlib window or saved PNG)
       
[Shell Integration Layer]  ← called at startup and on-demand
       |
       | baseline ARP table from arp-scan
       v
[ARP Table Manager]  ← seeded with baseline before capture starts
```

Key points:
- `threading.Queue` is the only shared state between the capture thread and the main thread — this avoids locks on the DataFrame itself
- The DataFrame is only written from the main thread (after dequeuing), so no concurrent writes
- Visualization reads the DataFrame; a snapshot copy (`df.copy()`) is taken before rendering to avoid read/write races

---

## Threading Model

**Why threads are needed:** `scapy.sniff()` blocks the calling thread indefinitely. The main thread must stay free to update the live dashboard, handle keyboard interrupts, and call shell tools.

**Model: two threads + one queue**

```
Thread 1 — Main Thread
  - Runs argparse, startup, arp-scan baseline
  - Reads Queue in a loop (queue.get(timeout=0.1))
  - Updates ARP Table Manager
  - Calls Detection Engine per update
  - Drives rich.Live dashboard refresh (every ~1s)
  - Handles Ctrl+C (KeyboardInterrupt) for clean shutdown

Thread 2 — Capture Thread (daemon=True)
  - Calls scapy.sniff(prn=callback, filter="arp", store=False)
  - Callback puts parsed packet onto Queue
  - Marked daemon so it dies automatically when main exits
```

**Visualization threading:**
- Do NOT run matplotlib in a separate thread — matplotlib is not thread-safe
- Two acceptable options for this project scope:
  1. **On-demand only:** User presses a key or passes `--visualize`; main thread pauses sniffing display briefly, renders graph, saves to PNG, resumes (simplest — recommended for course demo)
  2. **Matplotlib interactive mode (`plt.ion()`):** Call `plt.pause(0.001)` in the main loop to pump the event loop — works but can flicker; acceptable for demo

**Recommendation:** Use option 1 (save to PNG on demand). It avoids all threading complexity with matplotlib and is easier to demo.

**Shutdown sequence:**
```python
# In main thread on KeyboardInterrupt:
stop_event.set()          # signals capture thread to stop
capture_thread.join(timeout=3)
logger.flush()
visualizer.save_final()
```

Pass a `threading.Event` to the capture thread; the sniff `stop_filter` checks it.

---

## Recommended File Structure

```
arp-spoof-detector/
├── main.py                  # CLI entrypoint, argparse, main loop
├── capture.py               # scapy sniff wrapper, capture thread
├── arp_table.py             # pandas DataFrame manager
├── detector.py              # conflict detection logic
├── alerts.py                # colored console output, colorama/rich
├── logger.py                # file logger, report generator
├── visualizer.py            # networkx + matplotlib graph
├── shell_tools.py           # subprocess wrappers for arp-scan, tcpdump, awk, grep
│
├── scripts/
│   ├── baseline_scan.sh     # runs arp-scan, formats output for import
│   ├── analyze_log.sh       # awk/grep summary of arp_spoofing.log
│   └── capture_raw.sh       # tcpdump raw capture to .pcap for offline analysis
│
├── tests/
│   ├── test_detector.py     # unit tests for conflict detection logic
│   └── test_arp_table.py    # unit tests for DataFrame update/query
│
├── logs/
│   └── arp_spoofing.log     # runtime output (gitignored)
│
├── output/
│   └── topology.png         # saved graph output (gitignored)
│
├── requirements.txt
└── README.md
```

**Notes:**
- Shell scripts in `scripts/` are first-class files, not inline strings — this satisfies the course requirement to demonstrate shell scripting as a distinct skill
- `shell_tools.py` calls those scripts (or equivalent inline commands) via `subprocess.run()`
- `logs/` and `output/` are gitignored; created at runtime if absent

---

## Build Order

Each component depends on the ones above it. Build strictly in this order:

```
1. arp_table.py          — no dependencies; pure pandas; testable in isolation
       |
2. detector.py           — depends only on arp_table; testable with mock data
       |
3. logger.py             — depends on detector output shape; no network needed
       |
4. alerts.py             — depends on detector output shape; test with dummy conflicts
       |
5. shell_tools.py        — subprocess wrappers; test by running arp-scan manually
       |
6. capture.py            — depends on Queue contract; test by replaying a .pcap with scapy
       |
7. visualizer.py         — depends on arp_table being populated; test with synthetic data
       |
8. main.py               — wires all components; requires all above to exist
       |
9. scripts/*.sh          — written alongside the Python component they support
                            (baseline_scan.sh alongside shell_tools.py, etc.)
```

**Rationale for this order:**
- The detection core (steps 1-4) can be built and unit-tested entirely without root privileges or a live network — critical for development in a restricted environment
- Shell tools (step 5) are isolated; failures here don't break the Python pipeline
- Packet capture (step 6) is last because it needs root and a live interface; mock it during earlier development by feeding synthetic dicts into the Queue
- `main.py` is assembled last because it is pure orchestration — no logic of its own

---

## Shell Integration

**Pattern:** Python calls shell tools via `subprocess.run()`, captures stdout, parses it. Shell scripts are NOT used for logic — only for invoking tools that have no Python equivalent.

**`shell_tools.py` — three functions needed:**

```python
# 1. Baseline ARP table from arp-scan
def run_arp_scan(interface: str) -> list[dict]:
    result = subprocess.run(
        ["sudo", "arp-scan", "--localnet", "-I", interface],
        capture_output=True, text=True, check=True
    )
    return parse_arp_scan_output(result.stdout)  # returns [{ip, mac}, ...]

# 2. Raw capture for forensics (fire-and-forget)
def start_tcpdump(interface: str, output_file: str) -> subprocess.Popen:
    return subprocess.Popen(
        ["sudo", "tcpdump", "-i", interface, "arp", "-w", output_file],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

# 3. Log summary (calls the .sh script or inline awk)
def summarize_log(log_path: str) -> str:
    result = subprocess.run(
        ["awk", '-F,', '{print $3}', log_path],  # example: extract MACs
        capture_output=True, text=True
    )
    return result.stdout
```

**`scripts/baseline_scan.sh` — demonstrates shell scripting for grader:**
```bash
#!/bin/bash
# baseline_scan.sh — runs arp-scan and emits CSV for Python import
IFACE=${1:-eth0}
sudo arp-scan --localnet -I "$IFACE" \
  | grep -E '^[0-9]' \
  | awk '{print $1 "," $2}'
```

**`scripts/analyze_log.sh` — post-run log analysis:**
```bash
#!/bin/bash
# analyze_log.sh — summarizes arp_spoofing.log
LOG=${1:-logs/arp_spoofing.log}
echo "=== Attack Summary ==="
grep "CONFLICT" "$LOG" | awk -F',' '{print $2}' | sort | uniq -c | sort -rn
echo "Total events: $(wc -l < "$LOG")"
```

**Integration contract:**
- Shell scripts write only to stdout (no side effects) — Python owns all file I/O
- Python owns the log file; shell scripts only read it for analysis
- `tcpdump` is the exception — it writes its own .pcap file; Python just starts/stops the process

**Privilege handling:**
- `arp-scan` and `scapy.sniff()` require root
- Recommend running the whole tool with `sudo python3 main.py` rather than selective sudo inside subprocess — avoids repeated password prompts in a demo setting
