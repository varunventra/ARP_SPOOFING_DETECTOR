# Stack: ARP Spoofing Detector

**Project:** ARP Spoofing Detector (B.Tech AI Scripting Workshop)
**Researched:** 2026-05-05
**Note on confidence:** Web access unavailable during research. All findings are from training data (cutoff August 2025). APIs described are stable and have not changed across multiple major versions — confidence is assessed accordingly.

---

## Core Stack

| Library / Tool | Recommended Version | Role | Confidence |
|----------------|--------------------|----|------------|
| Python | 3.11 or 3.12 | Runtime | HIGH — both are LTS-class releases available in Ubuntu 22.04/24.04 |
| scapy | 2.5.x (latest 2.x) | Packet capture and ARP analysis | HIGH — API stable since 2.4, no breaking changes in ARP layer |
| pandas | 2.x (2.1+ preferred) | IP→MAC mapping table, conflict detection | HIGH — DataFrame API stable, 2.x is current series |
| networkx | 3.x | Network topology graph, node highlighting | MEDIUM — preferred over matplotlib for this use case (see below) |
| matplotlib | 3.8.x | Rendering backend for networkx graphs | HIGH — used as rendering layer, not graph logic |
| rich | 13.x | Colored console output, live tables, panels | HIGH — de facto standard for Python CLI output, 13.x stable |
| Python stdlib logging | stdlib | Persistent log file | HIGH — no external dependency needed |
| subprocess (stdlib) | stdlib | Shell tool integration (arp-scan, tcpdump) | HIGH — standard pattern |

---

## Python Libraries

### scapy

**Version:** 2.5.x (install: `pip install scapy`)
**Requires:** root/sudo for raw socket access — acceptable in lab/WSL environment.

**Key APIs for this project:**

```python
from scapy.all import sniff, ARP, Ether, get_if_list

# Capture ARP packets only — BPF filter runs in kernel, very efficient
sniff(
    filter="arp",           # BPF filter: kernel-level ARP-only capture
    prn=process_packet,     # callback called per packet
    store=False,            # don't accumulate in memory — critical for live capture
    iface="eth0"            # specify interface, or omit for default
)

# Inside process_packet(packet):
if packet.haslayer(ARP):
    arp = packet[ARP]
    op        = arp.op       # 1 = who-has (request), 2 = is-at (reply)
    src_ip    = arp.psrc     # sender protocol (IP) address
    src_mac   = arp.hwsrc    # sender hardware (MAC) address
    dst_ip    = arp.pdst     # target protocol (IP) address
    dst_mac   = arp.hwdst    # target hardware (MAC) address

# ARP spoofing detection logic: focus on op==2 (replies)
# A reply claiming an IP that already maps to a different MAC is the attack signature
```

**ARP layer field reference:**

| Field | Meaning | Spoofing relevance |
|-------|---------|-------------------|
| `op` | 1=request, 2=reply | Focus on replies (op=2) for spoofing detection |
| `psrc` | Sender IP | The IP being claimed |
| `hwsrc` | Sender MAC | The MAC making the claim |
| `pdst` | Target IP | Who the packet is addressed to |
| `hwdst` | Target MAC | Usually ff:ff:ff:ff:ff:ff for broadcasts |

**Filter syntax:**
- `filter="arp"` — captures all ARP (requests + replies). This is a BPF expression passed to libpcap.
- `filter="arp[6:2] == 2"` — replies only. More precise but `filter="arp"` with `op==2` check in Python is cleaner and easier to read.
- `iface` parameter: use `get_if_list()` to enumerate available interfaces; in WSL this is typically `eth0`.

**Gotchas:**
1. `store=False` is mandatory for live capture. Without it, scapy accumulates every packet in memory — the process will OOM during a long-running demo.
2. WSL2 network interface name may be `eth0` but can vary. Add an `--iface` CLI argument so the grader can specify it.
3. scapy's `sniff()` is blocking. Run it in a thread or use `AsyncSniffer` if the main thread needs to stay responsive (e.g., for `Ctrl+C` handling).
4. On WSL, `/proc/net/arp` is readable as the system ARP table — useful for building the initial baseline before sniffing starts.
5. Gratuitous ARP (a host announcing its own IP/MAC) is legitimate network behavior. Your detector must distinguish gratuitous ARP from spoofed ARP. The tell: a gratuitous ARP has `psrc == pdst` or is sent to the broadcast MAC. Flag but don't treat as definitive attack without a conflicting mapping.

**AsyncSniffer pattern (recommended for clean Ctrl+C):**

```python
from scapy.all import AsyncSniffer

sniffer = AsyncSniffer(filter="arp", prn=process_packet, store=False)
sniffer.start()
try:
    sniffer.join()  # blocks until stopped
except KeyboardInterrupt:
    sniffer.stop()
```

---

### pandas

**Version:** 2.1+ (install: `pip install pandas`)

**Role:** Maintain the ground-truth IP→MAC mapping table. Detect when a new ARP reply claims an IP that already maps to a different MAC.

**Key usage patterns:**

```python
import pandas as pd

# Initialize the ARP table as a DataFrame
arp_table = pd.DataFrame(columns=["ip", "mac", "first_seen", "last_seen", "count"])
arp_table = arp_table.set_index("ip")

# On each ARP reply: check for conflict
def check_and_update(src_ip, src_mac, timestamp):
    if src_ip in arp_table.index:
        known_mac = arp_table.at[src_ip, "mac"]
        if known_mac != src_mac:
            # CONFLICT DETECTED — this is the spoofing signature
            return "SPOOFING_DETECTED", known_mac
        else:
            # Same MAC, just update timestamp/count
            arp_table.at[src_ip, "last_seen"] = timestamp
            arp_table.at[src_ip, "count"] += 1
    else:
        # New IP→MAC mapping, record it
        arp_table.loc[src_ip] = [src_mac, timestamp, timestamp, 1]
    return "OK", None

# Periodic display: use arp_table.to_string() or pass to rich Table
print(arp_table.to_string())

# Export to CSV for the log/report
arp_table.to_csv("arp_baseline.csv")

# Load baseline (from arp-scan output parsed earlier)
baseline = pd.read_csv("baseline.csv", index_col="ip")
```

**Why DataFrame over a plain dict:** The PRD and course requirements specify pandas. Beyond compliance, `.to_csv()` gives free structured report export, and pandas makes it trivial to add columns (attack_count, vendor OUI lookup, etc.) without refactoring. For this scale (single subnet, <254 hosts), there is zero performance concern.

**Pandas 2.x note:** In pandas 2.0+, `DataFrame.append()` was removed. Use `pd.concat()` or `.loc[]` assignment instead. Do not use the old `.append()` pattern found in pre-2020 scapy tutorials.

---

### matplotlib vs. networkx — Recommendation

**Use networkx for graph logic, matplotlib as the rendering backend.**

These two libraries are not competitors for this use case — they are complementary:

| Concern | networkx | matplotlib |
|---------|---------|-----------|
| Representing nodes/edges (hosts/connections) | Native graph data structure | Not applicable |
| Layout algorithms (spring, circular, hierarchical) | Built-in (spring_layout, kamada_kawai_layout) | Not applicable |
| Highlighting spoofed nodes (red color, size change) | `nx.draw()` with per-node color list | Provides the Axes canvas |
| Rendering to screen / saving PNG | Delegates to matplotlib | Handles rendering |
| Showing IP/MAC labels on nodes | `nx.draw_networkx_labels()` | Not applicable |

**Verdict:** networkx owns the graph — nodes, edges, layout. matplotlib provides `plt.show()` and `plt.savefig()`. You always need both installed.

**Key APIs:**

```python
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

G = nx.Graph()

# Add nodes (hosts) and edges (observed ARP communication)
G.add_node("192.168.1.1", mac="aa:bb:cc:dd:ee:ff", spoofed=False)
G.add_node("192.168.1.100", mac="11:22:33:44:55:66", spoofed=True)
G.add_edge("192.168.1.1", "192.168.1.100")

# Color spoofed nodes red, normal nodes green
colors = ["red" if G.nodes[n].get("spoofed") else "lightgreen" for n in G.nodes()]

pos = nx.spring_layout(G, seed=42)  # seed for reproducible layout

fig, ax = plt.subplots(figsize=(10, 8))
nx.draw(G, pos, ax=ax, with_labels=True, node_color=colors,
        node_size=800, font_size=8)
plt.title("ARP Network Topology — Red = Spoofed")
plt.savefig("topology.png", dpi=150, bbox_inches="tight")
plt.show()
```

**For a live terminal demo:** do not call `plt.show()` inside the sniff loop — it blocks. Update the graph periodically (e.g., on each detected attack) and call `plt.savefig()` + `plt.pause(0.1)` for a non-blocking refresh, or save to PNG and display it separately.

**networkx version:** 3.x (install: `pip install networkx`)
**matplotlib version:** 3.8.x (install: `pip install matplotlib`)

---

### Supporting Libraries

#### rich (colored console output)

**Version:** 13.x (install: `pip install rich`)
**Use rich over colorama.** Rationale below.

**Key APIs for this project:**

```python
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.panel import Panel
from rich.live import Live

console = Console()

# Alert for detected spoofing
console.print(
    f"[bold red][ALERT] ARP SPOOFING DETECTED[/bold red]\n"
    f"  IP: {src_ip}\n"
    f"  Known MAC: {known_mac}\n"
    f"  Claimed MAC: {src_mac}",
    style="on dark_red"
)

# Live-updating ARP table using rich.Live
table = Table(title="ARP Table")
table.add_column("IP", style="cyan")
table.add_column("MAC", style="green")
table.add_column("Status", style="bold")

with Live(table, refresh_per_second=2) as live:
    # update table inside sniff loop
    ...
```

**Why rich over colorama:**
- colorama only adds ANSI escape codes — you still write `"\033[31mRED\033[0m"` manually.
- rich provides `Table`, `Panel`, `Live` (live-refreshing display), `Progress`, and `Syntax` — all relevant to a live monitoring tool.
- rich's `Live` context manager enables a real-time updating ARP table in the terminal without clearing/reprinting manually.
- For a graded demo, rich's output looks professional and demonstrates awareness of the modern Python ecosystem.
- Both are trivially installable with pip. No reason to use the inferior option.

#### logging (stdlib — persistent log file)

No external library needed. Use Python's stdlib `logging` module:

```python
import logging

logging.basicConfig(
    filename="arp_detector.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Log normal events
logging.info(f"New mapping: {src_ip} -> {src_mac}")

# Log attack events
logging.warning(f"SPOOFING DETECTED: {src_ip} claimed by {src_mac}, known {known_mac}")
```

Write to console via rich AND to file via logging simultaneously. Do not use rich for file output — plain text logs are more useful for post-analysis.

#### argparse (stdlib — CLI argument parsing)

```python
import argparse

parser = argparse.ArgumentParser(description="ARP Spoofing Detector")
parser.add_argument("--iface", default="eth0", help="Network interface to sniff")
parser.add_argument("--log", default="arp_detector.log", help="Log file path")
parser.add_argument("--baseline", help="CSV file with known IP→MAC mappings")
args = parser.parse_args()
```

This is important for the graded demo — the instructor may need to specify an interface.

---

## Shell Tools

### arp-scan

**Purpose:** Active network scan to build the initial IP→MAC baseline before passive sniffing begins.

**Installation (WSL Ubuntu):**
```bash
sudo apt-get install arp-scan
```

**Python integration:**

```python
import subprocess
import re

def run_arp_scan(iface="eth0"):
    result = subprocess.run(
        ["sudo", "arp-scan", "--interface", iface, "--localnet"],
        capture_output=True, text=True, timeout=30
    )
    # Parse output: lines like "192.168.1.1\taa:bb:cc:dd:ee:ff\tVendor Name"
    mappings = {}
    for line in result.stdout.splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line)
        if match:
            ip, mac = match.group(1), match.group(2)
            mappings[ip] = mac
    return mappings
```

**awk equivalent for shell script demo:**
```bash
sudo arp-scan --interface eth0 --localnet | awk '/^[0-9]/ {print $1, $2}'
```

**Why subprocess over a pure shell script:** The course requires demonstrating Python + shell integration. Using `subprocess.run()` calls the shell tool from Python — this satisfies the "shell scripting integration" requirement while keeping the logic in Python where pandas can use the result.

### ip arp / arp command

Fallback to read the kernel ARP cache without running an active scan:

```bash
ip neigh show   # modern iproute2 — preferred
arp -n          # legacy, but universally available
```

```python
def read_kernel_arp_table():
    result = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True)
    mappings = {}
    for line in result.stdout.splitlines():
        # Format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        parts = line.split()
        if "lladdr" in parts:
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1]
            mappings[ip] = mac
    return mappings
```

### tcpdump

**Purpose:** Packet capture fallback and shell script demonstration. tcpdump can capture ARP traffic and write to a pcap file that scapy can read offline.

**Direct use (shell script):**
```bash
# Capture ARP packets to file (shell script component of the demo)
sudo tcpdump -i eth0 -w arp_capture.pcap arp &
TCPDUMP_PID=$!
# ... let it run ...
kill $TCPDUMP_PID
```

**Python integration — read pcap offline:**
```python
from scapy.all import rdpcap
packets = rdpcap("arp_capture.pcap")
for pkt in packets:
    if pkt.haslayer(ARP):
        process_packet(pkt)
```

**tcpdump as subprocess from Python:**
```python
proc = subprocess.Popen(
    ["sudo", "tcpdump", "-i", "eth0", "-l", "-n", "arp"],
    stdout=subprocess.PIPE, text=True
)
for line in proc.stdout:
    # parse tcpdump text output line by line
    print(line.strip())
```

**When to use tcpdump vs. scapy sniff():** Use scapy `sniff()` as the primary capture mechanism (cleaner, Python-native parsing). Use tcpdump in the shell script component of the demo to satisfy the "shell tools" course requirement. They can run simultaneously — tcpdump writes to pcap, scapy reads live from the wire.

### awk / grep (log analysis)

**Purpose:** Demonstrate shell scripting competency by analyzing the log file the Python tool produces.

```bash
# Extract all SPOOFING alerts from log
grep "SPOOFING DETECTED" arp_detector.log

# Count attacks per IP
grep "SPOOFING DETECTED" arp_detector.log | awk '{print $5}' | sort | uniq -c | sort -rn

# Show last 20 log entries
tail -n 20 arp_detector.log

# Filter by date
awk '/2026-05-05/ && /SPOOFING/' arp_detector.log
```

**Design implication:** Write the log file in a structured, grep-friendly format. The `logging` format `"%(asctime)s [%(levelname)s] %(message)s"` is already grep-friendly. Include key fields (IP, MAC, attack type) as labeled tokens in the log message so awk field-splitting works cleanly.

---

## What NOT to Use

| Candidate | Avoid Because |
|-----------|--------------|
| **colorama** | Inferior to rich for this use case. Only provides ANSI color codes; no tables, no live display, no panels. Rich does everything colorama does plus much more. No reason to use colorama if rich is installed. |
| **dpkt / pyshark** | dpkt has a harder API and less documentation than scapy for ARP-specific work. pyshark is a Wireshark wrapper that requires tshark installed — adds a heavyweight dependency. scapy is the correct choice and is course-specified. |
| **SQLite / any DB** | PRD explicitly defers database persistence. Flat log file is sufficient. Adding SQLite creates schema management overhead with zero demo benefit. |
| **asyncio for packet processing** | Unnecessary complexity. scapy's `AsyncSniffer` handles the threading concern cleanly. Full asyncio architecture is overkill for a single-subnet LAN demo. |
| **psutil for network stats** | Not needed — scapy provides all packet-level data. psutil is for process/system monitoring, not packet inspection. |
| **arpwatch (Python import)** | arpwatch is a system daemon, not a Python library. It is useful as a reference/comparison but your tool replaces it. Don't attempt to wrap it. |
| **Scapy's send() / sendp()** | Do not send packets in the detector — this is detection only. Using send() accidentally on a real network is disruptive and a security concern. |
| **matplotlib graph inside sniff loop** | Calling `plt.show()` inside the packet callback blocks the callback thread. Update the graph on a timer or on-demand only. |

---

## Key Integration Points

### 1. Startup sequence

```
1. parse args (argparse)
2. run_arp_scan() or read_kernel_arp_table() → populate pandas DataFrame as baseline
3. display baseline table via rich
4. start AsyncSniffer(filter="arp", prn=process_packet, store=False)
5. main loop: wait for KeyboardInterrupt, periodically refresh rich display
6. on exit: save final arp_table to CSV, close log, save topology graph PNG
```

### 2. Python → shell tool call pattern

```python
# Always use: capture_output=True, text=True, timeout=N
result = subprocess.run(
    ["sudo", "arp-scan", "--interface", args.iface, "--localnet"],
    capture_output=True, text=True, timeout=30
)
if result.returncode != 0:
    console.print(f"[yellow]arp-scan failed: {result.stderr}[/yellow]")
    # fallback to ip neigh show
```

Use a list of strings (not a shell string) for `subprocess.run()` arguments — avoids shell injection and handles paths with spaces correctly.

### 3. Shell script component (separate .sh file for demo)

The course requires demonstrating shell scripting. Write a companion `analyze_log.sh`:

```bash
#!/bin/bash
# analyze_log.sh — Post-capture log analysis
LOG="${1:-arp_detector.log}"

echo "=== ARP Spoofing Summary ==="
echo "Total events: $(wc -l < "$LOG")"
echo "Attack events: $(grep -c "SPOOFING" "$LOG")"
echo ""
echo "=== Attacks by IP ==="
grep "SPOOFING DETECTED" "$LOG" | grep -oP 'IP: \K[\d.]+' | sort | uniq -c | sort -rn
echo ""
echo "=== Timeline ==="
grep "SPOOFING" "$LOG" | awk '{print $1, $2}' | head -20
```

Call this from Python at the end of the session or as a standalone demo step:
```python
subprocess.run(["bash", "analyze_log.sh", args.log])
```

### 4. Threading model

```
Main thread:    rich Live display loop + KeyboardInterrupt handler
Sniffer thread: AsyncSniffer (scapy manages this internally)
```

Shared state (the pandas DataFrame and the rich Table) must be protected with `threading.Lock()` since the sniffer callback runs in the sniffer thread.

```python
import threading
lock = threading.Lock()

def process_packet(packet):
    with lock:
        # safe to read/write arp_table and update rich table here
```

---

## Installation Summary

```bash
# WSL Ubuntu — system dependencies
sudo apt-get update
sudo apt-get install -y python3-pip arp-scan tcpdump

# Python packages
pip install scapy pandas matplotlib networkx rich

# Verify scapy can access raw sockets
sudo python3 -c "from scapy.all import sniff; print('scapy OK')"
```

**Minimum Python version:** 3.9 (f-strings, `subprocess.run(capture_output=True)`, walrus operator all available). Python 3.11 recommended — available in Ubuntu 22.04+ and meaningfully faster than 3.9 for CPU-bound work.

---

## Confidence Summary

| Area | Confidence | Basis |
|------|-----------|-------|
| scapy sniff() / ARP layer API | HIGH | Stable since scapy 2.4; field names (psrc, hwsrc, op) unchanged across all 2.x versions |
| pandas 2.x DataFrame patterns | HIGH | 2.x API well-established; `.append()` removal is the one known breaking change vs. old tutorials |
| networkx + matplotlib combination | HIGH | Standard pattern, unchanged API for nx.draw() for several major versions |
| rich 13.x Console/Table/Live | HIGH | Rich 13.x has been stable; Console, Table, Live APIs unchanged |
| subprocess shell integration patterns | HIGH | stdlib, unchanged |
| arp-scan output format parsing | MEDIUM | Output format has been stable but not verified against latest Ubuntu package version |
| Exact current package versions (2.5.x, 2.1+, etc.) | MEDIUM | Based on training data to August 2025; web access unavailable to confirm latest patch versions |
| AsyncSniffer thread safety with pandas | MEDIUM | Pattern is correct but threading + scapy callbacks have WSL-specific edge cases not fully characterized |
