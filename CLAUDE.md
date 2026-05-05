<!-- GSD:project-start source:PROJECT.md -->
## Project

**ARP Spoofing Detector**

A Python-based command-line network security tool that captures ARP traffic in real time, detects IP-MAC mapping conflicts that indicate ARP spoofing attacks, alerts the operator via colored console output and a persistent log file, and visualizes network topology changes. Built for a B.Tech AI Scripting Workshop course project, targeting a Linux/WSL environment.

**Core Value:** Real-time ARP spoofing detection with immediate console alerts — the tool must catch and surface an active ARP spoofing attack while it's happening, not after.

### Constraints

- **Tech Stack:** Python 3.x + scapy + pandas + matplotlib/networkx — no swapping to alternatives
- **Shell Tools:** arp-scan, tcpdump, awk, grep must be used (course requirement)
- **Platform:** Linux/WSL — not Windows-native
- **Privileges:** Packet capture requires root/sudo — acceptable for lab environment
- **Scope:** Graded demo, not production deployment — reliability under adversarial load not required
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

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
## Python Libraries
### scapy
# Capture ARP packets only — BPF filter runs in kernel, very efficient
# Inside process_packet(packet):
# ARP spoofing detection logic: focus on op==2 (replies)
# A reply claiming an IP that already maps to a different MAC is the attack signature
| Field | Meaning | Spoofing relevance |
|-------|---------|-------------------|
| `op` | 1=request, 2=reply | Focus on replies (op=2) for spoofing detection |
| `psrc` | Sender IP | The IP being claimed |
| `hwsrc` | Sender MAC | The MAC making the claim |
| `pdst` | Target IP | Who the packet is addressed to |
| `hwdst` | Target MAC | Usually ff:ff:ff:ff:ff:ff for broadcasts |
- `filter="arp"` — captures all ARP (requests + replies). This is a BPF expression passed to libpcap.
- `filter="arp[6:2] == 2"` — replies only. More precise but `filter="arp"` with `op==2` check in Python is cleaner and easier to read.
- `iface` parameter: use `get_if_list()` to enumerate available interfaces; in WSL this is typically `eth0`.
### pandas
# Initialize the ARP table as a DataFrame
# On each ARP reply: check for conflict
# Periodic display: use arp_table.to_string() or pass to rich Table
# Export to CSV for the log/report
# Load baseline (from arp-scan output parsed earlier)
### matplotlib vs. networkx — Recommendation
| Concern | networkx | matplotlib |
|---------|---------|-----------|
| Representing nodes/edges (hosts/connections) | Native graph data structure | Not applicable |
| Layout algorithms (spring, circular, hierarchical) | Built-in (spring_layout, kamada_kawai_layout) | Not applicable |
| Highlighting spoofed nodes (red color, size change) | `nx.draw()` with per-node color list | Provides the Axes canvas |
| Rendering to screen / saving PNG | Delegates to matplotlib | Handles rendering |
| Showing IP/MAC labels on nodes | `nx.draw_networkx_labels()` | Not applicable |
# Add nodes (hosts) and edges (observed ARP communication)
# Color spoofed nodes red, normal nodes green
### Supporting Libraries
#### rich (colored console output)
# Alert for detected spoofing
# Live-updating ARP table using rich.Live
- colorama only adds ANSI escape codes — you still write `"\033[31mRED\033[0m"` manually.
- rich provides `Table`, `Panel`, `Live` (live-refreshing display), `Progress`, and `Syntax` — all relevant to a live monitoring tool.
- rich's `Live` context manager enables a real-time updating ARP table in the terminal without clearing/reprinting manually.
- For a graded demo, rich's output looks professional and demonstrates awareness of the modern Python ecosystem.
- Both are trivially installable with pip. No reason to use the inferior option.
#### logging (stdlib — persistent log file)
# Log normal events
# Log attack events
#### argparse (stdlib — CLI argument parsing)
## Shell Tools
### arp-scan
### ip arp / arp command
### tcpdump
# Capture ARP packets to file (shell script component of the demo)
# ... let it run ...
### awk / grep (log analysis)
# Extract all SPOOFING alerts from log
# Count attacks per IP
# Show last 20 log entries
# Filter by date
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
## Key Integration Points
### 1. Startup sequence
### 2. Python → shell tool call pattern
# Always use: capture_output=True, text=True, timeout=N
### 3. Shell script component (separate .sh file for demo)
#!/bin/bash
# analyze_log.sh — Post-capture log analysis
### 4. Threading model
## Installation Summary
# WSL Ubuntu — system dependencies
# Python packages
# Verify scapy can access raw sockets
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
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
