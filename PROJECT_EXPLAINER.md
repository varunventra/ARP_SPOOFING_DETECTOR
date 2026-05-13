# ARP Spoofing Detector — Project Explainer

## What is ARP Spoofing?

Every device on a network has an IP address and a MAC address. ARP is the protocol that maps one to the other. The problem — ARP has no authentication. Anyone can send a fake ARP reply saying "I am the gateway" and redirect all traffic through their machine. That's ARP spoofing — a Man-in-the-Middle attack.

**Our tool detects it the moment it happens.**

---

## How It Works (30 seconds)

1. On startup, runs `arp-scan` to learn all real IP→MAC mappings (the baseline)
2. Listens to live ARP traffic using scapy
3. Every ARP reply gets checked — if an IP claims a different MAC than what we know, that's an attack
4. Fires a red alert instantly, logs it, draws a topology map

---

## Components

| What | File | One line |
|------|------|----------|
| ARP table | `arp_table.py` | Pandas DataFrame storing IP→MAC mappings |
| Detection | `detector.py` | Checks if incoming MAC conflicts with known MAC |
| Capture | `capture.py` | Scapy AsyncSniffer listening on the network interface |
| Baseline | `baseline.py` | Runs arp-scan at startup to pre-fill the table |
| Alerts | `alerts.py` | Prints red rich panel on detection |
| Visualization | `visualizer.py` | networkx topology PNG, spoofed nodes in red |
| Logger | `logger.py` | Writes one JSON line per attack to arp_detector.log |
| Reporter | `reporter.py` | Exports pandas CSV summary on shutdown |
| Shell scripts | `scripts/` | arp-scan, tcpdump, grep, awk — course shell tools |
| Attack sim | `simulate_attack.py` | Sends forged ARP packets via scapy for demo |

---

---

# Team Member Sections

---

## Member 1 — Detection Logic
**Files:** `arp_table.py`, `detector.py`

> "The ARP table is a pandas DataFrame — rows are IPs, columns are MAC and timestamps. When a packet comes in, detector.py checks it against the table with three rules: ignore ARP requests, ignore gratuitous ARP (devices announcing themselves on boot — not an attack), and if the IP exists with a different MAC, that's a conflict. One function, three rules, returns the attack record."

**If asked why gratuitous ARP is filtered:**
> "Without it, every device that reboots would trigger a false alarm. Gratuitous ARP is normal behaviour."

---

## Member 2 — Capture and Baseline
**Files:** `capture.py`, `baseline.py`, `scripts/baseline_scan.sh`

> "capture.py uses scapy's AsyncSniffer — it runs in a background thread and pushes packets onto a Queue. The main thread reads from that Queue and does all the processing. This means no thread locks needed. Before the sniffer starts, baseline.py calls arp-scan via subprocess to learn every real IP-MAC pair on the network. baseline_scan.sh is the standalone shell version — arp-scan piped through awk to strip headers and output clean IP-tab-MAC lines."

**If asked why root is needed:**
> "Raw socket access for packet capture is a privileged operation on Linux — same reason tcpdump needs sudo."

---

## Member 3 — Alerts and Visualization
**Files:** `alerts.py`, `visualizer.py`, `main.py`

> "alerts.py formats a red panel using the rich library — shows victim IP, attacker MAC, real MAC, and timestamp. main.py is the entry point that wires everything together: root check, baseline, sniffer, live dashboard loop, graceful Ctrl+C shutdown. visualizer.py builds a bipartite graph with networkx — IPs on the left, MACs on the right. Spoofed nodes go red. It saves to topology.png using matplotlib's Agg backend so it works in a headless terminal with no display."

**If asked what bipartite means:**
> "Two groups of nodes with edges only between groups, not within — IPs connect to MACs, IPs don't connect to other IPs."

---

## Member 4 — Logging, Reporting, Shell Tools
**Files:** `logger.py`, `reporter.py`, `scripts/analyze_log.sh`, `scripts/capture_raw.sh`, `simulate_attack.py`

> "logger.py writes one JSON object per line to arp_detector.log — JSONL format. Flushed immediately on every write so you can tail -f it live. reporter.py generates a pandas CSV at shutdown — that's our pandas data analysis requirement. analyze_log.sh uses grep and awk to count attacks, list attacker MACs, and print a timeline with no Python. capture_raw.sh uses tcpdump to record ARP traffic to a pcap. simulate_attack.py uses scapy's sendp() to send forged ARP replies — that's how we trigger the live demo."

**If asked why JSONL not a database:**
> "The spec says no database. JSONL is structured, appendable, and readable by both Python and shell tools with just grep."
