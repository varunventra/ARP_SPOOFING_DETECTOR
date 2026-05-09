# ARP Spoofing Detector

## What This Is

A Python-based command-line network security tool that captures ARP traffic in real time, detects IP-MAC mapping conflicts that indicate ARP spoofing attacks, alerts the operator via colored console output and a persistent log file, and visualizes network topology changes. Built for a B.Tech AI Scripting Workshop course project, targeting a Linux/WSL environment.

## Core Value

Real-time ARP spoofing detection with immediate console alerts — the tool must catch and surface an active ARP spoofing attack while it's happening, not after.

## Requirements

### Validated

- [x] Capture ARP packets via scapy AsyncSniffer with store=False — validated in Phase 1 (CAP-01)
- [x] In-memory IP→MAC pandas DataFrame with conflict detection — validated in Phase 1 (DET-01)
- [x] Root privilege check at startup (os.geteuid) — validated in Phase 1 (CAP-03)
- [x] --iface CLI arg + auto-detect via get_if_list() — validated in Phase 1 (CAP-02)
- [x] Filter to ARP op=2 replies only — validated in Phase 1 (CAP-04)

### Active

- [ ] Capture and analyze live ARP packets using scapy
- [ ] Detect duplicate/conflicting IP-MAC mappings (classic ARP spoofing signature)
- [ ] Alert operator with colored console output + persistent log file
- [ ] Visualize network topology and highlight spoofed nodes
- [ ] Generate structured attack log / report (IP, MAC, timestamp, attack type)
- [ ] Support baseline ARP table from arp-scan / ip arp for comparison
- [ ] Shell script integration (arp-scan, tcpdump, awk/grep for log analysis)

### Out of Scope

- Email/SMS alerting — not required for course demo scope
- iptables automatic blocking — PRD marks this "advanced", defer to v2
- Web/GUI dashboard — CLI-only per requirements
- Windows-native support — WSL is the target, not native Win32 APIs
- Database persistence — flat log file is sufficient for course demo

## Context

- **Course:** B.Tech 4th semester AI — Scripting Workshop project
- **Evaluator:** Instructor evaluating in a lab/VM/WSL environment
- **Platform:** Windows + WSL (Ubuntu) — Python scripts run inside WSL, shell tools available natively in WSL
- **Grading focus:** Demonstrates working integration of Python (scapy, pandas, matplotlib) + shell tools (arp-scan, tcpdump, awk/grep)
- **Network setup:** Single subnet LAN / VM network — no need to handle multi-hop or VPN scenarios
- **Key constraint:** Must demonstrate both Python scripting AND shell scripting competency (course requirement)

## Constraints

- **Tech Stack:** Python 3.x + scapy + pandas + matplotlib/networkx — no swapping to alternatives
- **Shell Tools:** arp-scan, tcpdump, awk, grep must be used (course requirement)
- **Platform:** Linux/WSL — not Windows-native
- **Privileges:** Packet capture requires root/sudo — acceptable for lab environment
- **Scope:** Graded demo, not production deployment — reliability under adversarial load not required

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| CLI with live output (not GUI) | PRD specifies CLI; course scope doesn't warrant web stack | — Pending |
| Console + log file alerts (not email) | Sufficient for lab demo; email adds infra complexity | — Pending |
| WSL as target platform | Linux tools (arp-scan, arpwatch) unavailable on native Windows | — Pending |
| iptables blocking deferred | PRD marks it "advanced"; out of scope for v1 demo | — Pending |

---

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-09 — Phase 1 complete (Core Data Layer + Capture Skeleton)*
