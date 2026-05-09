# Phase 2: Detection Pipeline + Alerting - Context

**Gathered:** 2026-05-09
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Wire the Phase 1 capture skeleton into a full detection pipeline: arp-scan baseline seeding, conflict detection with gratuitous ARP filtering, rich console alerts, live ARP dashboard, JSONL logging, and graceful Ctrl+C shutdown.

Requirements: DET-02, DET-03, DET-04, DET-05, ALT-01, ALT-02, ALT-03, ALT-04

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — discuss phase was skipped per user setting. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

Key decisions from ROADMAP:
- Gratuitous ARP filter (psrc == pdst guard) must be applied before table lookup
- DET-05 field set (timestamp, attacker MAC, victim IP, original MAC, spoofed MAC, attack type) is the contract between detector and logger/alert — locked here
- Implement arp-scan baseline loader via subprocess (list-form args, no shell=True)
- rich console alerts: red Panel for conflicts, Live dashboard for ARP table + recent alerts
- JSONL logging: one JSON object per line, append mode, flush on each write
- Graceful shutdown: Ctrl+C → flush log → print session summary → exit 0

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- arp_detector/arp_table.py — ARPTable with update()/check_conflict()/get_all()
- arp_detector/detector.py — check_packet() with op=2 + gratuitous ARP filter
- arp_detector/capture.py — AsyncSniffer, Queue, root check, --iface CLI
- arp_detector/alerts.py — stub (needs full implementation)
- arp_detector/logger.py — stub (needs full implementation)
- arp_detector/visualizer.py — Agg stub (Phase 3 work)

### Established Patterns
- Packet dict contract: {src_ip, src_mac, dst_ip, op, timestamp}
- Conflict dict contract: {ip, known_mac, new_mac, timestamp}
- All subprocess calls: list-form args, capture_output=True, text=True, timeout=N
- No shell=True anywhere
- pandas .loc[] only (no .append())
- threading model: AsyncSniffer thread puts to Queue, main thread reads Queue and writes ARPTable

### Integration Points
- New: arp_detector/baseline.py — arp-scan subprocess wrapper that pre-populates ARPTable
- Implement: arp_detector/alerts.py — rich Panel alert + Live dashboard
- Implement: arp_detector/logger.py — JSONL append log
- New: arp_detector/main.py — top-level entry point wiring all components

</code_context>

<specifics>
## Specific Ideas

- arp-scan output format: "IP\tMAC\tVendor" lines, parse first two columns
- rich.Live with Table showing ARP entries + a Panel for recent alerts
- Session summary on Ctrl+C: packets_seen, attacks_detected, unique_attacker_macs
- JSONL log default path: arp_detector.log in cwd
- DET-05 event dict keys: timestamp, attacker_mac, victim_ip, original_mac, spoofed_mac, attack_type="ARP_SPOOFING"

</specifics>

<deferred>
## Deferred Ideas

- --verbose flag for per-packet output (Phase 5 / nice-to-have)
- Email/SMS alerting (out of scope per PROJECT.md)

</deferred>
