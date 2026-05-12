# Phase 4: Shell Integration - Context

**Gathered:** 2026-05-12
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Three shell scripts (baseline_scan.sh, analyze_log.sh, capture_raw.sh) and a verified subprocess wrapper pattern in Python satisfy the course shell-scripting requirement.

Requirements: SHL-01, SHL-02, SHL-03, SHL-04

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All choices at Claude's discretion per ROADMAP and CLAUDE.md constraints.

Key constraints:
- shell=True PROHIBITED in all subprocess calls (security + testability constraint — locked in Phase 1)
- All subprocess calls: list-form args, capture_output=True, text=True, timeout=N
- Scripts must use arp-scan, tcpdump, awk, grep (course requirement)
- Scripts go in scripts/ directory
- baseline_scan.sh: runs arp-scan --localnet, formats output as IP<TAB>MAC lines
- analyze_log.sh: accepts arp_detector.log, prints human-readable summary using awk + grep only
- capture_raw.sh: starts tcpdump -n arp, writes to .pcap file (path configurable via arg)
- SHL-04: all Python subprocess calls already use list-form (verified in Phases 1-2); this phase verifies compliance and adds any missing wrappers

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- arp_detector/baseline.py — existing subprocess.run pattern (list-form, timeout=30, FileNotFoundError guard)
- arp_detector/capture.py — parse_cli_args() to add --capture-script arg if needed
- tests/ — mock-based subprocess testing pattern established in test_baseline.py

### Established Patterns
- subprocess.run(["tool", "arg"], capture_output=True, text=True, timeout=N) — no shell=True
- FileNotFoundError catch + warning print pattern
- Tests mock subprocess.run to avoid requiring root or live tools

### Integration Points
- scripts/baseline_scan.sh — called by baseline.py (or manually before demo)
- scripts/analyze_log.sh — post-demo log analysis tool
- scripts/capture_raw.sh — optional tcpdump capture for demo recording

</code_context>

<specifics>
## Specific Ideas

- baseline_scan.sh output format: one line per host, "IP\tMAC" (tab-separated), skip header/footer
- analyze_log.sh: use grep to filter JSONL lines, awk to count attacks and extract fields, print summary
- capture_raw.sh: accept $1 as output .pcap path, default to "capture.pcap" if not provided
- Test shell scripts against fixture files (saved output, not live tools)

</specifics>

<deferred>
## Deferred Ideas

- iptables integration (out of scope per PROJECT.md)
- Automated email alerts (out of scope)

</deferred>
