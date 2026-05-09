# Phase 3: Visualization + Reporting - Context

**Gathered:** 2026-05-09
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Generate a networkx topology PNG that marks spoofed nodes red when an attack is detected, and produce a pandas CSV summary report at session end.

Requirements: VIZ-01, VIZ-02, VIZ-03, VIZ-04, LOG-01, LOG-02, LOG-03

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion. Use ROADMAP phase goal, success criteria, and codebase conventions.

Key decisions from ROADMAP:
- Bipartite layout (IP nodes left, MAC nodes right) — chosen over spring layout for deterministic rendering
- Visualization is off by default: --visualize flag required to enable PNG generation
- matplotlib.use("Agg") ALREADY locked in visualizer.py stub from Phase 1 — do NOT change backend
- topology.png generated via networkx + matplotlib Agg, saved to file (never plt.show())
- Spoofed nodes: red; legitimate nodes: green
- Regenerate topology.png on each new spoofing event
- Summary report: pandas DataFrame → attack_report.csv at session end (Ctrl+C or --report flag)
- --logfile <path> redirects JSONL log output from default arp_detector.log

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- arp_detector/visualizer.py — stub with matplotlib.use("Agg") locked at top; draw_topology() and save_final() stubs
- arp_detector/main.py — entry point with --visualize flag integration point
- arp_detector/logger.py — JSONLLogger with log file path, build_event() DET-05 events
- arp_detector/arp_table.py — ARPTable.get_all() returns DataFrame (ip index, mac/first_seen/last_seen cols)

### Established Patterns
- No plt.show() — Agg backend only, file output
- pandas .loc[] only (no .append())
- matplotlib called on-demand (not inside packet callback)
- Tests don't require root or network

### Integration Points
- visualizer.py: implement draw_topology(arp_table_df, spoofed_ips, output_path)
- main.py: call draw_topology() after conflict detected (if --visualize active)
- Add --report and --logfile args to parse_cli_args() in capture.py or main.py
- New: arp_detector/reporter.py — pandas-based summary (packets, attacks, MACs, timeline) → CSV

</code_context>

<specifics>
## Specific Ideas

- networkx bipartite graph: IP nodes on left, MAC nodes on right, edges = ARP associations
- Node colors: spoofed_ips set → red, others → green; use node_color list in nx.draw()
- draw_topology() regenerates full graph each call (stateless function)
- reporter.py: generate_report(events: list[dict], output_path="attack_report.csv") -> pd.DataFrame
- Events list from JSONLLogger (read log file) or passed directly from main loop
- Report columns: timestamp, victim_ip, attacker_mac, original_mac, attack_type (from DET-05)
- Add summary row or separate summary.txt: total packets, total attacks, unique attacker MACs

</specifics>

<deferred>
## Deferred Ideas

- Interactive graph visualization (requires $DISPLAY — out of scope)
- Real-time graph streaming (Phase 5 demo uses static PNG)

</deferred>
