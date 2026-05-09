---
phase: 02-detection-pipeline-alerting
plan: "04"
subsystem: cli
tags: [scapy, pandas, rich, asyncsniffer, queue, live-dashboard, arp-spoofing]

requires:
  - phase: 02-01
    provides: load_baseline() — seeds ARPTable from arp-scan before sniffing
  - phase: 02-02
    provides: JSONLLogger + build_event() — event persistence to JSONL log
  - phase: 02-03
    provides: format_alert_panel() — rich.Panel alert builder
  - phase: 01
    provides: ARPTable, check_packet(), check_root(), parse_cli_args(), start_capture()

provides:
  - arp_detector/main.py — top-level entry point wiring all Phase 2 components
  - build_layout() — rich.Layout with arp_table + alerts split
  - build_arp_table_renderable(df) — rich.Panel wrapping a rich.Table of known hosts
  - build_alerts_renderable(recent_alerts) — rich.Panel showing last 5 alert strings
  - Full detection loop: Queue -> check_packet -> build_event -> log_event + alert
  - Graceful Ctrl+C shutdown: sniffer.stop(), logger.close(), session summary

affects:
  - phase: 03-visualization-reporting
  - phase: 05-integration-demo

tech-stack:
  added: []
  patterns:
    - "check_root() first before any other operation in main()"
    - "load_baseline() before start_capture() (seed table before sniffing)"
    - "AsyncSniffer callback ONLY enqueues dicts — main thread sole DataFrame writer"
    - "Queue.get(timeout=0.1) prevents blocking; dashboard refreshes on Empty"
    - "live.console.print(panel) inside Live context — never Console().print()"
    - "build_* renderable functions are pure (no side effects) — testable without terminal"

key-files:
  created:
    - arp_detector/main.py
    - tests/test_main.py
  modified: []

key-decisions:
  - "live.console.print() used for all conflict alerts inside Live context (avoids display corruption)"
  - "build_arp_table_renderable/build_alerts_renderable are pure functions — enables unit testing without a terminal"
  - "WSL smoke test (Task 3 checkpoint) auto-approved and deferred to Phase 5 demo day"

patterns-established:
  - "TDD flow: RED (ImportError) -> GREEN (17 passing) on all main.py exports"
  - "Renderable builders take pure data (DataFrame, list[str]) and return rich objects — decoupled from loop state"

requirements-completed: [DET-03, DET-04, ALT-02, ALT-04]

duration: 10min
completed: 2026-05-09
---

# Phase 2 Plan 04: main.py — Full Detection Pipeline Entry Point Summary

**rich.Live dashboard with ARP table + alert panels wired to AsyncSniffer Queue, conflict detection loop, and graceful Ctrl+C shutdown with session summary**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-05-09T08:22:15Z
- **Completed:** 2026-05-09T08:32:00Z
- **Tasks:** 2 executed + 1 auto-approved checkpoint
- **Files modified:** 2 (arp_detector/main.py, tests/test_main.py)

## Accomplishments

- `arp_detector/main.py` wires all Phase 2 components into a runnable entry point
- TDD cycle: 17 failing tests (RED) → 17 passing tests (GREEN), 122 total green (no regressions)
- Threading contract enforced: `Queue.get(timeout=0.1)`, `live.console.print()`, `check_root()` first, `load_baseline()` before `start_capture()`
- Session summary on Ctrl+C: packets_seen, attacks_detected, unique attacker MACs

## Task Commits

Each task was committed atomically:

1. **Task 1: Write failing tests for main.py (RED)** - `a6990fa` (test)
2. **Task 2: Implement main.py to make tests pass (GREEN)** - `89e5be6` (feat)
3. **Task 3: Smoke-test checkpoint** - Auto-approved (deferred to Phase 5 demo day)

**Plan metadata:** (docs commit below)

_Note: TDD tasks have two commits — test (RED) then feat (GREEN)._

## Files Created/Modified

- `arp_detector/main.py` — Top-level entry point: startup sequence, Live dashboard, main loop, shutdown
- `tests/test_main.py` — 17 unit tests for renderables, layout, and conflict-path wiring (no root/network required)

## Decisions Made

- `live.console.print()` used inside the `with Live(...)` context for conflict alert panels. Using `Console().print()` separately would corrupt the Live display — this is a hard constraint documented in CLAUDE.md.
- `build_arp_table_renderable` and `build_alerts_renderable` are pure functions (take DataFrame and list, return Panel) — this enables full unit testing without a terminal or Live context.
- WSL smoke test checkpoint auto-approved per execution context instructions; deferred to Phase 5 demo day when a live WSL environment is available.

## Deviations from Plan

None — plan executed exactly as written.

## Checkpoint: Task 3 Auto-Approved

**Type:** checkpoint:human-verify  
**Reason for auto-approval:** Execution context specified "AUTO-APPROVE the checkpoint: treat it as approved, note it in SUMMARY.md as deferred to demo day."  
**What was deferred:** Live WSL smoke test (`sudo python3 -m arp_detector.main --iface eth0`) — requires root and a WSL terminal with arp-scan installed.  
**Deferred to:** Phase 5 (Integration + Demo Prep) — pre-demo checklist in research/SUMMARY.md covers this exact verification step.  
**Automated tests that verify equivalent behavior:** All 17 tests in `tests/test_main.py` pass, covering all exported functions and the conflict-path wiring logic.

## Issues Encountered

None.

## Known Stubs

None — all data paths are wired. The "No alerts yet" placeholder text in `build_alerts_renderable` is intentional UI copy for the empty-list case, not a stub.

## Next Phase Readiness

- Phase 2 complete: full pipeline from baseline seed → packet capture → conflict detection → alert + log → session summary
- Phase 3 (Visualization + Reporting) can import `ARPTable.get_all()` and `JSONLLogger` as needed
- Phase 5 demo prep: run `sudo python3 -m arp_detector.main --iface <iface>` in WSL to validate live pipeline

---
*Phase: 02-detection-pipeline-alerting*
*Completed: 2026-05-09*
