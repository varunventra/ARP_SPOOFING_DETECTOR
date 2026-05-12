---
phase: 03-visualization-reporting
plan: "03"
subsystem: cli
tags: [argparse, draw_topology, generate_report, jsonl-logger, visualization, reporting]

# Dependency graph
requires:
  - phase: 03-visualization-reporting
    provides: draw_topology() from visualizer.py and generate_report() from reporter.py
  - phase: 02-core-detector
    provides: main() loop, JSONLLogger, ARPTable, check_packet, build_event
provides:
  - "--visualize flag in parse_cli_args() gates PNG generation per conflict"
  - "--report flag and path in parse_cli_args() for CSV at shutdown"
  - "--logfile flag in parse_cli_args() routes JSONL log path"
  - "main() wired: draw_topology on conflict, generate_report at shutdown, JSONLLogger(args.logfile)"
affects: [phase-04-shell-tools, integration-testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "TDD (RED → GREEN) for CLI wiring and main() integration"
    - "patch arp_detector.main.<name> for all main() unit tests"
    - "Namespace from argparse used to construct mock CLI args in tests"

key-files:
  created: []
  modified:
    - arp_detector/capture.py
    - arp_detector/main.py
    - tests/test_capture.py
    - tests/test_main.py

key-decisions:
  - "generate_report() called unconditionally at shutdown (not gated on --visualize)"
  - "draw_topology() gated on both args.visualize AND non-empty table in shutdown block"
  - "spoofed_ips_set and events_list declared in main() scope outside Live context manager so they persist across the loop"
  - "TestMainWiring uses patch('arp_detector.main.queue.Queue') to control packet delivery for deterministic test execution"

patterns-established:
  - "patch arp_detector.main.<symbol> for all symbols imported into main.py"
  - "Simulate queue side_effects: [packet_dict, KeyboardInterrupt()] to test one-packet loop exit"

requirements-completed: [VIZ-04, LOG-03]

# Metrics
duration: 15min
completed: 2026-05-12
---

# Phase 3 Plan 03: CLI Wiring Summary

**--visualize/--report/--logfile args added to parse_cli_args(); draw_topology() called on each conflict and shutdown; generate_report() called unconditionally at shutdown; JSONLLogger receives args.logfile path**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-05-12T00:00:00Z
- **Completed:** 2026-05-12T00:15:00Z
- **Tasks:** 2 (TDD RED + GREEN)
- **Files modified:** 4

## Accomplishments

- Added 3 new CLI args (--visualize, --report, --logfile) to parse_cli_args() in capture.py with correct defaults
- Wired draw_topology() into main() conflict branch (gated on args.visualize) and shutdown block (gated on args.visualize + non-empty table)
- Wired generate_report() into main() shutdown block unconditionally with events_list, packets_seen, args.report
- Changed JSONLLogger() to JSONLLogger(args.logfile) so log path is CLI-controlled
- Added spoofed_ips_set and events_list tracking vars in main() to accumulate across the full session
- All 146 tests pass (136 original + 10 new)

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Add failing tests** - `a07d1c9` (test)
2. **Task 2 (GREEN): Wire capture.py args and main.py call sites** - `ee2f744` (feat)

## Files Created/Modified

- `arp_detector/capture.py` - Added --visualize, --report, --logfile args to parse_cli_args()
- `arp_detector/main.py` - Added imports (draw_topology, generate_report); JSONLLogger(args.logfile); spoofed_ips_set/events_list tracking; draw_topology on conflict; generate_report at shutdown
- `tests/test_capture.py` - Added 6 new test methods to TestParseCLIArgs for all 3 new args
- `tests/test_main.py` - Added TestMainWiring class with 4 integration tests for new wiring

## Decisions Made

- `generate_report()` is unconditional at shutdown — every session produces a CSV (even if empty) so the user always gets a report artifact
- `draw_topology()` in the shutdown block is gated on both `args.visualize` AND `len(arp_table.get_all()) > 0` to avoid writing a blank graph
- `spoofed_ips_set` and `events_list` are declared outside the `with Live(...)` block so they persist through the entire session (not reset on Live exit)
- Test mocking approach: `patch("arp_detector.main.queue.Queue", return_value=mock_queue_inst)` with side_effects controls the queue loop deterministically without real threads

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Known Stubs

None - all data flows are fully wired. draw_topology() receives real ARPTable data; generate_report() receives real events_list and packets_seen counter.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 3 visualization + reporting pipeline fully wired end-to-end
- main.py now activates VIZ-04 (--visualize gates PNG on conflict) and LOG-03 (--logfile routes JSONL path)
- Phase 4 shell tools integration can proceed with confidence the main pipeline is complete

---
*Phase: 03-visualization-reporting*
*Completed: 2026-05-12*
