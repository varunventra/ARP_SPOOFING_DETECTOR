---
phase: 01-core-data-layer-capture-skeleton
plan: "02"
subsystem: detection
tags: [arp, pandas, detection, pytest, tdd]

# Dependency graph
requires:
  - phase: 01-core-data-layer-capture-skeleton plan 01
    provides: ARPTable.update() — IP->MAC mapping with conflict detection

provides:
  - check_packet() in arp_detector/detector.py — stateless ARP reply filter and conflict dispatcher
  - 17 pytest tests covering all detection rules (op filter, gratuitous ARP, first-seen, conflict, repeat)

affects:
  - 01-03-capture-skeleton (capture.py calls check_packet() for each parsed packet)
  - Phase 2 detection pipeline (check_packet is the core detection primitive)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Packet dict contract: synthetic plain Python dicts flow through detection without scapy dependency"
    - "Two-rule pre-filter pattern: op!=2 skip, gratuitous ARP skip, then delegate to stateful table"
    - "TDD flow: RED (ImportError on missing module) -> GREEN (implement module to pass all tests)"

key-files:
  created:
    - arp_detector/detector.py
    - tests/test_detector.py
  modified: []

key-decisions:
  - "check_packet() is a pure function over packet dict + ARPTable — no module-level state"
  - "Gratuitous ARP (src_ip == dst_ip) filtered before table lookup to avoid false-positive conflicts"
  - "No scapy import in detector.py — testable without root, network, or scapy installation"

patterns-established:
  - "Packet dict contract: {src_ip, src_mac, dst_ip, op, timestamp} — capture.py produces, detector.py consumes"
  - "Detection is op=2 replies only; op=1 requests do not seed the ARP table"

requirements-completed:
  - DET-01

# Metrics
duration: 1min
completed: "2026-05-09"
---

# Phase 01 Plan 02: Detector Logic Summary

**check_packet() ARP conflict detector with op=2 filter, gratuitous ARP skip, and ARPTable delegation — 17 tests all passing, no scapy dependency**

## Performance

- **Duration:** ~1 min
- **Started:** 2026-05-09T07:34:57Z
- **Completed:** 2026-05-09T07:35:51Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 2

## Accomplishments

- Implemented `arp_detector/detector.py` with `check_packet()` — the core detection primitive for all downstream capture and alerting
- 17 unit tests across 6 test classes covering every detection scenario (first-seen, conflict, same-MAC repeat, op=1 skip, gratuitous ARP skip, multi-IP independence)
- Zero scapy or root dependency — fully testable in any Python 3.11+ environment

## Task Commits

Each task was committed atomically:

1. **Task 1: detector.py + test_detector.py** - `bdbbd8d` (feat)

**Plan metadata:** (see final commit below)

_Note: TDD task — RED (ImportError confirmed), GREEN (17/17 pass in one pass)_

## Files Created/Modified

- `arp_detector/detector.py` - check_packet() with op=2 filter, gratuitous ARP filter, ARPTable delegation
- `tests/test_detector.py` - 17 pytest tests: TestFirstSeen, TestConflictDetection, TestSameMacRepeat, TestOpFilter, TestGratuitousARPFilter, TestMultipleIPs

## Decisions Made

- check_packet() is stateless (no module-level variables) — all state lives in ARPTable, passed in as argument. This makes unit testing straightforward and avoids hidden coupling.
- Gratuitous ARP check (src_ip == dst_ip) occurs before table.update() — prevents false conflict signals from legitimate IP announcements.

## Deviations from Plan

None — plan executed exactly as written. The test file already existed as an untracked file (noted in execution context), so the RED phase was verified via ImportError on the missing module rather than via test assertion failure.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `check_packet()` is the complete detection primitive — ready for Plan 01-03 (capture.py) to wire packet callbacks through it
- Both test suites (test_arp_table.py 21 tests + test_detector.py 17 tests = 38 total) pass clean together
- No stubs or placeholders in detector.py — all detection rules fully implemented

---
*Phase: 01-core-data-layer-capture-skeleton*
*Completed: 2026-05-09*
