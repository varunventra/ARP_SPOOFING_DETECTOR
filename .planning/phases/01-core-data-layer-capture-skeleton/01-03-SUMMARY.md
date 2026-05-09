---
phase: 01-core-data-layer-capture-skeleton
plan: 03
subsystem: capture
tags: [scapy, asyncsniffer, queue, pcap, argparse, tdd, cap-01, cap-02, cap-03, cap-04]

# Dependency graph
requires:
  - 01-01 (ARPTable class — update/check_conflict/get_all)
  - 01-02 (check_packet() in detector.py — packet dict contract)
provides:
  - capture.py with 5 exported functions: check_root, get_default_iface, parse_cli_args, build_packet_callback, start_capture
  - tests/fixtures/synthetic_arp.pcap — 5-packet pcap fixture (2 normal op=2, 1 op=1, 1 spoofed op=2, 1 gratuitous op=2)
  - tests/test_capture.py — 28 pytest tests for all capture behaviors
  - TDD-verified: all tests written RED before implementation, 28/28 pass GREEN
affects:
  - 02-01 (detection pipeline wires start_capture() + packet_queue into main loop)
  - 05-01 (demo wires capture.py as entry point with check_root() guard)

# Tech tracking
tech-stack:
  added: [scapy>=2.5.0 (installed 2.7.0)]
  patterns:
    - AsyncSniffer with store=False — prevents RAM OOM on long sessions
    - Queue as the only thread boundary between sniffer and main threads
    - build_packet_callback closure — filters op=2 only, enqueues dict, never touches ARPTable
    - getattr(os, 'geteuid', None) — cross-platform root check (Windows lacks os.geteuid)
    - patch('module.os.geteuid', create=True) — mock pattern for Windows-compatible geteuid testing

key-files:
  created:
    - arp_detector/capture.py
    - tests/fixtures/create_fixture.py
    - tests/fixtures/synthetic_arp.pcap
    - tests/test_capture.py
  modified: []

key-decisions:
  - "AsyncSniffer + store=False is Phase 1 architecture lock — never change to store=True"
  - "Callback closure is op=2-only filter; gratuitous ARP semantic filtering belongs in detector.check_packet()"
  - "check_root() uses getattr(os, 'geteuid', None) for cross-platform safety — WSL/Linux path still works"
  - "Mock tests use patch('arp_detector.capture.os.geteuid', create=True) — required for Windows Python 3.14 where os.geteuid is absent"

requirements-completed: [CAP-01, CAP-02, CAP-03, CAP-04]

# Metrics
duration: 8min
completed: 2026-05-09
---

# Phase 01 Plan 03: Capture Skeleton Summary

**AsyncSniffer-based packet capture with Queue integration, root privilege guard, --iface CLI arg, and 28 passing TDD tests — all exercisable without root using synthetic scapy packets and pcap replay**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-05-09T07:37:54Z
- **Completed:** 2026-05-09T07:46:00Z
- **Tasks:** 2 (pcap fixture creation, capture.py TDD)
- **Files created:** 4
- **Tests:** 28 new tests; 66 total pass across all 3 test files

## Accomplishments

- `arp_detector/capture.py` implementing all 5 required exported functions:
  - `check_root()` — exits with code 1 if not root (geteuid != 0); uses `getattr` for Windows compat
  - `get_default_iface()` — calls `get_if_list()`, filters `'lo'`, returns first candidate; exits if empty
  - `parse_cli_args()` — argparse with optional `--iface`; defaults to None for auto-detection
  - `build_packet_callback(queue)` — closure that enqueues only op=2 ARP dicts; op=1 and non-ARP dropped
  - `start_capture(iface, queue)` — creates and starts AsyncSniffer with `store=False`, `filter="arp"`
- `tests/fixtures/synthetic_arp.pcap` — 5-packet fixture: 4 op=2 (1 spoofed, 1 gratuitous), 1 op=1
- `tests/fixtures/create_fixture.py` — reproducible fixture generator using scapy wrpcap()
- `tests/test_capture.py` — 28 tests across 6 test classes (TDD: written RED first, all GREEN after implementation)
- Full 66-test suite passes: test_arp_table.py (21) + test_detector.py (17) + test_capture.py (28)

## Task Commits

Each task committed atomically:

1. **Task 1: Create synthetic ARP pcap fixture** — `6ddede9` (feat)
2. **Task 2 RED: Failing tests for capture.py** — `89a584b` (test)
3. **Task 2 GREEN: Implement capture.py** — `453f19b` (feat)

## Files Created

- `arp_detector/capture.py` — capture engine: check_root, get_default_iface, parse_cli_args, build_packet_callback, start_capture, main()
- `tests/fixtures/create_fixture.py` — script to regenerate the pcap fixture
- `tests/fixtures/synthetic_arp.pcap` — 5-packet binary pcap for offline replay tests
- `tests/test_capture.py` — 28 tests: TestCheckRoot, TestGetDefaultIface, TestParseCLIArgs, TestBuildPacketCallback, TestStartCapture, TestPcapReplay

## Decisions Made

- `store=False` is a hard Phase 1 lock on all AsyncSniffer calls — default `store=True` OOMs on long sessions; retrofitting the capture loop later would require a full rewrite
- Callback closure only filters by `op == 2`; gratuitous ARP semantic filtering (`psrc == pdst`) is `detector.check_packet()`'s responsibility — separation of concerns
- `getattr(os, "geteuid", None)` pattern chosen so capture.py imports without error on Windows native Python; on POSIX (WSL/Linux), the function is present and the check runs normally
- Test mock uses `patch('arp_detector.capture.os.geteuid', create=True)` — the `create=True` kwarg is required on Windows where `os.geteuid` is absent from the frozen `os` module

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Windows os.geteuid mock incompatibility**
- **Found during:** Task 2 GREEN (first test run)
- **Issue:** Tests patching `"os.geteuid"` failed with `AttributeError: <module 'os' (frozen)> does not have the attribute 'geteuid'` on Windows Python 3.14 — `os.geteuid` is a POSIX-only function absent from the Windows `os` module
- **Fix 1:** Updated all three `TestCheckRoot` test patches from `patch("os.geteuid", ...)` to `patch("arp_detector.capture.os.geteuid", ..., create=True)` — target is the module's `os` reference, `create=True` injects the attribute when absent
- **Fix 2:** Updated `check_root()` in `capture.py` from direct `os.geteuid()` call to `getattr(os, "geteuid", None)` with early return on `None` — allows import and no-op on Windows; full root check runs on POSIX (WSL/Linux) as intended
- **Files modified:** `arp_detector/capture.py`, `tests/test_capture.py`
- **Commit:** `453f19b`
- **Impact:** Zero — behavior on WSL/Linux target platform is identical; test suite now runs on both platforms

## Known Stubs

None — all 5 exported functions in capture.py are fully implemented and tested.

## Self-Check: PASSED

All files exist on disk:
- FOUND: arp_detector/capture.py
- FOUND: tests/test_capture.py
- FOUND: tests/fixtures/synthetic_arp.pcap
- FOUND: tests/fixtures/create_fixture.py
- FOUND: .planning/phases/01-core-data-layer-capture-skeleton/01-03-SUMMARY.md

All commits exist in git log:
- FOUND: 6ddede9 feat(01-03): create synthetic ARP pcap fixture with 5 packets
- FOUND: 89a584b test(01-03): add failing tests for capture.py (RED)
- FOUND: 453f19b feat(01-03): implement capture.py — AsyncSniffer packet capture engine (GREEN)

Test suite: 66 passed, 0 failed (all 3 test files)
