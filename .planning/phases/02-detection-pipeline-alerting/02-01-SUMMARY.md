---
phase: 02-detection-pipeline-alerting
plan: 01
subsystem: detection
tags: [arp-scan, subprocess, pandas, baseline, detection, mocking]

# Dependency graph
requires:
  - phase: 01-core-data-layer
    provides: ARPTable with update() and get_all() interface used directly by load_baseline()
provides:
  - arp_detector/baseline.py — load_baseline(table, timeout) subprocess wrapper for arp-scan
  - tests/test_baseline.py — 18 unit tests covering DET-02, all mock-based (no root needed)
affects: [03-visualization-reporting, 05-integration-demo-prep]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "subprocess list-form args (no shell=True) — mandatory pattern per CLAUDE.md"
    - "IPv4 regex guard (_IP_RE) to distinguish arp-scan data lines from header/footer"
    - "FileNotFoundError + TimeoutExpired caught at call site, warning to stderr, return 0"
    - "unittest.mock.patch('subprocess.run') — mock pattern for testing shell wrappers"

key-files:
  created:
    - arp_detector/baseline.py
    - tests/test_baseline.py
  modified: []

key-decisions:
  - "Parse arp-scan output by splitting on tab and matching first field to IPv4 regex — avoids fragile line-number assumptions about header/footer position"
  - "Return int count (not list of entries) from load_baseline() — caller only needs to know how many hosts were loaded for logging"
  - "Warn to stderr on binary-not-found / timeout, return 0 — detector still starts with empty baseline rather than crashing"

patterns-established:
  - "Baseline loader pattern: subprocess call -> parse stdout line-by-line -> seed ARPTable -> return count"
  - "All subprocess wrappers tested via unittest.mock.patch('subprocess.run') — zero root, zero network dependency"

requirements-completed: [DET-02]

# Metrics
duration: 2min
completed: 2026-05-09
---

# Phase 2 Plan 1: Baseline Loader Summary

**arp-scan subprocess wrapper (load_baseline) that seeds ARPTable via tab-split + IPv4 regex, with FileNotFoundError/TimeoutExpired guards and 18 mock-based unit tests**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-05-09T08:11:54Z
- **Completed:** 2026-05-09T08:13:34Z
- **Tasks:** 2 (TDD RED + GREEN)
- **Files modified:** 2

## Accomplishments

- Implemented load_baseline(table, timeout=30) in arp_detector/baseline.py using list-form subprocess args with no shell=True
- IPv4 regex guard skips all header/footer lines; only tab-separated lines with valid IP in field[0] are loaded into ARPTable
- Robust error handling: FileNotFoundError and TimeoutExpired both caught, warning printed to stderr, 0 returned — detector starts even if arp-scan is absent
- 18 unit tests in tests/test_baseline.py covering all plan behaviors — zero root, zero network, all tests use unittest.mock.patch
- Full test suite remains green: 84/84 tests pass (18 new + 66 prior)

## Task Commits

Each task was committed atomically:

1. **Task 1: Write failing tests for baseline.py (RED)** - `e092f7e` (test)
2. **Task 2: Implement baseline.py to make tests pass (GREEN)** - `fc29134` (feat)

## Files Created/Modified

- `arp_detector/baseline.py` - arp-scan subprocess wrapper; exports load_baseline()
- `tests/test_baseline.py` - 18 unit tests for load_baseline(); all mock-based

## Decisions Made

- Parse arp-scan output by splitting on tab and matching first field to IPv4 regex pattern (`r'^\d{1,3}(?:\.\d{1,3}){3}$'`) — avoids fragile line-number assumptions; robust to arp-scan version differences that change header/footer wording
- Return `int` count from load_baseline() rather than a list — the only caller need is logging "loaded N hosts"
- On FileNotFoundError/TimeoutExpired: print warning to stderr and return 0, allowing the detector to continue with an empty (cold-start) baseline rather than crashing at startup

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- baseline.py is ready to be called at detector startup (before AsyncSniffer starts)
- ARPTable.update() is called directly per parsed IP/MAC pair — wire-up in main entry point (Phase 5)
- arp-scan must be installed on the WSL/Linux target machine: `sudo apt install arp-scan`

---
*Phase: 02-detection-pipeline-alerting*
*Completed: 2026-05-09*
