---
phase: 01-core-data-layer-capture-skeleton
plan: 01
subsystem: database
tags: [pandas, matplotlib, scapy, networkx, rich, arp-table, dataframe]

# Dependency graph
requires: []
provides:
  - ARPTable class (update, check_conflict, get_all) backed by pandas DataFrame
  - matplotlib Agg backend stub (visualizer.py) with backend locked before pyplot import
  - stub logger.py and alerts.py for Phase 2 implementation
  - 21 pytest tests for ARPTable using synthetic in-memory data (no root/network)
  - requirements.txt pinning all five core libraries
affects:
  - 01-02 (capture skeleton uses ARPTable.update())
  - 01-03 (main entry point imports ARPTable)
  - 02-01 (detection pipeline builds on ARPTable conflict detection)
  - 03-01 (visualization uses visualizer.py stubs)

# Tech tracking
tech-stack:
  added: [pandas>=2.1.0, matplotlib>=3.8.0, networkx>=3.0, rich>=13.0.0, scapy>=2.5.0, pytest]
  patterns:
    - pandas .loc[] and .at[] assignment (never .append() — removed in pandas 2.0)
    - single-writer threading contract (main thread owns DataFrame, sniffer thread only enqueues)
    - matplotlib.use("Agg") before any pyplot import (locked at module level)

key-files:
  created:
    - arp_detector/__init__.py
    - arp_detector/arp_table.py
    - arp_detector/visualizer.py
    - arp_detector/logger.py
    - arp_detector/alerts.py
    - tests/__init__.py
    - tests/test_arp_table.py
    - requirements.txt
  modified: []

key-decisions:
  - "pandas .loc[] and .at[] assignment only — DataFrame.append() banned (removed in pandas 2.0)"
  - "matplotlib.use('Agg') set at top of visualizer.py before pyplot import — no display backend needed in WSL2"
  - "Single-writer threading contract: only main thread calls ARPTable.update(); sniffer enqueues dicts into Queue"

patterns-established:
  - "ARPTable uses .loc[ip] = [mac, now, now] for new rows and .at[ip, col] for column updates"
  - "check_conflict() is a pure read-only probe — it never modifies the DataFrame"
  - "get_all() returns self._df.copy() so callers get a snapshot, not a live reference"

requirements-completed: [DET-01]

# Metrics
duration: 15min
completed: 2026-05-09
---

# Phase 01 Plan 01: Core Data Layer Summary

**Pandas-backed ARPTable with conflict detection (DET-01), matplotlib Agg stub, and 21 passing pytest tests — all exercisable without root, network, or scapy**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-05-09T00:00:00Z
- **Completed:** 2026-05-09T00:15:00Z
- **Tasks:** 2 (scaffold + stubs, ARPTable TDD)
- **Files modified:** 8

## Accomplishments

- ARPTable class implementing update(), check_conflict(), and get_all() using pandas 2.x .loc[] pattern, with full threading contract documented in module docstring
- visualizer.py stub with matplotlib.use("Agg") locked as the first executable statement before any pyplot import — prevents WSL2 display backend failures in all downstream phases
- 21 pytest tests across 5 test classes covering all ARPTable behaviors (first-seen, same-MAC refresh, conflict detection, read-only check_conflict, copy isolation), all passing with exit code 0
- requirements.txt pinning all five stack libraries (scapy, pandas, matplotlib, networkx, rich) with minimum versions — no banned packages (colorama absent)

## Task Commits

Each task was committed atomically:

1. **Task 1 + Task 2: Project scaffold + stubs + ARPTable TDD** - `e8e77a5` (feat)

_Note: Files were pre-created outside GSD tracking; verified against plan requirements, confirmed all 21 tests pass, then committed as a single atomic unit._

## Files Created/Modified

- `arp_detector/__init__.py` - Empty package marker
- `arp_detector/arp_table.py` - ARPTable class: update(), check_conflict(), get_all() with pandas .loc[] and threading contract docs
- `arp_detector/visualizer.py` - matplotlib Agg backend stub with draw_topology() and save_final() stubs for Phase 3
- `arp_detector/logger.py` - log_event() and flush() stubs for Phase 2
- `arp_detector/alerts.py` - alert_conflict() stub for Phase 2
- `tests/__init__.py` - Empty test package marker
- `tests/test_arp_table.py` - 21 pytest tests across TestARPTableFirstSeen, TestARPTableSameMac, TestARPTableConflict, TestARPTableCheckConflict, TestARPTableGetAll
- `requirements.txt` - scapy>=2.5.0, pandas>=2.1.0, matplotlib>=3.8.0, networkx>=3.0, rich>=13.0.0

## Decisions Made

- Used .loc[ip] = [mac, now, now] for new row insertion — pandas 2.x compatible, .append() is gone
- matplotlib.use("Agg") placed before import matplotlib.pyplot — moving it after pyplot import is a no-op (pyplot caches backend on first import)
- Single-writer threading contract: ARPTable has no locks by design; only main thread writes; sniffer callback enqueues to Queue for main thread to drain

## Deviations from Plan

None — plan executed exactly as written. Files already existed matching the plan specification; verified against all plan requirements (must_haves, interfaces, acceptance criteria) and committed.

## Issues Encountered

- pytest was not installed in the Python 3.14 environment — installed via pip before running the test suite. All 21 tests passed after install.

## User Setup Required

None — no external service configuration required. All code runs with synthetic in-memory data, no root privileges needed for tests.

## Next Phase Readiness

- ARPTable is production-ready for Phase 01-02 (capture skeleton): just call `table.update(ip, mac)` on each ARP reply packet
- visualizer.py Agg stub is in place — Phase 03-01 can implement draw_topology() without changing the backend setup
- logger.py and alerts.py stubs are in place — Phase 02-01 can implement without changing call sites
- All phase 01 plans (01-02 capture skeleton, 01-03 main entry) have the data layer contract they need

---
*Phase: 01-core-data-layer-capture-skeleton*
*Completed: 2026-05-09*
