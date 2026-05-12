---
phase: 03-visualization-reporting
plan: "01"
subsystem: visualization
tags: [networkx, matplotlib, bipartite-graph, topology, png, arp-spoofing]

# Dependency graph
requires:
  - phase: 02-detection-pipeline
    provides: ARPTable.get_all() DataFrame shape (index="ip", column="mac") used as input
provides:
  - draw_topology(arp_table_df, spoofed_ips, output_path) — bipartite PNG generator with red/green node coloring
  - save_final(output_path) — thin wrapper (no-op, superseded by direct calls)
affects: [04-shell-integration, 05-integration-demo]

# Tech tracking
tech-stack:
  added: [networkx 3.x, bipartite_layout from networkx.drawing.layout]
  patterns:
    - bipartite graph with ip_nodes (bipartite=0) and mac_nodes (bipartite=1)
    - node_colors built by iterating G.nodes() in order (not ip_nodes/mac_nodes separately)
    - plt.close(fig) after every savefig() to prevent figure accumulation
    - matplotlib Agg backend locked at module top — no plt.show() anywhere

key-files:
  created: []
  modified:
    - arp_detector/visualizer.py
    - tests/test_visualizer.py

key-decisions:
  - "bipartite_layout imported from networkx.drawing.layout (not networkx.algorithms.bipartite — does not exist in v3.6.1)"
  - "plt.close(fig) mandatory after every savefig() — prevents figure accumulation across repeated calls"
  - "save_final() kept as no-op — direct draw_topology() calls in main.py are sufficient"
  - "node_colors list built by iterating G.nodes() directly — ensures order matches networkx draw iteration"

patterns-established:
  - "Agg backend pattern: matplotlib.use('Agg') at module top, before all pyplot imports, never duplicated"
  - "Figure cleanup pattern: fig, ax = plt.subplots() → savefig() → plt.close(fig)"
  - "Bipartite graph pattern: G.add_nodes_from(ip_nodes, bipartite=0) + G.add_nodes_from(mac_nodes, bipartite=1)"

requirements-completed: [VIZ-01, VIZ-02, VIZ-03]

# Metrics
duration: 8min
completed: 2026-05-12
---

# Phase 3 Plan 01: Topology Visualizer Summary

**Bipartite networkx graph (IPs left, MACs right) rendered to PNG via Agg backend with red highlighting for spoofed nodes**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-05-12T00:00:00Z
- **Completed:** 2026-05-12T00:08:00Z
- **Tasks:** 2 (TDD: RED already done, GREEN implemented)
- **Files modified:** 1 (visualizer.py)

## Accomplishments

- Implemented draw_topology() replacing the stub with a full bipartite networkx graph renderer
- Spoofed IPs and their associated MACs are colored red; all other nodes are green
- plt.close(fig) after every savefig() prevents figure accumulation across repeated calls
- Empty DataFrame guard returns immediately without creating a file (clean no-op behavior)
- All 6 unit tests pass; full 128-test suite green with zero regressions

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Write failing tests for draw_topology()** - pre-existing (tests already written)
2. **Task 2 (GREEN): Implement draw_topology()** - `4ad0f20` (feat)

**Plan metadata:** (docs commit follows)

_Note: RED state was pre-existing — tests were already written and 3 were failing. This execution covered the GREEN phase only._

## Files Created/Modified

- `arp_detector/visualizer.py` - Implemented draw_topology() and save_final(); bipartite graph with Agg PNG output

## Decisions Made

- Used `from networkx.drawing.layout import bipartite_layout` (verified path for networkx 3.6.1 — the algorithms.bipartite path does not exist)
- `node_colors` list built by iterating `G.nodes()` directly to guarantee alignment with networkx's internal draw order
- `save_final()` kept as a no-op pass — main.py calls draw_topology() directly, making the wrapper redundant

## Deviations from Plan

None - plan executed exactly as written. Tests were pre-existing (RED state), implementation followed the plan's step-by-step algorithm verbatim.

## Issues Encountered

None. The bipartite_layout import path, node_colors iteration order, and plt.close(fig) placement were all specified precisely in the plan context, avoiding the common pitfalls.

## User Setup Required

None - no external service configuration required. Agg backend renders to file without a display.

## Next Phase Readiness

- draw_topology() is ready for main.py to call on each detected conflict (Phase 4/5)
- bipartite PNG output written to configurable output_path — main.py can pass its own path
- No stubs remain in visualizer.py that block the plan's goal

---
*Phase: 03-visualization-reporting*
*Completed: 2026-05-12*
