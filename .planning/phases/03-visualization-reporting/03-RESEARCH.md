# Phase 3: Visualization + Reporting - Research

**Researched:** 2026-05-09
**Domain:** networkx bipartite graphs, matplotlib Agg, pandas CSV reporting, argparse extension
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Bipartite layout (IP nodes left, MAC nodes right) chosen over spring layout — deterministic rendering
- Visualization is off by default (`--visualize` flag required) to avoid WSL2 `$DISPLAY` failures
- `matplotlib.use("Agg")` is ALREADY locked at the top of `visualizer.py` — do NOT move, do NOT change
- `topology.png` generated via networkx + matplotlib Agg, saved to file — never `plt.show()`
- Spoofed nodes: red; legitimate nodes: green
- Regenerate `topology.png` on each new spoofing event
- Summary report: pandas DataFrame → `attack_report.csv` at session end (Ctrl+C or `--report` flag)
- `--logfile <path>` redirects JSONL log output from default `arp_detector.log`

### Claude's Discretion
All implementation choices are at Claude's discretion. Use ROADMAP phase goal, success criteria, and codebase conventions.

### Deferred Ideas (OUT OF SCOPE)
- Interactive graph visualization (requires `$DISPLAY`)
- Real-time graph streaming (Phase 5 demo uses static PNG)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| VIZ-01 | networkx bipartite graph (IP nodes left, MAC nodes right) rendered to `topology.png` via matplotlib Agg | Verified: `bipartite_layout` from `networkx.drawing.layout`, `nx.draw_networkx()` with Agg fig/ax |
| VIZ-02 | Spoofed nodes in red, legitimate nodes in green | Verified: per-node `node_color` list passed to `nx.draw_networkx()` |
| VIZ-03 | Regenerate and overwrite `topology.png` on each new spoofing event | Verified: stateless `draw_topology()` called from main loop on conflict, `fig.savefig()` overwrites |
| VIZ-04 | `--visualize` flag to enable PNG generation (off by default) | Verified: `action='store_true', default=False` argparse pattern, checked in main loop `if args.visualize` |
| LOG-01 | pandas summary at session end: total packets, attacks detected, unique attacker MACs, timeline | Verified: `pd.DataFrame(events)` + computed summary dict |
| LOG-02 | Save summary as `attack_report.csv` via `pandas.to_csv()` | Verified: `df.to_csv(path, index=False)`, round-trips cleanly with `pd.read_csv()` |
| LOG-03 | `--logfile <path>` argument for custom log location | Verified: `JSONLLogger(path)` already accepts path; add `--logfile` to argparse and pass through |
</phase_requirements>

---

## Summary

Phase 3 adds two independent output channels to the existing detection pipeline: a networkx topology PNG that marks spoofed nodes red, and a pandas CSV summary report at session end. Both are pure output — they read from existing data structures (`ARPTable.get_all()`, collected DET-05 event dicts) and write files. Neither touches the packet capture loop or detection logic.

The visualization work is straightforward: `networkx.drawing.layout.bipartite_layout` (the correct import path — not `networkx.algorithms.bipartite.layout`, which does not exist in networkx 3.6.1) provides deterministic left/right column layout. `nx.draw_networkx()` accepts a `node_color` list that controls per-node color. The full draw-save-close cycle using `fig, ax = plt.subplots()` / `fig.savefig()` / `plt.close(fig)` was verified against the installed Agg backend.

The reporting work is even simpler: `reporter.py` collects the list of DET-05 event dicts that main.py already builds, wraps them in a DataFrame, calls `to_csv()`, and appends a summary. The `--logfile` change is a one-line extension to `parse_cli_args()` plus passing `args.logfile` to the `JSONLLogger` constructor — the constructor already accepts a path parameter.

**Primary recommendation:** Implement in three micro-plans: (1) `visualizer.py` implementation + tests, (2) `reporter.py` new module + tests, (3) wire both into `main.py` via new CLI args + call sites.

---

## Standard Stack

### Core (all already in requirements.txt)
| Library | Installed Version | Purpose | Why Standard |
|---------|------------------|---------|--------------|
| networkx | 3.6.1 | Bipartite graph data structure + layout | Project-mandated; installed and verified |
| matplotlib | 3.10.8 | Agg backend rendering, `fig.savefig()` | Project-mandated; Agg backend confirmed working |
| pandas | 3.0.2 | DataFrame → CSV report | Project-mandated; `to_csv()` verified |

### No New Dependencies Required
All libraries needed for Phase 3 are already in `requirements.txt`. No `pip install` step needed.

---

## Architecture Patterns

### Recommended Project Structure (additions only)
```
arp_detector/
├── visualizer.py    # EXISTING stub — implement draw_topology() and save_final()
├── reporter.py      # NEW — generate_report() function, pandas → CSV
tests/
├── test_visualizer.py  # NEW — uses synthetic DataFrames, no network/root
├── test_reporter.py    # NEW — uses synthetic event lists and tmp_path
```

### Pattern 1: draw_topology() — Stateless Bipartite Renderer

**What:** Pure function. Takes ARP table DataFrame + set of spoofed IPs. Builds a new figure every call, saves to path, closes figure. No state retained between calls.

**When to use:** Called from `main.py` main loop immediately after `if conflict is not None` branch, gated on `args.visualize`.

**Verified example (confirmed against networkx 3.6.1 + matplotlib 3.10.8 Agg):**
```python
# Source: verified locally against installed packages
import matplotlib
matplotlib.use("Agg")   # already at top of visualizer.py — DO NOT repeat here
import matplotlib.pyplot as plt
import networkx as nx
from networkx.drawing.layout import bipartite_layout  # correct import path

def draw_topology(arp_table_df, spoofed_ips=None, output_path="topology.png"):
    """Generate bipartite topology PNG. Safe to call repeatedly — no state."""
    if spoofed_ips is None:
        spoofed_ips = set()

    if len(arp_table_df) == 0:
        return  # nothing to draw

    G = nx.Graph()
    ip_nodes = list(arp_table_df.index)
    mac_nodes = list(arp_table_df["mac"].unique())

    G.add_nodes_from(ip_nodes, bipartite=0)   # left column
    G.add_nodes_from(mac_nodes, bipartite=1)  # right column

    for ip, row in arp_table_df.iterrows():
        G.add_edge(ip, row["mac"])

    # Per-node color list — order must match G.nodes() iteration order
    node_colors = [
        "red" if n in spoofed_ips or n in _spoofed_macs(arp_table_df, spoofed_ips)
        else "green"
        for n in G.nodes()
    ]

    pos = bipartite_layout(G, ip_nodes)

    fig, ax = plt.subplots(figsize=(12, 7))
    nx.draw_networkx(G, pos=pos, ax=ax, node_color=node_colors,
                     node_size=1200, font_size=7, arrows=False)
    ax.set_title("ARP Network Topology")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close(fig)   # CRITICAL: prevents figure accumulation across repeated calls
```

**Key detail — which nodes turn red:** The CONTEXT.md says "spoofed nodes" (red). A spoofing event means an IP was claimed by a new MAC. Both the victim IP and the attacker MAC should be red. Derive attacker MACs from spoofed_ips by looking up what MACs those IPs currently map to in `arp_table_df` — call a helper `_spoofed_macs(df, spoofed_ips)` that returns the set of MAC values for those IPs.

### Pattern 2: bipartite_layout Import Path

**Critical:** The correct import in networkx 3.6.1 is:
```python
from networkx.drawing.layout import bipartite_layout
```
NOT `from networkx.algorithms.bipartite.layout import bipartite_layout` — that module does not exist. The latter raises `ModuleNotFoundError`.

`bipartite_layout(G, top_nodes)` where `top_nodes` is the set/list of left-side (IP) nodes. Returns `{node: array([x, y])}` position dict passed directly to `nx.draw_networkx(pos=pos, ...)`.

### Pattern 3: Node Color List Order

`nx.draw_networkx()` iterates `G.nodes()` in insertion order (Python 3.7+ dict order). The `node_color` list must be built with the same iteration order:
```python
node_colors = ["red" if n in red_set else "green" for n in G.nodes()]
```
The `red_set` should be `spoofed_ips | spoofed_macs` — both the IP and the MAC involved in the attack get colored red.

### Pattern 4: reporter.py — generate_report()

**What:** Reads a list of DET-05 event dicts (passed directly, not re-read from disk), wraps in DataFrame, writes CSV, returns (df, summary_dict).

**Verified example:**
```python
# Source: verified locally
import pandas as pd

def generate_report(events: list[dict], total_packets: int = 0,
                    output_path: str = "attack_report.csv") -> tuple[pd.DataFrame, dict]:
    """Build CSV report from collected DET-05 events.
    
    Args:
        events: List of DET-05 event dicts from main loop.
        total_packets: packets_seen counter from main loop.
        output_path: Destination CSV path.
    
    Returns:
        (DataFrame of events, summary dict with aggregates)
    """
    COLUMNS = ["timestamp", "attacker_mac", "victim_ip",
               "original_mac", "spoofed_mac", "attack_type"]

    if events:
        df = pd.DataFrame(events)
    else:
        df = pd.DataFrame(columns=COLUMNS)

    df.to_csv(output_path, index=False)

    summary = {
        "total_packets": total_packets,
        "total_attacks": len(df),
        "unique_attacker_macs": int(df["attacker_mac"].nunique()) if len(df) > 0 else 0,
    }
    return df, summary
```

**Edge case verified:** Empty events list produces valid CSV with column headers only — `pd.read_csv()` loads it without errors.

### Pattern 5: argparse Extension in parse_cli_args()

`parse_cli_args()` lives in `capture.py` and is imported by `main.py`. Add the three Phase 3 arguments there:
```python
parser.add_argument(
    "--visualize",
    action="store_true",
    default=False,
    help="Generate topology.png on each spoofing event (off by default).",
)
parser.add_argument(
    "--report",
    default="attack_report.csv",
    metavar="PATH",
    help="Path for CSV summary report (written at session end).",
)
parser.add_argument(
    "--logfile",
    default="arp_detector.log",
    metavar="PATH",
    help="Path for JSONL log file (default: arp_detector.log).",
)
```

Then in `main.py`: change `JSONLLogger()` to `JSONLLogger(args.logfile)`. The constructor already accepts `path` — verified.

### Pattern 6: Wiring draw_topology() into main.py

Call after the conflict branch, inside the `with Live(...)` block:
```python
if conflict is not None:
    event = build_event(conflict)
    attacks_detected += 1
    attacker_macs.add(event["attacker_mac"])
    spoofed_ips_set.add(event["victim_ip"])   # accumulate for coloring
    events_list.append(event)                  # accumulate for reporter
    recent_alerts.append(...)
    logger.log_event(event)
    live.console.print(format_alert_panel(event))
    if args.visualize:                         # VIZ-04 gate
        draw_topology(arp_table.get_all(), spoofed_ips=spoofed_ips_set,
                      output_path="topology.png")
```

And in the shutdown block:
```python
sniffer.stop()
logger.close()
if args.visualize and len(arp_table.get_all()) > 0:
    draw_topology(arp_table.get_all(), spoofed_ips=spoofed_ips_set,
                  output_path="topology.png")  # final save (VIZ-03)
generate_report(events_list, total_packets=packets_seen, output_path=args.report)
```

### Anti-Patterns to Avoid

- **`plt.show()` anywhere:** Agg backend does not support interactive display. `plt.show()` with Agg is a silent no-op on some systems and raises on others. Only `fig.savefig()`.
- **`plt.clf()` instead of `plt.close(fig)`:** `clf()` clears but does not close the figure — figures accumulate in memory across repeated calls. Use `plt.close(fig)`.
- **Global figure state:** Never use `plt.figure()` / `plt.subplot()` (module-level state). Always `fig, ax = plt.subplots()` and pass `ax` explicitly. This is the only thread-safe pattern with Agg.
- **`from networkx.algorithms.bipartite.layout import bipartite_layout`:** Module does not exist in 3.6.1. Use `from networkx.drawing.layout import bipartite_layout`.
- **Re-reading the JSONL log in reporter.py:** Pass the in-memory `events_list` directly to `generate_report()`. Re-reading from disk adds file I/O, encoding edge cases, and requires the log path to be known to reporter. Keep reporter pure.
- **Calling `draw_topology()` inside the scapy callback:** The packet callback runs in the AsyncSniffer thread. The existing architecture already prevents this (callback only enqueues), but do not add any visualization calls to the callback or `check_packet()`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Bipartite node layout | Custom x/y position calculation | `bipartite_layout(G, ip_nodes)` | Handles single-node, disconnected, isolated node edge cases automatically |
| Per-node color mapping | Custom dict lookup loop | List comprehension over `G.nodes()` with set membership | Order must match G.nodes() iteration; list comprehension guarantees this |
| CSV with header only (no rows) | Custom file writer | `pd.DataFrame(columns=[...]).to_csv()` | Verified: produces valid CSV with headers, no data rows; pd.read_csv() loads cleanly |
| Figure memory cleanup | Manual figure tracking | `plt.close(fig)` | Prevents figure accumulation — verified: `plt.get_fignums()` returns `[]` after close |

---

## Common Pitfalls

### Pitfall 1: Wrong bipartite_layout Import Path
**What goes wrong:** `from networkx.algorithms.bipartite.layout import bipartite_layout` raises `ModuleNotFoundError` on networkx 3.x.
**Why it happens:** Documentation examples sometimes show different import paths; the function moved.
**How to avoid:** Use `from networkx.drawing.layout import bipartite_layout` — verified against networkx 3.6.1.
**Warning signs:** `ModuleNotFoundError: No module named 'networkx.algorithms.bipartite.layout'`

### Pitfall 2: node_color List Length Mismatch
**What goes wrong:** `nx.draw_networkx()` raises `ValueError: X supplied colors but Y nodes provided` or silently cycles colors.
**Why it happens:** Building `node_color` from `ip_nodes + mac_nodes` when `G.nodes()` iteration order differs.
**How to avoid:** Always build `node_color` by iterating `G.nodes()` directly: `[color_for(n) for n in G.nodes()]`.
**Warning signs:** `ValueError` mentioning color count mismatch during draw; some nodes getting wrong colors.

### Pitfall 3: Figure Accumulation Across Repeated Calls
**What goes wrong:** Memory grows unbounded when `draw_topology()` is called on every spoofing event during a sustained attack.
**Why it happens:** `plt.savefig()` without `plt.close(fig)` leaves the figure allocated.
**How to avoid:** Always call `plt.close(fig)` after `fig.savefig()`. Verified: `plt.get_fignums()` is empty after close.
**Warning signs:** Memory usage climbing during sustained attack simulation.

### Pitfall 4: Empty Graph Crash
**What goes wrong:** `bipartite_layout(G, [])` or operating on an empty graph crashes or produces degenerate output.
**Why it happens:** Called before any packets processed (empty `arp_table_df`).
**How to avoid:** Guard at top of `draw_topology()`: `if len(arp_table_df) == 0: return`. Verified: empty DataFrame has `len() == 0`.
**Warning signs:** AttributeError or ZeroDivisionError during layout computation on first packet.

### Pitfall 5: parse_cli_args() Test Breakage
**What goes wrong:** Existing tests for `parse_cli_args()` fail because `sys.argv` during pytest includes pytest arguments.
**Why it happens:** `parser.parse_args()` reads `sys.argv[1:]` by default; pytest injects its own args.
**How to avoid:** In tests, call `parse_cli_args()` by patching `sys.argv` or by passing `args=[]` directly. Existing tests already use `patch` — follow that pattern. The function itself does NOT need `parse_known_args()`.
**Warning signs:** `error: unrecognized arguments: --tb=short` in test output.

### Pitfall 6: Reporter Receiving No Total Packets Count
**What goes wrong:** `attack_report.csv` shows 0 total packets because `packets_seen` was not passed to `generate_report()`.
**Why it happens:** `generate_report()` only knows about events (attacks), not the total packet counter.
**How to avoid:** Pass `total_packets=packets_seen` explicitly from the main shutdown sequence. If the report has a summary row, add it as a separate metadata section or a second CSV.
**Warning signs:** `total_packets: 0` in report when attacks were detected.

---

## Code Examples

### Full draw_topology() verified pattern
```python
# Source: verified against networkx 3.6.1, matplotlib 3.10.8, Agg backend
# File: arp_detector/visualizer.py

import matplotlib
matplotlib.use("Agg")  # already at top of file — do not duplicate
import matplotlib.pyplot as plt
import networkx as nx
from networkx.drawing.layout import bipartite_layout  # verified correct path


def draw_topology(arp_table_df, spoofed_ips=None, output_path="topology.png"):
    if spoofed_ips is None:
        spoofed_ips = set()
    if len(arp_table_df) == 0:
        return

    # Derive MACs belonging to spoofed IPs (for red coloring)
    spoofed_macs = set(
        arp_table_df.loc[ip, "mac"]
        for ip in spoofed_ips
        if ip in arp_table_df.index
    )
    red_nodes = spoofed_ips | spoofed_macs

    G = nx.Graph()
    ip_nodes = list(arp_table_df.index)
    mac_nodes = list(arp_table_df["mac"].unique())
    G.add_nodes_from(ip_nodes, bipartite=0)
    G.add_nodes_from(mac_nodes, bipartite=1)
    for ip, row in arp_table_df.iterrows():
        G.add_edge(ip, row["mac"])

    node_colors = ["red" if n in red_nodes else "green" for n in G.nodes()]
    pos = bipartite_layout(G, ip_nodes)

    fig, ax = plt.subplots(figsize=(12, 7))
    nx.draw_networkx(G, pos=pos, ax=ax, node_color=node_colors,
                     node_size=1200, font_size=7, arrows=False)
    ax.set_title("ARP Network Topology")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close(fig)
```

### generate_report() verified pattern
```python
# Source: verified — pandas 3.0.2
# File: arp_detector/reporter.py

import pandas as pd

_COLUMNS = ["timestamp", "attacker_mac", "victim_ip",
            "original_mac", "spoofed_mac", "attack_type"]


def generate_report(events: list, total_packets: int = 0,
                    output_path: str = "attack_report.csv"):
    df = pd.DataFrame(events) if events else pd.DataFrame(columns=_COLUMNS)
    df.to_csv(output_path, index=False)
    summary = {
        "total_packets": total_packets,
        "total_attacks": len(df),
        "unique_attacker_macs": int(df["attacker_mac"].nunique()) if len(df) > 0 else 0,
    }
    return df, summary
```

### parse_cli_args() extension (in capture.py)
```python
# Add inside the existing parser in parse_cli_args() — verified argparse pattern
parser.add_argument("--visualize", action="store_true", default=False,
                    help="Generate topology.png on each spoofing event.")
parser.add_argument("--report", default="attack_report.csv", metavar="PATH",
                    help="Path for CSV summary report.")
parser.add_argument("--logfile", default="arp_detector.log", metavar="PATH",
                    help="Path for JSONL log file.")
```

### main.py: initialization changes
```python
# Change in Step 4 of main():
logger = JSONLLogger(args.logfile)   # was: JSONLLogger()

# Add tracking variables before the Live block:
spoofed_ips_set: set = set()
events_list: list = []

# Inside conflict branch:
spoofed_ips_set.add(event["victim_ip"])
events_list.append(event)
if args.visualize:
    draw_topology(arp_table.get_all(), spoofed_ips=spoofed_ips_set)

# In shutdown block (after logger.close()):
from arp_detector.reporter import generate_report
generate_report(events_list, total_packets=packets_seen, output_path=args.report)
if args.visualize:
    draw_topology(arp_table.get_all(), spoofed_ips=spoofed_ips_set)  # final save
```

---

## Environment Availability

Step 2.6: All dependencies are already installed — no external environment changes required.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| networkx | VIZ-01 bipartite graph | Yes | 3.6.1 | — |
| matplotlib (Agg) | VIZ-01 PNG save | Yes | 3.10.8 | — |
| pandas | LOG-01, LOG-02 CSV report | Yes | 3.0.2 | — |
| pytest | Test suite | Yes | 9.0.3 | — |

No missing dependencies.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 9.0.3 |
| Config file | none — pytest auto-discovers `tests/` directory |
| Quick run command | `python3 -m pytest tests/test_visualizer.py tests/test_reporter.py -x -q` |
| Full suite command | `python3 -m pytest tests/ -x -q` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| VIZ-01 | `draw_topology()` creates a valid PNG at given path | unit | `pytest tests/test_visualizer.py::TestDrawTopology::test_creates_png_file -x` | No — Wave 0 |
| VIZ-02 | No crash when `spoofed_ips` has members; red node list computed | unit | `pytest tests/test_visualizer.py::TestDrawTopology::test_spoofed_ip_in_red_nodes -x` | No — Wave 0 |
| VIZ-03 | Second call to `draw_topology()` overwrites the file | unit | `pytest tests/test_visualizer.py::TestDrawTopology::test_overwrites_existing -x` | No — Wave 0 |
| VIZ-04 | `parse_cli_args()` accepts `--visualize` flag; default False | unit | `pytest tests/test_capture.py::TestParseCLIArgs::test_visualize_flag -x` | No — add to existing |
| LOG-01 | `generate_report()` returns dict with expected summary keys | unit | `pytest tests/test_reporter.py::TestGenerateReport::test_summary_keys -x` | No — Wave 0 |
| LOG-02 | CSV file is readable by `pd.read_csv()` without error | unit | `pytest tests/test_reporter.py::TestGenerateReport::test_csv_roundtrip -x` | No — Wave 0 |
| LOG-03 | `parse_cli_args()` accepts `--logfile`; `JSONLLogger` uses it | unit | `pytest tests/test_capture.py::TestParseCLIArgs::test_logfile_arg -x` | No — add to existing |

### Sampling Rate
- **Per task commit:** `python3 -m pytest tests/test_visualizer.py tests/test_reporter.py -x -q`
- **Per wave merge:** `python3 -m pytest tests/ -x -q`
- **Phase gate:** Full suite green (122 existing + new Phase 3 tests) before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/test_visualizer.py` — covers VIZ-01, VIZ-02, VIZ-03
- [ ] `tests/test_reporter.py` — covers LOG-01, LOG-02
- [ ] Add `test_visualize_flag` and `test_logfile_arg` test cases to existing `tests/test_capture.py`

*(No new framework install needed — pytest 9.0.3 already present)*

---

## Plan Decomposition Recommendation

Three micro-plans, each independently testable (RED → GREEN → refactor):

**Plan 03-01:** `visualizer.py` — implement `draw_topology()` + `tests/test_visualizer.py`
- `draw_topology()` fully implemented
- `save_final()` can delegate to `draw_topology()` (thin wrapper, kept for API compat)
- Tests use synthetic `pd.DataFrame` — no root, no network, no display

**Plan 03-02:** `reporter.py` — new module `generate_report()` + `tests/test_reporter.py`
- Pure pandas function, no network/root required
- Tests use `tmp_path` fixture (existing pattern in test_logger.py)

**Plan 03-03:** `main.py` + `capture.py` wiring — add CLI args + call sites
- Add `--visualize`, `--report`, `--logfile` to `parse_cli_args()` in `capture.py`
- Update `main.py`: pass `args.logfile` to `JSONLLogger`, add `spoofed_ips_set` and `events_list` accumulators, call `draw_topology()` on conflict, call `generate_report()` at shutdown
- Add two test cases to `tests/test_capture.py` for new args
- Update `tests/test_main.py` to patch new call sites

---

## Sources

### Primary (HIGH confidence)
- Verified by running against installed packages (networkx 3.6.1, matplotlib 3.10.8, pandas 3.0.2, pytest 9.0.3)
  - `from networkx.drawing.layout import bipartite_layout` — correct import path confirmed
  - `bipartite_layout(G, ip_nodes)` — returns position dict, works with isolated nodes
  - `nx.draw_networkx(G, pos=pos, ax=ax, node_color=[...])` — verified with Agg
  - `fig, ax = plt.subplots(); fig.savefig(); plt.close(fig)` — verified, no figure leaks
  - `pd.DataFrame(events).to_csv(); pd.read_csv()` round-trip — verified
  - `pd.DataFrame(columns=[...]).to_csv()` empty case — verified
  - `JSONLLogger(custom_path)` — already accepts path argument, no code change needed
  - argparse `action='store_true'` and `default=` patterns — verified

### Secondary (MEDIUM confidence)
- CONTEXT.md design decisions (bipartite layout choice, color scheme, off-by-default flag)
- Existing codebase patterns (pandas `.loc[]`, `tmp_path` fixture usage, `patch` in tests)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries installed, all patterns run and verified
- Architecture: HIGH — all integration points traced through existing code
- Pitfalls: HIGH — all identified by running the actual failure cases
- Test map: HIGH — maps directly to existing test infrastructure patterns

**Research date:** 2026-05-09
**Valid until:** 2026-06-09 (stable libraries, no fast-moving dependencies)
