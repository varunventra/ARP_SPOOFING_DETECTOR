# Phase 2: Detection Pipeline + Alerting - Research

**Researched:** 2026-05-09
**Domain:** Python detection pipeline wiring, rich console UI, JSONL logging, subprocess baseline seeding
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Gratuitous ARP filter (`psrc == pdst` guard) must be applied before table lookup
- DET-05 field set (timestamp, attacker_mac, victim_ip, original_mac, spoofed_mac, attack_type="ARP_SPOOFING") is the contract between detector and logger/alert — locked here
- Implement arp-scan baseline loader via subprocess (list-form args, no shell=True)
- rich console alerts: red Panel for conflicts, Live dashboard for ARP table + recent alerts
- JSONL logging: one JSON object per line, append mode, flush on each write
- Graceful shutdown: Ctrl+C → flush log → print session summary → exit 0

### Claude's Discretion
All implementation choices are at Claude's discretion — discuss phase was skipped per user setting. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

### Deferred Ideas (OUT OF SCOPE)
- `--verbose` flag for per-packet output (Phase 5 / nice-to-have)
- Email/SMS alerting (out of scope per PROJECT.md)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DET-02 | Bootstrap ARP table from `arp-scan --localnet` output via subprocess at startup | baseline.py section: subprocess list-form, parse IP/MAC from tab-split lines, skip header/footer |
| DET-03 | Detect IP-MAC conflict: ARP reply mapping an IP to a different MAC than the known table entry | detector.check_packet() already implements this via ARPTable.update() — Phase 2 wires the result |
| DET-04 | Filter gratuitous ARPs (`psrc == pdst`) to avoid false positives | Already implemented in detector.check_packet(); verified correct placement before table lookup |
| DET-05 | Record attack events with timestamp, attacker_mac, victim_ip, original_mac, spoofed_mac, attack_type | Event dict construction section — derives from conflict dict returned by check_packet() |
| ALT-01 | Colored rich console alert immediately on detection, including all DET-05 fields | alerts.py section: `Console().print(Panel(...))` with red border_style, called on each event |
| ALT-02 | Live-updating rich dashboard (rich `Live` + `Table`) showing ARP table + recent alerts | Live layout section: Layout with two panels, `live.update()` on each packet cycle |
| ALT-03 | Persistent JSONL log file (`arp_detector.log`), one JSON object per event | logger.py section: open in append mode, `json.dumps(event) + "\n"`, `f.flush()` after each write |
| ALT-04 | Graceful shutdown on Ctrl+C: flush log, print session summary, exit 0 | main.py shutdown section: KeyboardInterrupt → `logger.flush()` → console summary → `sys.exit(0)` |
</phase_requirements>

---

## Summary

Phase 2 wires five already-built pieces (ARPTable, check_packet, AsyncSniffer, Queue, parse_cli_args) into a running detection system that a user can observe in real time. There is no new algorithm work — the hard decisions (threading model, gratuitous ARP filter, pandas write contract) are locked from Phase 1. The work is: (1) a new `baseline.py` module that seeds the table before the sniffer starts, (2) implementing `alerts.py` and `logger.py` stubs, and (3) writing `main.py` as the top-level orchestrator that calls everything in the correct order.

The most technically nuanced part is the `rich.Live` layout. Rich's `Live` renders exactly one renderable on each refresh tick. The correct pattern for "ARP table + alerts panel" is to build a `rich.layout.Layout` object with named sections, update each section's content in the main loop, and pass the whole Layout to `Live`. This avoids flickering and keeps the terminal from scrolling. The `live.console.print()` method (not plain `Console().print()`) must be used for any out-of-band output inside the Live context so it appears above the live display rather than interleaving with it.

The JSONL logger and graceful shutdown are straightforward: open in append mode, write `json.dumps(event) + "\n"`, call `f.flush()` after each line. KeyboardInterrupt is caught in main loop, sniffer is stopped, logger is closed, summary is printed, process exits 0.

**Primary recommendation:** Build in this order — baseline.py → logger.py → alerts.py → main.py. Test each module in isolation before wiring. The live dashboard is the only component requiring a running terminal; test it last.

---

## Project Constraints (from CLAUDE.md)

Directives that must be honored in every task:

| Directive | Source |
|-----------|--------|
| Python 3.x + scapy + pandas + matplotlib/networkx + rich only — no alternative libraries | CLAUDE.md Tech Stack |
| arp-scan, tcpdump, awk, grep must be used as shell tools | CLAUDE.md Constraints |
| Target platform is Linux/WSL — not Windows-native | CLAUDE.md Constraints |
| All subprocess calls: list-form args, `capture_output=True`, `text=True`, `timeout=N`, no `shell=True` | CLAUDE.md Key Integration Points |
| pandas: `.loc[]` and `.at[]` only — never `.append()` (removed in pandas 2.0) | CLAUDE.md Python Libraries |
| Do NOT call `plt.show()` inside the packet callback or anywhere in the capture loop | CLAUDE.md What NOT to Use |
| Do NOT use `scapy.send()` or `scapy.sendp()` in the detector — detection only | CLAUDE.md What NOT to Use |
| Do NOT use colorama — use rich for all console output | CLAUDE.md What NOT to Use |
| AsyncSniffer callback only puts to Queue; main thread is sole writer to ARPTable | CLAUDE.md Key Integration Points / Phase 1 lock |
| matplotlib.use("Agg") is already set in visualizer.py — do not re-import pyplot without this guard | Phase 1 lock |
| `shell=True` is prohibited in all subprocess calls | CLAUDE.md / Phase 1 lock |

---

## Standard Stack

### Core (all already in requirements.txt)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| scapy | >=2.5.0 | AsyncSniffer, packet parsing | Course-specified; ARP layer API stable since 2.4 |
| pandas | >=2.1.0 | ARPTable DataFrame | Course-specified; already used in Phase 1 |
| rich | >=13.0.0 | Console alerts, Live dashboard, Tables | Course-specified; de facto Python CLI standard |
| Python stdlib `json` | stdlib | JSONL serialization | No external dep; `json.dumps()` is the correct tool |
| Python stdlib `logging` | stdlib | Session-level log formatting (optional) | Already in CLAUDE.md stack; stdlib |
| Python stdlib `subprocess` | stdlib | arp-scan invocation | Already in CLAUDE.md stack |
| Python stdlib `threading.Queue` | stdlib | Already used in capture.py | Locked pattern from Phase 1 |
| Python stdlib `datetime` | stdlib | ISO 8601 timestamp formatting | Standard; `datetime.fromtimestamp().isoformat()` |

No new packages need to be installed. All Phase 2 dependencies are already present.

---

## Architecture Patterns

### Module Layout After Phase 2

```
arp_detector/
├── __init__.py
├── arp_table.py      # Phase 1 — unchanged
├── capture.py        # Phase 1 — unchanged (start_capture, check_root, parse_cli_args)
├── detector.py       # Phase 1 — unchanged (check_packet)
├── baseline.py       # NEW — arp-scan subprocess wrapper, seeds ARPTable
├── alerts.py         # IMPLEMENT — rich Panel alert + Live dashboard state
├── logger.py         # IMPLEMENT — JSONL append log with flush
├── visualizer.py     # Phase 1 stub — untouched in Phase 2
└── main.py           # NEW — top-level entry point, full startup sequence
```

### Pattern 1: baseline.py — arp-scan subprocess wrapper (DET-02)

**What:** Run `arp-scan --localnet` via subprocess, parse tab-delimited output, call `table.update()` for each valid host line.

**When to use:** Called once at startup, before `start_capture()`. The table must be pre-populated so that the first ARP reply for a known host does not trigger a false positive.

**arp-scan output format (confirmed MEDIUM confidence — see sources):**
```
Interface: eth0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.1.1
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1     aa:bb:cc:dd:ee:01    Cisco Systems, Inc
192.168.1.5     aa:bb:cc:dd:ee:05    (Unknown)
192.168.1.10    aa:bb:cc:dd:ee:0a    VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 1.234 seconds (207.45 hosts/sec). 3 responded
```

Fields are separated by **tab characters** (`\t`). Header lines start with `Interface:`, `Starting`, or `Ending`. Footer lines contain `packets received` or `Ending`. Data lines have `parts[0]` = IP, `parts[1]` = MAC (after `line.split('\t')`).

**Detection pattern for valid data lines:** `len(parts) >= 2` and `parts[0]` matches a bare IP address (contains dots, no spaces). Using `re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0])` is the safe guard.

**Example:**
```python
# Source: CLAUDE.md subprocess pattern + arp-scan man page
import subprocess
import re
from arp_detector.arp_table import ARPTable

_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

def load_baseline(table: ARPTable, timeout: int = 30) -> int:
    """Run arp-scan --localnet and seed table. Returns count of hosts loaded."""
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print("[WARN] arp-scan not found — skipping baseline seeding", file=sys.stderr)
        return 0
    except subprocess.TimeoutExpired:
        print("[WARN] arp-scan timed out — partial baseline may be loaded", file=sys.stderr)
        return 0

    count = 0
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) >= 2 and _IP_RE.match(parts[0]):
            ip = parts[0].strip()
            mac = parts[1].strip()
            table.update(ip, mac)
            count += 1
    return count
```

**Failure mode:** `arp-scan` not installed → `FileNotFoundError`. Handle with try/except and warn; do not crash. The tool can still run without baseline (just with a higher false-positive risk on first packet).

**Requires root:** `arp-scan --localnet` requires root. Since Phase 1's `check_root()` is called first, this is guaranteed by the time `load_baseline()` is called.

---

### Pattern 2: DET-05 event dict construction

**What:** When `check_packet()` returns a conflict dict, transform it into the full DET-05 event dict. This is done in `main.py` after calling `check_packet()`, before calling `alerts.alert_conflict()` and `logger.log_event()`.

**Conflict dict from check_packet() (Phase 1 contract):**
```python
{'ip': str, 'known_mac': str, 'new_mac': str, 'timestamp': float}
```

**DET-05 event dict (locked field set from CONTEXT.md):**
```python
{
    'timestamp':    str,   # ISO 8601 string — datetime.fromtimestamp(ts).isoformat()
    'attacker_mac': str,   # conflict['new_mac']   — the MAC making the false claim
    'victim_ip':    str,   # conflict['ip']        — the IP being spoofed
    'original_mac': str,   # conflict['known_mac'] — the legitimate MAC
    'spoofed_mac':  str,   # conflict['new_mac']   — same as attacker_mac (redundant but spec'd)
    'attack_type':  str,   # always "ARP_SPOOFING"
}
```

**Rationale for `attacker_mac` == `spoofed_mac`:** The spec lists both. They are the same value (`new_mac`). Both fields are included to satisfy the spec; consumers can use whichever is clearer.

**Construction helper:**
```python
# Source: CONTEXT.md DET-05 spec
from datetime import datetime

def build_event(conflict: dict) -> dict:
    return {
        'timestamp':    datetime.fromtimestamp(conflict['timestamp']).isoformat(),
        'attacker_mac': conflict['new_mac'],
        'victim_ip':    conflict['ip'],
        'original_mac': conflict['known_mac'],
        'spoofed_mac':  conflict['new_mac'],
        'attack_type':  'ARP_SPOOFING',
    }
```

---

### Pattern 3: logger.py — JSONL append with immediate flush (ALT-03)

**What:** Open log file in append mode at startup, write one JSON line per event, flush immediately so the file is readable with `cat` between events.

**Why not use Python's `logging` module for JSONL:** `logging` uses structured text formatting. For JSONL (machine-parseable structured records), `json.dumps()` + `f.flush()` is simpler, more direct, and avoids handler configuration complexity. The `logging` stdlib is appropriate for the session-level human-readable log if desired, but the JSONL output path must bypass it.

**Design:** Logger holds an open file handle (opened in `__init__` or `open()` call at startup). `log_event()` writes and flushes. `flush()` and `close()` are called on shutdown.

```python
# Source: standard Python JSONL pattern — MEDIUM confidence (no Context7 entry for stdlib json)
import json
import sys
from pathlib import Path

class JSONLLogger:
    def __init__(self, path: str = "arp_detector.log"):
        self._path = path
        self._fh = open(path, "a", encoding="utf-8")

    def log_event(self, event: dict) -> None:
        """Append one JSON line and flush immediately."""
        self._fh.write(json.dumps(event) + "\n")
        self._fh.flush()

    def flush(self) -> None:
        """Explicit flush — call before shutdown."""
        self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()
```

**Module-level API:** The existing `logger.py` stub has module-level functions `log_event()` and `flush()`. Two approaches are valid:

1. **Class-based (recommended):** `JSONLLogger` instance created in `main.py`, passed to alerts/logger functions. Cleaner to test; allows `--logfile` override (Phase 3 requirement).
2. **Module-level singleton:** Module holds `_logger: JSONLLogger | None` initialized on first call. Simpler but harder to test with custom paths.

**Recommendation:** Use the class-based approach. The module-level stub functions can wrap the instance for backward compatibility. This also makes `--logfile` (Phase 3 LOG-03) trivial to add.

---

### Pattern 4: alerts.py — rich Panel alert + Live dashboard state (ALT-01, ALT-02)

**What:** Two separate responsibilities — (A) one-shot console alert when a spoofing event fires, and (B) maintaining the state of the Live dashboard.

#### 4A: One-shot console alert (ALT-01)

`rich.Panel` with `border_style="red"` prints a single framed alert. Inside a `Live` context, use `live.console.print()` rather than `Console().print()` to ensure the output appears above the live display without interrupting it.

```python
# Source: rich 13.x docs — HIGH confidence
from rich.panel import Panel
from rich.text import Text

def format_alert_panel(event: dict) -> Panel:
    """Build a red Panel renderable for a detected spoofing event."""
    body = Text()
    body.append("ATTACK DETECTED\n", style="bold red")
    body.append(f"  Time:         {event['timestamp']}\n")
    body.append(f"  Victim IP:    {event['victim_ip']}\n")
    body.append(f"  Original MAC: {event['original_mac']}\n")
    body.append(f"  Attacker MAC: {event['attacker_mac']}\n")
    body.append(f"  Type:         {event['attack_type']}\n")
    return Panel(body, title="[bold red]ARP SPOOFING[/]", border_style="red")
```

**Critical:** Inside `Live` context, alerts must be printed via `live.console.print(panel)`, NOT a separate `Console().print(panel)`. Using a second Console while Live owns the terminal produces interleaved/corrupted output.

#### 4B: Live dashboard (ALT-02)

**rich.Live + rich.Layout approach (recommended):**

`Layout` is the correct composable container for a two-panel dashboard. Split vertically into `"arp_table"` section and `"alerts"` section. Each refresh tick, rebuild the Table from `arp_table.get_all()` and update the alerts section with the last N alert strings.

```python
# Source: rich 14.x layout docs (stable API, unchanged from 13.x)
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

def build_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="arp_table", ratio=3),
        Layout(name="alerts", ratio=1),
    )
    return layout

def build_arp_table_renderable(df) -> Panel:
    """Build a rich Table from the ARPTable DataFrame snapshot."""
    table = Table(title="ARP Table", show_header=True, header_style="bold cyan")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="green")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    for ip, row in df.iterrows():
        from datetime import datetime
        first = datetime.fromtimestamp(row['first_seen']).strftime('%H:%M:%S')
        last  = datetime.fromtimestamp(row['last_seen']).strftime('%H:%M:%S')
        table.add_row(ip, row['mac'], first, last)
    return Panel(table, title="[bold cyan]ARP Table[/]", border_style="cyan")

def build_alerts_renderable(recent_alerts: list[str]) -> Panel:
    """Build a Panel showing the last N alert lines."""
    text = "\n".join(recent_alerts[-5:]) if recent_alerts else "[dim]No alerts yet[/dim]"
    return Panel(text, title="[bold red]Recent Alerts[/]", border_style="red")
```

**Update pattern in main loop:**
```python
# Inside the main loop, after processing each packet:
layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
layout["alerts"].update(build_alerts_renderable(recent_alerts))
live.refresh()
```

**Why Layout over a raw Group/Columns:** Layout allows ratio-based height splitting (arp table gets 3/4, alerts get 1/4 of terminal height). Without Layout, a tall ARP table will push the alerts panel off screen.

---

### Pattern 5: main.py — startup sequence wiring (ALT-04)

**Startup sequence (locked):**
```
1. check_root()              # capture.check_root() — exit(1) if not root
2. parse_cli_args()          # capture.parse_cli_args() — gets --iface, --logfile
3. iface resolution          # args.iface or capture.get_default_iface()
4. logger = JSONLLogger(...)  # open log file BEFORE sniffer starts
5. baseline.load_baseline()  # seed ARPTable before sniffer; arp-scan subprocess
6. packet_queue = Queue()
7. sniffer = start_capture() # AsyncSniffer starts; callback puts to queue
8. layout = build_layout()
9. with Live(layout, ...) as live:
       main_loop(...)        # queue.get(timeout=0.1) loop
```

**Main loop structure:**
```python
# Source: capture.py Phase 1 pattern + Phase 2 additions
packets_seen = 0
attacks_detected = 0
attacker_macs: set[str] = set()
recent_alerts: list[str] = []

try:
    with Live(layout, refresh_per_second=4, console=Console()) as live:
        while True:
            try:
                pkt_dict = packet_queue.get(timeout=0.1)
            except queue.Empty:
                # Refresh dashboard even when no new packets arrive
                layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
                live.refresh()
                continue

            packets_seen += 1
            conflict = check_packet(pkt_dict, arp_table)

            if conflict is not None:
                event = build_event(conflict)
                attacks_detected += 1
                attacker_macs.add(event['attacker_mac'])
                recent_alerts.append(
                    f"[red]{event['timestamp']}[/] {event['victim_ip']} → {event['attacker_mac']}"
                )
                logger.log_event(event)
                live.console.print(format_alert_panel(event))  # above Live display

            # Update dashboard on every packet (not just on conflict)
            layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
            layout["alerts"].update(build_alerts_renderable(recent_alerts))

except KeyboardInterrupt:
    pass  # fall through to shutdown
```

**Graceful shutdown:**
```python
# Source: CONTEXT.md ALT-04 spec
sniffer.stop()
logger.close()          # flush + close file handle
console = Console()
console.print("\n[bold]Session Summary[/bold]")
console.print(f"  Packets seen:        {packets_seen}")
console.print(f"  Attacks detected:    {attacks_detected}")
console.print(f"  Unique attacker MACs: {len(attacker_macs)}")
sys.exit(0)
```

---

### Anti-Patterns to Avoid

- **Calling `Console().print()` inside a `Live` context:** Creates a second console; output interleaves with the Live display. Always use `live.console.print()` for alerts inside the loop.
- **Calling `arp_table.update()` from the AsyncSniffer callback:** Violates the single-writer contract locked in Phase 1. The callback must only `queue.put()`.
- **Opening the log file inside `log_event()`:** Re-opens on each call. Open once in `__init__` / startup, keep file handle open, flush after each write.
- **Calling `live.update()` with a new Layout on every packet:** Rebuilds the Layout object each tick. Instead, update the sections of the existing Layout in-place (`layout["section"].update(new_renderable)`).
- **Checking gratuitous ARP inside the callback (instead of `check_packet()`):** The Phase 1 architecture places this filter in `detector.check_packet()`. The callback must remain pure queue-put. Do not add `if pkt[ARP].psrc == pkt[ARP].pdst: return` to the callback.
- **`shell=True` in any subprocess call:** Prohibited (security + testability). Always pass a list.
- **Not handling `FileNotFoundError` on arp-scan:** On machines where arp-scan is not installed, the tool would crash at startup without this guard.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Colored terminal output | Manual ANSI escape codes | `rich.Panel`, `rich.Text` with styles | rich handles terminal width, nesting, markup escaping |
| Live-refreshing terminal display | `os.system("clear")` + reprint loop | `rich.Live` with `Layout` | Avoids flicker, handles terminal resize, thread-safe refresh |
| JSON serialization | Custom string formatting | `json.dumps()` | Handles escaping, unicode, nested structures correctly |
| Subprocess output parsing | Shell pipeline (`awk`, `grep` in shell=True) | List-form `subprocess.run()` + Python string parsing | Testable, no shell injection risk, no shell=True |
| IP address format validation in arp-scan parsing | No validation (trust raw output) | `re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', ...)` | arp-scan header/footer lines contain non-IP strings that would crash `table.update()` |

---

## Common Pitfalls

### Pitfall 1: arp-scan output header/footer lines corrupt the table

**What goes wrong:** `arp-scan --localnet` prints 2–3 header lines (`Interface:`, `Starting arp-scan...`) and 2 footer lines (`N packets received`, `Ending arp-scan...`) that are not tab-delimited IP/MAC pairs. Naively splitting every line by `\t` and calling `table.update(parts[0], parts[1])` will call `update("Interface:", ...)` or crash on `IndexError`.

**Why it happens:** The output is designed for human readers, not machine parsing. Only the data lines are tab-separated with IP in column 0.

**How to avoid:** Guard with `_IP_RE.match(parts[0])` before calling `table.update()`. Regex `r'^\d{1,3}(?:\.\d{1,3}){3}$'` matches only bare IPv4 addresses.

**Warning signs:** `ARPTable` contains entries with keys like `"Interface:"` or `"Starting"` after `load_baseline()`.

---

### Pitfall 2: `Console().print()` inside `Live` context causes display corruption

**What goes wrong:** Creating a second `Console` instance while `Live` is active causes both to write to stdout independently. The result is interleaved lines, broken ANSI sequences, and the Live display not clearing properly.

**Why it happens:** `Live` takes ownership of the terminal output stream via its internal `Console`. A second `Console()` created independently doesn't know about the Live display and writes directly.

**How to avoid:** Always use `live.console.print(...)` for any console output inside the `with Live(...) as live:` block.

**Warning signs:** Terminal output looks garbled or the table re-prints instead of updating in place during attacks.

---

### Pitfall 3: Queue.get() without timeout blocks Ctrl+C on some platforms

**What goes wrong:** `queue.get()` (no timeout) blocks the main thread indefinitely waiting for a packet. On Linux, `KeyboardInterrupt` can be delayed or lost when the thread is blocked in a C extension wait (Python's GIL behavior with blocking syscalls).

**Why it happens:** Python signal handlers only run between bytecodes. A thread blocked in `queue.get()` with no timeout may not check for signals.

**How to avoid:** Always use `queue.get(timeout=0.1)` and handle `queue.Empty` with `continue`. This pattern is already established in `capture.py`'s Phase 1 stub — do not change it.

**Warning signs:** Ctrl+C does nothing; user has to kill the process with `kill -9`.

---

### Pitfall 4: arp-scan not available at test time

**What goes wrong:** Tests for `baseline.py` that call the real `arp-scan` binary fail in CI, on non-root environments, or on machines where arp-scan is not installed.

**Why it happens:** `load_baseline()` shells out to a system binary.

**How to avoid:** Tests must mock `subprocess.run` with a fixture string representing realistic `arp-scan` output (including header and footer lines). The test verifies parsing logic, not the binary. A fixture string is sufficient:
```python
MOCK_ARP_SCAN_OUTPUT = (
    "Interface: eth0, type: EN10MB, MAC: aa:bb:cc:00:00:01, IPv4: 192.168.1.1\n"
    "Starting arp-scan 1.9.7 with 256 hosts\n"
    "192.168.1.1\taa:bb:cc:dd:ee:01\tCisco Systems\n"
    "192.168.1.5\taa:bb:cc:dd:ee:05\t(Unknown)\n"
    "\n"
    "2 packets received by filter, 0 dropped\n"
)
```

---

### Pitfall 5: `live.refresh()` called on every packet at high packet rate

**What goes wrong:** During a sustained ARP storm (attacker sends hundreds of spoofed packets/sec), calling `live.refresh()` on every packet pegs the CPU on terminal rendering and may cause the sniffer queue to back up.

**Why it happens:** `rich.Live` with `auto_refresh=True` (default) already refreshes at `refresh_per_second` (default 4 Hz). Calling `live.refresh()` manually on every packet adds overhead on top of this.

**How to avoid:** Let `auto_refresh=True` handle the refresh cadence. Only call `live.update()` / section updates to mutate the renderable state; let the auto-refresh timer do the actual terminal write. In `queue.Empty` branches (no new packets), manual `live.refresh()` is fine since it's infrequent.

---

## Code Examples

### Complete DET-05 event dict construction

```python
# Source: CONTEXT.md DET-05 spec (locked field set)
from datetime import datetime

def build_event(conflict: dict) -> dict:
    """Transform ARPTable conflict dict → DET-05 event dict."""
    return {
        'timestamp':    datetime.fromtimestamp(conflict['timestamp']).isoformat(),
        'attacker_mac': conflict['new_mac'],
        'victim_ip':    conflict['ip'],
        'original_mac': conflict['known_mac'],
        'spoofed_mac':  conflict['new_mac'],   # same as attacker_mac per spec
        'attack_type':  'ARP_SPOOFING',
    }
```

### JSONLLogger class

```python
# Source: standard Python append-mode file I/O + json stdlib
import json

class JSONLLogger:
    def __init__(self, path: str = "arp_detector.log"):
        self._fh = open(path, "a", encoding="utf-8")

    def log_event(self, event: dict) -> None:
        self._fh.write(json.dumps(event) + "\n")
        self._fh.flush()   # immediate flush — file readable between events

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()
```

### baseline.py load_baseline()

```python
# Source: CLAUDE.md subprocess pattern + arp-scan man page output format
import re
import subprocess
import sys
from arp_detector.arp_table import ARPTable

_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

def load_baseline(table: ARPTable, timeout: int = 30) -> int:
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        print("[WARN] arp-scan not found — skipping baseline", file=sys.stderr)
        return 0
    except subprocess.TimeoutExpired:
        print("[WARN] arp-scan timed out — partial baseline", file=sys.stderr)
        return 0
    count = 0
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) >= 2 and _IP_RE.match(parts[0].strip()):
            table.update(parts[0].strip(), parts[1].strip())
            count += 1
    return count
```

### rich.Live layout with two sections

```python
# Source: rich 13.x/14.x Layout + Live docs
from rich.layout import Layout
from rich.live import Live
from rich.console import Console

def build_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="arp_table", ratio=3),
        Layout(name="alerts", ratio=1),
    )
    return layout

# Usage:
layout = build_layout()
console = Console()
with Live(layout, refresh_per_second=4, console=console) as live:
    # Inside loop — update sections in place:
    layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
    layout["alerts"].update(build_alerts_renderable(recent_alerts))
    # Alert outside Live (prints above display):
    live.console.print(format_alert_panel(event))
```

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (already used in Phase 1 — 28 tests passing) |
| Config file | None — no pytest.ini, setup.cfg, or pyproject.toml found |
| Quick run command | `pytest tests/ -x -q` |
| Full suite command | `pytest tests/ -v` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DET-02 | `load_baseline()` parses arp-scan output and seeds ARPTable | unit | `pytest tests/test_baseline.py -x` | Wave 0 |
| DET-02 | `load_baseline()` handles missing arp-scan binary gracefully (no crash) | unit | `pytest tests/test_baseline.py -x -k "not_found"` | Wave 0 |
| DET-02 | `load_baseline()` skips header/footer lines, only seeds valid IP lines | unit | `pytest tests/test_baseline.py -x -k "header_footer"` | Wave 0 |
| DET-03 | conflict returned when same IP seen with different MAC | unit | `pytest tests/test_detector.py -x` (existing — covers this) | Exists |
| DET-04 | gratuitous ARP (psrc==pdst) returns None and does not seed table | unit | `pytest tests/test_detector.py -x` (existing — covers this) | Exists |
| DET-05 | `build_event()` produces dict with all 6 required keys | unit | `pytest tests/test_main.py -x -k "event"` | Wave 0 |
| DET-05 | `build_event()` timestamp is ISO 8601 string | unit | `pytest tests/test_main.py -x -k "timestamp"` | Wave 0 |
| ALT-01 | `format_alert_panel()` returns a `rich.Panel` instance | unit | `pytest tests/test_alerts.py -x -k "panel"` | Wave 0 |
| ALT-01 | alert panel contains victim_ip, attacker_mac, original_mac fields | unit | `pytest tests/test_alerts.py -x` | Wave 0 |
| ALT-03 | `JSONLLogger.log_event()` appends one valid JSON line per call | unit | `pytest tests/test_logger.py -x` | Wave 0 |
| ALT-03 | Written lines are parseable with `json.loads()` | unit | `pytest tests/test_logger.py -x -k "parseable"` | Wave 0 |
| ALT-03 | File is not empty immediately after `log_event()` (flush verified) | unit | `pytest tests/test_logger.py -x -k "flush"` | Wave 0 |
| ALT-04 | `close()` flushes and closes file handle without error | unit | `pytest tests/test_logger.py -x -k "close"` | Wave 0 |
| ALT-02 | Live dashboard renders without error with empty ARPTable | manual/smoke | `sudo python3 -m arp_detector.main --iface lo` | N/A |

### Sampling Rate

- **Per task commit:** `pytest tests/ -x -q`
- **Per wave merge:** `pytest tests/ -v`
- **Phase gate:** Full suite green (all 28 existing + new Phase 2 tests) before `/gsd:verify-work`

### Wave 0 Gaps (test files to create before implementation)

- [ ] `tests/test_baseline.py` — covers DET-02 (mock subprocess.run with fixture output)
- [ ] `tests/test_logger.py` — covers ALT-03, ALT-04 (uses `tmp_path` pytest fixture for log file)
- [ ] `tests/test_alerts.py` — covers ALT-01 (format_alert_panel returns Panel, contains required fields)
- [ ] `tests/test_main.py` — covers DET-05 build_event() dict shape and timestamp format

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.x | Runtime | Assumed present (Phase 1 complete) | 3.x | — |
| scapy | AsyncSniffer capture | Assumed present (Phase 1 28 tests pass) | >=2.5.0 | — |
| pandas | ARPTable | Assumed present (Phase 1 complete) | >=2.1.0 | — |
| rich | Console alerts, Live | In requirements.txt | >=13.0.0 | — |
| arp-scan | DET-02 baseline seeding | Unknown — must check on target machine | unknown | Warn and skip baseline; tool continues without pre-seeding |
| Linux/WSL | Raw socket capture | Target platform per CLAUDE.md | — | — |

**Note on arp-scan:** The tool is a system binary (`apt install arp-scan` on Ubuntu/Debian). It is NOT a Python package and is not in requirements.txt. `load_baseline()` must handle its absence gracefully. For the graded demo environment, the operator should verify it is installed. The Phase 4 shell script (`baseline_scan.sh`) also depends on it.

**Missing dependencies with fallback:**
- `arp-scan` binary: missing → `load_baseline()` prints warning and returns 0; sniffer still starts; baseline table is empty (first ARP reply for any IP is treated as first-seen, no false positive). This is an acceptable degraded mode for the demo.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `DataFrame.append()` | `df.loc[ip] = [...]` | pandas 2.0 (2023) | `.append()` raises AttributeError in pandas 2.x — already handled in Phase 1 |
| `colorama` for colored output | `rich.Panel` / `rich.Text` | rich gained dominance ~2021 | colorama is prohibited per CLAUDE.md |
| `threading.Lock` on shared DataFrame | Single-writer contract (main thread only) | Phase 1 architectural decision | No locks needed; callback only queues |
| `plt.show()` for visualization | `matplotlib.use("Agg")` + `savefig()` | Phase 1 architectural decision | `plt.show()` blocks callback; Agg is already set in visualizer.py |

---

## Open Questions

1. **arp-scan binary availability on demo machine**
   - What we know: `arp-scan` is a system binary, not a Python package; not confirmed installed in the target WSL environment
   - What's unclear: Whether it requires separate `apt install arp-scan` before the demo
   - Recommendation: `load_baseline()` must not crash if absent (FileNotFoundError guard). Include a note in demo checklist: `sudo apt install arp-scan` before demo day.

2. **Whether `live.console.print()` flushes the terminal before the Live display redraws**
   - What we know: Rich docs say `live.console.print()` renders above the Live display
   - What's unclear: Exact timing — whether the alert panel is visible for a full refresh cycle before being scrolled above the display
   - Recommendation: Acceptable for demo purposes. If the alert disappears too quickly, add `recent_alerts` display in the dashboard (already planned).

3. **arp-scan output format on the specific lab machine's version**
   - What we know: Tab-separated IP/MAC/Vendor is the documented format (MEDIUM confidence)
   - What's unclear: Whether Ubuntu 22.04's packaged arp-scan version has any deviations
   - Recommendation: Test `arp-scan --localnet` manually on the lab machine before integration. The `_IP_RE` guard handles unexpected lines safely.

---

## Sources

### Primary (HIGH confidence)
- CLAUDE.md — full tech stack, subprocess patterns, threading model, prohibited libraries
- `arp_detector/capture.py` (Phase 1) — threading model, Queue pattern, check_root(), parse_cli_args(), build_packet_callback()
- `arp_detector/detector.py` (Phase 1) — check_packet(), conflict dict shape, gratuitous ARP filter
- `arp_detector/arp_table.py` (Phase 1) — ARPTable.update() return contract, conflict dict fields
- `.planning/phases/02-detection-pipeline-alerting/02-CONTEXT.md` — DET-05 field set, all locked decisions
- `.planning/ROADMAP.md` Phase 2 section — success criteria, key decisions

### Secondary (MEDIUM confidence)
- [Live Display — Rich 14.1.0 documentation](https://rich.readthedocs.io/en/latest/live.html) — `Live` constructor params, `live.console.print()`, `live.update()`, `refresh_per_second`
- [Layout — Rich 14.1.0 documentation](https://rich.readthedocs.io/en/stable/layout.html) — `Layout.split_column()`, named sections, `layout["section"].update()`
- [arp-scan User Guide (GitHub wiki)](https://github.com/royhills/arp-scan/wiki/arp-scan-User-Guide) — tab-separated output format, header/footer line content
- [arp-scan man page (Ubuntu Manpages)](https://manpages.ubuntu.com/manpages/jammy/man1/arp-scan.1.html) — output format confirmation

### Tertiary (LOW confidence)
- WebSearch results for JSONL append pattern — verified against stdlib `json` module behavior (standard; LOW only because no official stdlib doc URL fetched)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries are Phase 1 carry-overs; requirements.txt confirmed
- Architecture (baseline.py, logger.py, main.py wiring): HIGH — derived from Phase 1 locked patterns
- rich.Live + Layout API: MEDIUM-HIGH — confirmed via official docs fetch; 14.x docs match 13.x API
- arp-scan output format: MEDIUM — documented format, but lab machine version not verified hands-on
- Pitfalls: HIGH — all derived from Phase 1 architecture decisions or known Python/rich behavior

**Research date:** 2026-05-09
**Valid until:** 2026-06-09 (stable libraries; rich and pandas APIs unlikely to change within 30 days)
