"""main.py — Top-level entry point for the ARP Spoofing Detector.

Wires all Phase 2 components into a running detection system:
  - check_root()       → must be the first call (PITFALLS C1)
  - parse_cli_args()   → --iface argument
  - load_baseline()    → seeds ARPTable before sniffing starts (DET-02)
  - start_capture()    → AsyncSniffer puts dicts onto a Queue
  - rich.Live dashboard → Layout with ARP table + recent alerts (ALT-02)
  - Main loop          → Queue.get(timeout=0.1) → check_packet() → build_event()
                         → log_event() + format_alert_panel() (DET-03, DET-04)
  - Ctrl+C shutdown    → sniffer.stop() → logger.close() → session summary (ALT-04)

Requirements addressed:
  DET-02 — Baseline ARP table seeded from arp-scan before capture
  DET-03 — Conflict detection integrated in main loop
  DET-04 — Detected conflicts produce DET-05 event dicts
  ALT-02 — Rich Live dashboard with ARP table + alerts panels
  ALT-03 — Conflicts written to JSONL log via JSONLLogger
  ALT-04 — Session summary printed on shutdown

Usage::
    sudo python3 -m arp_detector.main --iface eth0
    # or let it auto-detect the interface
    sudo python3 -m arp_detector.main
"""
from __future__ import annotations

import queue
import sys
from datetime import datetime

import pandas as pd
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from arp_detector.alerts import format_alert_panel
from arp_detector.arp_table import ARPTable
from arp_detector.baseline import load_baseline
from arp_detector.capture import check_root, get_default_iface, parse_cli_args, start_capture
from arp_detector.detector import check_packet
from arp_detector.logger import JSONLLogger, build_event
from arp_detector.reporter import generate_report
from arp_detector.visualizer import draw_topology

__all__ = ["main", "build_layout", "build_arp_table_renderable", "build_alerts_renderable"]


def build_arp_table_renderable(df: pd.DataFrame) -> Panel:
    """Build a rich.Panel wrapping a rich.Table showing all known IP->MAC mappings.

    Args:
        df: DataFrame snapshot from ARPTable.get_all().
            Index is 'ip'; columns are 'mac', 'first_seen', 'last_seen'.

    Returns:
        rich.Panel with a cyan border, title "ARP Table", containing a rich.Table
        with columns: IP, MAC, First Seen, Last Seen.
    """
    table = Table(
        show_header=True,
        header_style="bold",
        expand=True,
    )
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("MAC", style="green", no_wrap=True)
    table.add_column("First Seen", no_wrap=True)
    table.add_column("Last Seen", no_wrap=True)

    for ip, row in df.iterrows():
        try:
            first = datetime.fromtimestamp(float(row["first_seen"])).strftime("%H:%M:%S")
        except (OSError, ValueError, OverflowError):
            first = str(row["first_seen"])
        try:
            last = datetime.fromtimestamp(float(row["last_seen"])).strftime("%H:%M:%S")
        except (OSError, ValueError, OverflowError):
            last = str(row["last_seen"])
        table.add_row(str(ip), str(row["mac"]), first, last)

    return Panel(table, title="[bold cyan]ARP Table[/]", border_style="cyan")


def build_alerts_renderable(recent_alerts: list) -> Panel:
    """Build a rich.Panel showing the most recent alert lines.

    Args:
        recent_alerts: List of alert strings accumulated during the session.
                       Only the last 5 entries are shown.

    Returns:
        rich.Panel with a red border, title "Recent Alerts".
        If the list is empty, shows a dim placeholder message.
    """
    if not recent_alerts:
        text = "[dim]No alerts yet[/dim]"
    else:
        text = "\n".join(recent_alerts[-5:])

    return Panel(text, title="[bold red]Recent Alerts[/]", border_style="red")


def build_layout() -> Layout:
    """Build the rich.Layout for the live dashboard.

    Creates a two-section vertical split:
      - 'arp_table' section (ratio 3) — ARP table display
      - 'alerts'    section (ratio 1) — recent alert lines

    Returns:
        rich.Layout instance with 'arp_table' and 'alerts' named sections.
    """
    layout = Layout()
    layout.split_column(
        Layout(name="arp_table", ratio=3),
        Layout(name="alerts", ratio=1),
    )
    return layout


def main() -> None:
    """Run the full ARP spoofing detection pipeline.

    Startup sequence:
      1. check_root()         — exit 1 if not root (must be FIRST)
      2. parse_cli_args()     — resolve --iface
      3. ARPTable()           — create in-memory table
      4. JSONLLogger()        — open log file
      5. load_baseline()      — seed table with arp-scan results
      6. start_capture()      — start AsyncSniffer → Queue
      7. Live dashboard loop  — read Queue, detect, log, alert
      8. Ctrl+C shutdown      — stop sniffer, close logger, print summary

    Threading contract (do not violate):
      - AsyncSniffer callback ONLY puts dicts onto packet_queue.
      - Main thread is the sole writer to ARPTable (no locks needed).
      - Queue.get(timeout=0.1) ensures the dashboard refreshes even with no traffic.
    """
    # Step 1 — must be first (PITFALLS C1)
    check_root()

    # Step 2 — parse CLI
    args = parse_cli_args()
    iface = args.iface if args.iface else get_default_iface()

    # Step 3 — create ARP table
    arp_table = ARPTable()

    # Step 4 — open logger before any events can occur
    logger = JSONLLogger(args.logfile)

    # Step 5 — seed table with baseline (must happen BEFORE start_capture)
    baseline_count = load_baseline(arp_table)
    print(f"[*] Baseline loaded: {baseline_count} host(s) seeded from arp-scan")

    # Step 6 — start packet capture
    packet_queue: queue.Queue = queue.Queue()
    sniffer = start_capture(iface, packet_queue)
    print(f"[*] Sniffer started on {iface}. Press Ctrl+C to stop.")

    # Step 7 — live dashboard + main detection loop
    layout = build_layout()
    console = Console()

    packets_seen: int = 0
    attacks_detected: int = 0
    attacker_macs: set = set()
    recent_alerts: list = []
    spoofed_ips_set: set = set()
    events_list: list = []

    # Seed the initial layout with empty renderables
    layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
    layout["alerts"].update(build_alerts_renderable(recent_alerts))

    try:
        with Live(layout, refresh_per_second=4, console=console) as live:
            while True:
                try:
                    pkt_dict = packet_queue.get(timeout=0.1)
                except queue.Empty:
                    # No packet — just refresh the dashboard
                    layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
                    continue

                # Process the packet in the main thread (single-writer contract)
                packets_seen += 1
                conflict = check_packet(pkt_dict, arp_table)

                if conflict is not None:
                    event = build_event(conflict)
                    attacks_detected += 1
                    attacker_macs.add(event["attacker_mac"])
                    recent_alerts.append(
                        f"[red]{event['timestamp']}[/] "
                        f"{event['victim_ip']} -> {event['attacker_mac']}"
                    )
                    # Log to file
                    logger.log_event(event)
                    # Track for report and visualization
                    spoofed_ips_set.add(event["victim_ip"])
                    events_list.append(event)
                    if args.visualize:
                        draw_topology(arp_table.get_all(), spoofed_ips=spoofed_ips_set)
                    # Print alert panel above the Live display (critical: use live.console)
                    live.console.print(format_alert_panel(event))

                # Refresh both dashboard sections
                layout["arp_table"].update(build_arp_table_renderable(arp_table.get_all()))
                layout["alerts"].update(build_alerts_renderable(recent_alerts))

    except KeyboardInterrupt:
        pass  # fall through to shutdown

    # Step 8 — graceful shutdown
    sniffer.stop()
    logger.close()
    generate_report(events_list, total_packets=packets_seen, output_path=args.report)
    if args.visualize and len(arp_table.get_all()) > 0:
        draw_topology(arp_table.get_all(), spoofed_ips=spoofed_ips_set)

    console.print("\n[bold]Session Summary[/bold]")
    console.print(f"  Packets seen:         {packets_seen}")
    console.print(f"  Attacks detected:     {attacks_detected}")
    console.print(f"  Unique attacker MACs: {len(attacker_macs)}")

    sys.exit(0)


if __name__ == "__main__":
    main()
