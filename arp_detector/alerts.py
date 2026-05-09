"""alerts.py — Rich console alert builder for the ARP spoofing detector.

Implements ALT-01: format_alert_panel() constructs a rich.Panel with a red
border containing all DET-05 event fields and returns it to the caller.

IMPORTANT: format_alert_panel() only builds and returns the Panel object.
It does NOT call Console().print() or live.console.print(). The caller
(main.py) is responsible for printing inside the Live context. Calling
Console().print() inside this function would corrupt the Live display.
"""

from rich.panel import Panel
from rich.text import Text


def format_alert_panel(event: dict) -> Panel:
    """Build a red rich.Panel containing all DET-05 alert fields.

    Takes a DET-05 event dict (produced by logger.build_event()) and returns
    a rich.Panel renderable. The caller (main.py) prints it via
    live.console.print() inside the Live context.

    Args:
        event: DET-05 event dict with keys:
            timestamp    — ISO 8601 string
            attacker_mac — MAC claiming the IP
            victim_ip    — IP being spoofed
            original_mac — legitimate MAC for the IP
            spoofed_mac  — same as attacker_mac per DET-05 spec
            attack_type  — constant "ARP_SPOOFING"

    Returns:
        rich.Panel with border_style="red" and a body showing all key fields.
    """
    body = Text()
    body.append("ATTACK DETECTED\n", style="bold red")
    body.append(f"  Time:         {event['timestamp']}\n")
    body.append(f"  Victim IP:    {event['victim_ip']}\n")
    body.append(f"  Original MAC: {event['original_mac']}\n")
    body.append(f"  Attacker MAC: {event['attacker_mac']}\n")
    body.append(f"  Type:         {event['attack_type']}\n")

    return Panel(body, title="[bold red]ARP SPOOFING[/]", border_style="red")
