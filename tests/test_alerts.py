"""test_alerts.py — unit tests for alerts.py (ALT-01).

All tests use a synthetic DET-05 event dict — no root, no terminal, no
Live context required. Panel rendering is tested via rich Console with
a StringIO backend so tests run in any environment.
"""
from io import StringIO

import pytest
from rich.console import Console
from rich.panel import Panel

from arp_detector.alerts import format_alert_panel


SAMPLE_EVENT = {
    'timestamp':    '2026-05-09T14:23:01.123456',
    'attacker_mac': 'bb:bb:bb:bb:bb:bb',
    'victim_ip':    '192.168.1.1',
    'original_mac': 'aa:aa:aa:aa:aa:aa',
    'spoofed_mac':  'bb:bb:bb:bb:bb:bb',
    'attack_type':  'ARP_SPOOFING',
}


def _render(panel) -> str:
    """Render a rich renderable to a plain string via StringIO Console."""
    sio = StringIO()
    c = Console(file=sio, force_terminal=False, width=120)
    c.print(panel)
    return sio.getvalue()


class TestPanelType:
    """format_alert_panel() must return a rich.Panel instance."""

    def test_returns_panel(self):
        result = format_alert_panel(SAMPLE_EVENT)
        assert isinstance(result, Panel)


class TestPanelStyle:
    """Panel must have the correct border style and title for visual recognition."""

    def test_border_style_red(self):
        panel = format_alert_panel(SAMPLE_EVENT)
        assert panel.border_style == "red"

    def test_title_contains_arp_spoofing(self):
        panel = format_alert_panel(SAMPLE_EVENT)
        assert "ARP SPOOFING" in str(panel.title)


class TestPanelBodyContent:
    """Panel body must contain all required DET-05 event fields when rendered."""

    def test_body_contains_victim_ip(self):
        panel = format_alert_panel(SAMPLE_EVENT)
        output = _render(panel)
        assert "192.168.1.1" in output

    def test_body_contains_attacker_mac(self):
        panel = format_alert_panel(SAMPLE_EVENT)
        output = _render(panel)
        assert "bb:bb:bb:bb:bb:bb" in output

    def test_body_contains_original_mac(self):
        panel = format_alert_panel(SAMPLE_EVENT)
        output = _render(panel)
        assert "aa:aa:aa:aa:aa:aa" in output

    def test_body_contains_timestamp(self):
        panel = format_alert_panel(SAMPLE_EVENT)
        output = _render(panel)
        assert "2026-05-09" in output
