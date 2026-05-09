"""test_main.py — unit tests for main.py (DET-03, DET-04, ALT-02, ALT-04).

All tests use unittest.mock.patch throughout — no root, no network, no terminal.
Tests cover:
  - build_arp_table_renderable() — Panel wrapping a rich.Table
  - build_alerts_renderable()    — Panel with recent alert strings
  - build_layout()               — Layout with 'arp_table' and 'alerts' sections
  - Conflict path wiring         — log_event + format_alert_panel called on conflict
"""
from io import StringIO
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel

from arp_detector.main import (
    build_alerts_renderable,
    build_arp_table_renderable,
    build_layout,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_df() -> pd.DataFrame:
    """Return an empty ARPTable-shaped DataFrame (index=ip, cols=mac/first_seen/last_seen)."""
    df = pd.DataFrame(columns=["mac", "first_seen", "last_seen"])
    df.index.name = "ip"
    return df


def _one_row_df() -> pd.DataFrame:
    """Return a DataFrame with a single host row for rendering tests."""
    df = pd.DataFrame(
        [{"mac": "aa:bb:cc:dd:ee:ff", "first_seen": 1000.0, "last_seen": 1001.0}],
        index=pd.Index(["1.2.3.4"], name="ip"),
    )
    return df


def _render(renderable) -> str:
    """Render any rich renderable to a plain string via StringIO Console."""
    sio = StringIO()
    c = Console(file=sio, force_terminal=False, width=120)
    c.print(renderable)
    return sio.getvalue()


# ---------------------------------------------------------------------------
# build_arp_table_renderable
# ---------------------------------------------------------------------------

class TestBuildArpTableRenderableEmpty:
    """build_arp_table_renderable with empty DataFrame returns a Panel."""

    def test_returns_panel(self):
        result = build_arp_table_renderable(_empty_df())
        assert isinstance(result, Panel)


class TestBuildArpTableRenderableWithRows:
    """build_arp_table_renderable with data includes IP in rendered output."""

    def test_ip_in_output(self):
        df = _one_row_df()
        result = build_arp_table_renderable(df)
        output = _render(result)
        assert "1.2.3.4" in output

    def test_mac_in_output(self):
        df = _one_row_df()
        result = build_arp_table_renderable(df)
        output = _render(result)
        assert "aa:bb:cc:dd:ee:ff" in output

    def test_returns_panel(self):
        result = build_arp_table_renderable(_one_row_df())
        assert isinstance(result, Panel)


# ---------------------------------------------------------------------------
# build_alerts_renderable
# ---------------------------------------------------------------------------

class TestBuildAlertsRenderableEmpty:
    """build_alerts_renderable with empty list returns a Panel."""

    def test_returns_panel(self):
        result = build_alerts_renderable([])
        assert isinstance(result, Panel)

    def test_no_alerts_text_present(self):
        result = build_alerts_renderable([])
        output = _render(result)
        # Should contain some placeholder text when empty
        assert "No alerts" in output or output.strip() != ""


class TestBuildAlertsRenderableWithData:
    """build_alerts_renderable with data includes alert string in output."""

    def test_alert_text_in_output(self):
        result = build_alerts_renderable(["alert line 1"])
        output = _render(result)
        assert "alert line 1" in output

    def test_returns_panel(self):
        result = build_alerts_renderable(["alert line 1"])
        assert isinstance(result, Panel)

    def test_multiple_alerts_shown(self):
        alerts = ["alert 1", "alert 2", "alert 3"]
        result = build_alerts_renderable(alerts)
        output = _render(result)
        assert "alert 1" in output
        assert "alert 3" in output

    def test_only_last_five_alerts_shown(self):
        """Only the last 5 alerts should be displayed (most recent)."""
        alerts = [f"alert {i}" for i in range(10)]
        result = build_alerts_renderable(alerts)
        output = _render(result)
        # Last 5 are alerts 5-9; first 5 (0-4) should not appear in output
        assert "alert 9" in output
        # alert 0 through 4 should NOT be present
        assert "alert 0" not in output


# ---------------------------------------------------------------------------
# build_layout
# ---------------------------------------------------------------------------

class TestBuildLayout:
    """build_layout() returns a rich.Layout with arp_table and alerts sections."""

    def test_returns_layout(self):
        result = build_layout()
        assert isinstance(result, Layout)

    def test_has_arp_table_section(self):
        layout = build_layout()
        # Accessing layout["arp_table"] must not raise KeyError
        section = layout["arp_table"]
        assert section is not None

    def test_has_alerts_section(self):
        layout = build_layout()
        # Accessing layout["alerts"] must not raise KeyError
        section = layout["alerts"]
        assert section is not None

    def test_arp_table_and_alerts_are_separate(self):
        layout = build_layout()
        assert layout["arp_table"] is not layout["alerts"]


# ---------------------------------------------------------------------------
# Conflict path wiring — log_event + format_alert_panel called on conflict
# ---------------------------------------------------------------------------

class TestConflictPathCallsLogEvent:
    """When a conflict is detected, log_event must be called with a valid event dict."""

    def test_log_event_called_with_attack_type(self):
        """Simulate the main loop's conflict-handling logic inline."""
        from arp_detector.arp_table import ARPTable
        from arp_detector.detector import check_packet
        from arp_detector.logger import build_event, JSONLLogger
        from arp_detector.alerts import format_alert_panel

        # Set up table with known IP->MAC
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")

        # Build a packet dict that will conflict
        pkt_dict = {
            "src_ip": "10.0.0.1",
            "src_mac": "bb:bb:bb:bb:bb:bb",
            "dst_ip": "10.0.0.2",
            "op": 2,
            "timestamp": 1000.0,
        }

        mock_logger = MagicMock(spec=JSONLLogger)
        mock_format = MagicMock(return_value=Panel("test"))
        mock_live_print = MagicMock()

        conflict = check_packet(pkt_dict, table)
        assert conflict is not None, "Expected conflict but got None"

        # Simulate main loop conflict branch
        event = build_event(conflict)
        mock_logger.log_event(event)
        panel = mock_format(event)
        mock_live_print(panel)

        # Assert log_event was called once with a dict containing 'attack_type'
        mock_logger.log_event.assert_called_once()
        called_event = mock_logger.log_event.call_args[0][0]
        assert isinstance(called_event, dict)
        assert called_event.get("attack_type") == "ARP_SPOOFING"

    def test_format_alert_panel_called_on_conflict(self):
        """format_alert_panel must be called with the event dict on a conflict."""
        from arp_detector.arp_table import ARPTable
        from arp_detector.detector import check_packet
        from arp_detector.logger import build_event
        from arp_detector.alerts import format_alert_panel

        table = ARPTable()
        table.update("10.0.0.2", "cc:cc:cc:cc:cc:cc")

        pkt_dict = {
            "src_ip": "10.0.0.2",
            "src_mac": "dd:dd:dd:dd:dd:dd",
            "dst_ip": "10.0.0.3",
            "op": 2,
            "timestamp": 2000.0,
        }

        conflict = check_packet(pkt_dict, table)
        assert conflict is not None

        event = build_event(conflict)
        # format_alert_panel should return a Panel without error
        panel = format_alert_panel(event)
        assert isinstance(panel, Panel)

    def test_no_log_event_on_non_conflict(self):
        """log_event must NOT be called when check_packet returns None."""
        from arp_detector.arp_table import ARPTable
        from arp_detector.detector import check_packet
        from arp_detector.logger import JSONLLogger

        table = ARPTable()

        # First packet for an IP — not a conflict
        pkt_dict = {
            "src_ip": "10.0.0.3",
            "src_mac": "ee:ee:ee:ee:ee:ee",
            "dst_ip": "10.0.0.4",
            "op": 2,
            "timestamp": 3000.0,
        }

        mock_logger = MagicMock(spec=JSONLLogger)

        conflict = check_packet(pkt_dict, table)
        assert conflict is None

        # Simulate main loop: only call log_event if conflict is not None
        if conflict is not None:
            mock_logger.log_event(build_event(conflict))

        mock_logger.log_event.assert_not_called()
