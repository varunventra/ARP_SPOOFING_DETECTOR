"""test_reporter.py — Unit tests for reporter.py (LOG-01, LOG-02).

Tests cover:
  - generate_report(): CSV creation from DET-05 event dicts
  - CSV round-trip: written file must be loadable by pd.read_csv()
  - Summary dict: total_packets, total_attacks, unique_attacker_macs keys and values
  - Empty events: no crash, CSV with column headers only, 0-row DataFrame
  - All tests use tmp_path pytest fixture — no root, no network, no hardcoded paths.
"""
import pandas as pd
import pytest
from arp_detector.reporter import generate_report


def _make_event(victim_ip="192.168.1.1", attacker_mac="de:ad:be:ef:00:01"):
    """Return a synthetic DET-05 event dict for use in tests."""
    return {
        "timestamp": "2026-05-09T10:00:00",
        "attacker_mac": attacker_mac,
        "victim_ip": victim_ip,
        "original_mac": "aa:bb:cc:dd:ee:ff",
        "spoofed_mac": attacker_mac,
        "attack_type": "ARP_SPOOFING",
    }


class TestGenerateReport:
    """Unit tests for generate_report(events, total_packets, output_path)."""

    def test_creates_csv_file(self, tmp_path):
        """generate_report() must create a file at output_path."""
        event1 = _make_event(victim_ip="192.168.1.1")
        event2 = _make_event(victim_ip="192.168.1.2")
        output = tmp_path / "r.csv"
        generate_report([event1, event2], total_packets=10, output_path=str(output))
        assert output.exists()

    def test_csv_roundtrip(self, tmp_path):
        """CSV written by generate_report() must be loadable by pd.read_csv()."""
        event1 = _make_event(victim_ip="192.168.1.1")
        event2 = _make_event(victim_ip="192.168.1.2")
        output = tmp_path / "r.csv"
        generate_report([event1, event2], total_packets=10, output_path=str(output))
        loaded_df = pd.read_csv(str(output))
        assert len(loaded_df) == 2

    def test_summary_keys(self, tmp_path):
        """Returned summary dict must have exactly the 3 expected keys."""
        event1 = _make_event()
        output = tmp_path / "keys.csv"
        _, summary = generate_report([event1], total_packets=5, output_path=str(output))
        assert "total_packets" in summary
        assert "total_attacks" in summary
        assert "unique_attacker_macs" in summary

    def test_summary_values(self, tmp_path):
        """Summary values must be correct: 2 events same MAC → attacks=2, unique_macs=1."""
        mac = "de:ad:be:ef:00:01"
        event1 = _make_event(victim_ip="192.168.1.1", attacker_mac=mac)
        event2 = _make_event(victim_ip="192.168.1.2", attacker_mac=mac)
        output = tmp_path / "values.csv"
        _, summary = generate_report([event1, event2], total_packets=10,
                                     output_path=str(output))
        assert summary["total_attacks"] == 2
        assert summary["unique_attacker_macs"] == 1
        assert summary["total_packets"] == 10

    def test_empty_events_no_crash(self, tmp_path):
        """generate_report([]) must not raise and must return a 0-row DataFrame."""
        output = tmp_path / "empty.csv"
        df, summary = generate_report([], total_packets=5, output_path=str(output))
        assert len(df) == 0
        assert output.exists()

    def test_empty_events_csv_is_loadable(self, tmp_path):
        """CSV from empty events must be loadable by pd.read_csv() without error."""
        output = tmp_path / "empty.csv"
        generate_report([], total_packets=5, output_path=str(output))
        loaded_df = pd.read_csv(str(output))
        # Must load without raising — shape check: 0 rows
        assert len(loaded_df) == 0

    def test_empty_events_csv_has_headers(self, tmp_path):
        """CSV from empty events must contain all 6 column headers."""
        output = tmp_path / "empty_headers.csv"
        generate_report([], total_packets=0, output_path=str(output))
        loaded_df = pd.read_csv(str(output))
        expected_columns = {
            "timestamp", "attacker_mac", "victim_ip",
            "original_mac", "spoofed_mac", "attack_type",
        }
        assert set(loaded_df.columns) == expected_columns

    def test_unique_attacker_macs_multiple(self, tmp_path):
        """3 events with 2 distinct attacker MACs → unique_attacker_macs == 2."""
        mac1 = "de:ad:be:ef:00:01"
        mac2 = "ca:fe:ba:be:00:02"
        events = [
            _make_event(victim_ip="192.168.1.1", attacker_mac=mac1),
            _make_event(victim_ip="192.168.1.2", attacker_mac=mac1),
            _make_event(victim_ip="192.168.1.3", attacker_mac=mac2),
        ]
        output = tmp_path / "multi.csv"
        _, summary = generate_report(events, total_packets=20, output_path=str(output))
        assert summary["unique_attacker_macs"] == 2
