"""test_logger.py — Unit tests for logger.py (DET-05, ALT-03, ALT-04).

Tests cover:
  - JSONLLogger: one-line-per-event JSONL writes with immediate flush
  - build_event(): locked DET-05 event dict mapping from conflict dict
  - All tests use tmp_path pytest fixture — no root, no network, no hardcoded paths.
"""
import json
import pytest
from arp_detector.logger import JSONLLogger, build_event


# ---------------------------------------------------------------------------
# JSONLLogger tests
# ---------------------------------------------------------------------------

class TestLogEvent:
    """JSONLLogger.log_event() must write exactly one JSON line per call."""

    def test_log_event_appends_one_line(self, tmp_path):
        """Single log_event call produces exactly one line in the file."""
        log_path = tmp_path / "test.log"
        logger = JSONLLogger(str(log_path))
        event = {"timestamp": "2026-05-09T00:00:00", "msg": "test"}
        logger.log_event(event)
        logger.close()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1

    def test_log_event_valid_json(self, tmp_path):
        """The written line must be parseable by json.loads() and match the input dict."""
        log_path = tmp_path / "test.log"
        logger = JSONLLogger(str(log_path))
        event = {"timestamp": "2026-05-09T00:00:00", "attacker_mac": "aa:bb:cc:dd:ee:ff"}
        logger.log_event(event)
        logger.close()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        parsed = json.loads(lines[0])
        assert parsed == event

    def test_log_event_flushed_immediately(self, tmp_path):
        """After log_event(), file content must be readable without calling close() first."""
        log_path = tmp_path / "test.log"
        logger = JSONLLogger(str(log_path))
        event = {"timestamp": "2026-05-09T00:00:00", "msg": "flush-test"}
        logger.log_event(event)
        # Read using a fresh file handle — proves flush() was called inside log_event()
        content = log_path.read_text(encoding="utf-8")
        assert content.strip() != ""
        logger.close()

    def test_two_events_two_lines(self, tmp_path):
        """Two log_event calls produce exactly two parseable lines."""
        log_path = tmp_path / "test.log"
        logger = JSONLLogger(str(log_path))
        event1 = {"timestamp": "2026-05-09T00:00:01", "seq": 1}
        event2 = {"timestamp": "2026-05-09T00:00:02", "seq": 2}
        logger.log_event(event1)
        logger.log_event(event2)
        logger.close()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0]) == event1
        assert json.loads(lines[1]) == event2


class TestClose:
    """JSONLLogger.close() must leave the file handle in a closed state."""

    def test_close_no_error(self, tmp_path):
        """close() must not raise any exception."""
        log_path = tmp_path / "test.log"
        logger = JSONLLogger(str(log_path))
        event = {"timestamp": "2026-05-09T00:00:00", "msg": "close-test"}
        logger.log_event(event)
        logger.close()  # must not raise

    def test_close_file_handle_closed(self, tmp_path):
        """After close(), logger._fh.closed must be True."""
        log_path = tmp_path / "test.log"
        logger = JSONLLogger(str(log_path))
        logger.log_event({"timestamp": "2026-05-09T00:00:00"})
        logger.close()
        assert logger._fh.closed is True


# ---------------------------------------------------------------------------
# build_event() tests — DET-05 contract
# ---------------------------------------------------------------------------

SAMPLE_CONFLICT = {
    'ip': '1.2.3.4',
    'known_mac': 'aa:bb:cc:dd:ee:ff',
    'new_mac': 'ff:ee:dd:cc:bb:aa',
    'timestamp': 1000.0,
}


class TestBuildEventKeys:
    """build_event() must return a dict with exactly the 6 DET-05 keys."""

    def test_build_event_keys(self):
        """Returned dict has all required DET-05 keys."""
        result = build_event(SAMPLE_CONFLICT)
        expected_keys = {
            'timestamp', 'attacker_mac', 'victim_ip',
            'original_mac', 'spoofed_mac', 'attack_type',
        }
        assert set(result.keys()) == expected_keys

    def test_build_event_timestamp_iso(self):
        """timestamp must be ISO 8601 format (contains 'T' separator)."""
        result = build_event(SAMPLE_CONFLICT)
        assert 'T' in result['timestamp']

    def test_build_event_attacker_mac(self):
        """attacker_mac must equal conflict['new_mac']."""
        result = build_event(SAMPLE_CONFLICT)
        assert result['attacker_mac'] == 'ff:ee:dd:cc:bb:aa'

    def test_build_event_victim_ip(self):
        """victim_ip must equal conflict['ip']."""
        result = build_event(SAMPLE_CONFLICT)
        assert result['victim_ip'] == '1.2.3.4'

    def test_build_event_original_mac(self):
        """original_mac must equal conflict['known_mac']."""
        result = build_event(SAMPLE_CONFLICT)
        assert result['original_mac'] == 'aa:bb:cc:dd:ee:ff'

    def test_build_event_spoofed_mac(self):
        """spoofed_mac must equal conflict['new_mac'] (same as attacker_mac per spec)."""
        result = build_event(SAMPLE_CONFLICT)
        assert result['spoofed_mac'] == 'ff:ee:dd:cc:bb:aa'

    def test_build_event_attack_type(self):
        """attack_type must be the constant string 'ARP_SPOOFING'."""
        result = build_event(SAMPLE_CONFLICT)
        assert result['attack_type'] == 'ARP_SPOOFING'

    def test_build_event_attacker_mac_equals_spoofed_mac(self):
        """attacker_mac and spoofed_mac must be equal (both from new_mac)."""
        result = build_event(SAMPLE_CONFLICT)
        assert result['attacker_mac'] == result['spoofed_mac']
