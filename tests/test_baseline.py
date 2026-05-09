"""test_baseline.py — Unit tests for arp_detector/baseline.py (DET-02).

All tests mock subprocess.run — no root required, no arp-scan binary needed.
Tests verify: correct parsing of arp-scan output, header/footer skipping,
return value (count of hosts), and error handling (FileNotFoundError, TimeoutExpired).
"""
import subprocess
from unittest.mock import patch, MagicMock
import pytest
from arp_detector.arp_table import ARPTable
from arp_detector.baseline import load_baseline


# Fixture: realistic arp-scan --localnet output with 2 data lines
MOCK_ARP_SCAN_OUTPUT = (
    "Interface: eth0, type: EN10MB, MAC: aa:bb:cc:00:00:01, IPv4: 192.168.1.1\n"
    "Starting arp-scan 1.9.7 with 256 hosts\n"
    "192.168.1.1\taa:bb:cc:dd:ee:01\tCisco Systems\n"
    "192.168.1.5\taa:bb:cc:dd:ee:05\t(Unknown)\n"
    "\n"
    "2 packets received by filter, 0 dropped\n"
)

# Fixture: only header/footer lines — no data lines
MOCK_HEADER_ONLY_OUTPUT = (
    "Interface: eth0, type: EN10MB, MAC: aa:bb:cc:00:00:01, IPv4: 192.168.1.1\n"
    "Starting arp-scan 1.9.7 with 256 hosts\n"
    "\n"
    "0 packets received by filter, 0 dropped\n"
)


def _make_completed_process(stdout: str, returncode: int = 0) -> MagicMock:
    """Helper: construct a CompletedProcess-like mock with stdout set."""
    mock = MagicMock()
    mock.stdout = stdout
    mock.returncode = returncode
    return mock


class TestLoadsValidHosts:
    """load_baseline() correctly parses IP/MAC data lines from arp-scan output."""

    def test_loads_valid_hosts(self):
        """Two data lines in mock output — table should have exactly 2 entries."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        assert len(df) == 2

    def test_loads_correct_first_ip(self):
        """First data line IP (192.168.1.1) is present in the table."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        assert "192.168.1.1" in df.index

    def test_loads_correct_second_ip(self):
        """Second data line IP (192.168.1.5) is present in the table."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        assert "192.168.1.5" in df.index

    def test_loads_correct_first_mac(self):
        """First data line MAC (aa:bb:cc:dd:ee:01) matches the stored entry."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        assert df.at["192.168.1.1", "mac"] == "aa:bb:cc:dd:ee:01"

    def test_loads_correct_second_mac(self):
        """Second data line MAC (aa:bb:cc:dd:ee:05) matches the stored entry."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        assert df.at["192.168.1.5", "mac"] == "aa:bb:cc:dd:ee:05"


class TestSkipsHeaderFooter:
    """load_baseline() silently skips non-data lines (header/footer)."""

    def test_does_not_add_interface_line(self):
        """The 'Interface:' header line must not produce a table entry."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        # 'Interface:' is not a valid IPv4 address — it must not be in the index
        for idx in df.index:
            assert not idx.startswith("Interface")

    def test_does_not_add_starting_line(self):
        """The 'Starting arp-scan' header line must not produce a table entry."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        for idx in df.index:
            assert not idx.startswith("Starting")

    def test_does_not_add_packets_line(self):
        """The footer '... packets received ...' line must not produce a table entry."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            load_baseline(table)
        df = table.get_all()
        for idx in df.index:
            assert "packets" not in idx


class TestReturnsCount:
    """load_baseline() return value equals the number of valid host lines parsed."""

    def test_returns_count_of_two(self):
        """Two data lines in mock output -> return value must be 2."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            result = load_baseline(table)
        assert result == 2

    def test_returns_integer(self):
        """Return type must be int."""
        table = ARPTable()
        with patch("subprocess.run", return_value=_make_completed_process(MOCK_ARP_SCAN_OUTPUT)):
            result = load_baseline(table)
        assert isinstance(result, int)


class TestHandlesMissingBinary:
    """load_baseline() returns 0 and does not raise when arp-scan binary is absent."""

    def test_missing_binary_returns_zero(self):
        """FileNotFoundError from subprocess.run -> return 0."""
        table = ARPTable()
        with patch("subprocess.run", side_effect=FileNotFoundError("arp-scan not found")):
            result = load_baseline(table)
        assert result == 0

    def test_missing_binary_does_not_raise(self):
        """No exception must propagate to the caller on missing binary."""
        table = ARPTable()
        with patch("subprocess.run", side_effect=FileNotFoundError("arp-scan not found")):
            try:
                load_baseline(table)
            except FileNotFoundError:
                pytest.fail("load_baseline() must not propagate FileNotFoundError")

    def test_missing_binary_leaves_table_empty(self):
        """When the binary is missing, the table must remain empty."""
        table = ARPTable()
        with patch("subprocess.run", side_effect=FileNotFoundError("arp-scan not found")):
            load_baseline(table)
        assert len(table.get_all()) == 0


class TestHandlesTimeout:
    """load_baseline() returns 0 and does not raise on subprocess timeout."""

    def test_timeout_returns_zero(self):
        """subprocess.TimeoutExpired -> return 0."""
        table = ARPTable()
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["arp-scan", "--localnet"], timeout=30),
        ):
            result = load_baseline(table)
        assert result == 0

    def test_timeout_does_not_raise(self):
        """No exception must propagate to the caller on timeout."""
        table = ARPTable()
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["arp-scan", "--localnet"], timeout=30),
        ):
            try:
                load_baseline(table)
            except subprocess.TimeoutExpired:
                pytest.fail("load_baseline() must not propagate TimeoutExpired")

    def test_timeout_leaves_table_empty(self):
        """When the subprocess times out, the table must remain empty."""
        table = ARPTable()
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["arp-scan", "--localnet"], timeout=30),
        ):
            load_baseline(table)
        assert len(table.get_all()) == 0


class TestEmptyTableOnHeaderOnly:
    """load_baseline() handles output that has no data lines (header/footer only)."""

    def test_header_only_returns_zero(self):
        """No data lines -> return value must be 0."""
        table = ARPTable()
        with patch(
            "subprocess.run",
            return_value=_make_completed_process(MOCK_HEADER_ONLY_OUTPUT),
        ):
            result = load_baseline(table)
        assert result == 0

    def test_header_only_table_is_empty(self):
        """No data lines -> table must have 0 rows."""
        table = ARPTable()
        with patch(
            "subprocess.run",
            return_value=_make_completed_process(MOCK_HEADER_ONLY_OUTPUT),
        ):
            load_baseline(table)
        assert len(table.get_all()) == 0
