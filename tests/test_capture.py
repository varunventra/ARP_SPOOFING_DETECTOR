"""test_capture.py — unit tests for capture.py.

Tests run without root by:
  - Patching os.geteuid() with mock
  - Calling build_packet_callback() directly (no live sniffer)
  - Using rdpcap() on tests/fixtures/synthetic_arp.pcap (pre-built fixture)

CAP-01: store=False verified by inspecting AsyncSniffer kwargs
CAP-02: --iface arg and get_if_list() fallback
CAP-03: root check exits with code 1
CAP-04: op=2 filter — only replies enqueued
"""
import queue
import sys
import time
import os
from unittest.mock import patch, MagicMock
import pytest
from scapy.all import rdpcap, ARP, Ether


# ---------------------------------------------------------------------------
# CAP-03: Root privilege check
# ---------------------------------------------------------------------------

class TestCheckRoot:
    """check_root() must exit(1) when not root, pass silently when root.

    Patches target arp_detector.capture.os.geteuid with create=True so that
    tests run on both POSIX (Linux/WSL) and non-POSIX (Windows) platforms.
    """

    def test_check_root_exits_when_not_root(self):
        from arp_detector.capture import check_root
        with patch("arp_detector.capture.os.geteuid", return_value=1000, create=True):
            with pytest.raises(SystemExit) as exc_info:
                check_root()
        assert exc_info.value.code == 1

    def test_check_root_prints_error_message_when_not_root(self, capsys):
        from arp_detector.capture import check_root
        with patch("arp_detector.capture.os.geteuid", return_value=1000, create=True):
            with pytest.raises(SystemExit):
                check_root()
        captured = capsys.readouterr()
        # error must appear on stderr or stdout; must mention root/sudo
        output = captured.out + captured.err
        assert any(word in output.lower() for word in ("root", "sudo", "privilege")), \
            f"Error message does not mention root/sudo/privilege: {output!r}"

    def test_check_root_does_not_exit_when_root(self):
        from arp_detector.capture import check_root
        with patch("arp_detector.capture.os.geteuid", return_value=0, create=True):
            check_root()  # must not raise SystemExit


# ---------------------------------------------------------------------------
# CAP-02: Interface detection and --iface CLI arg
# ---------------------------------------------------------------------------

class TestGetDefaultIface:
    """get_default_iface() filters 'lo' from get_if_list() and returns first result."""

    def test_returns_first_non_loopback(self):
        from arp_detector.capture import get_default_iface
        with patch("arp_detector.capture.get_if_list", return_value=["lo", "eth0", "eth1"]):
            result = get_default_iface()
        assert result == "eth0"

    def test_filters_loopback_only(self):
        from arp_detector.capture import get_default_iface
        with patch("arp_detector.capture.get_if_list", return_value=["eth0"]):
            result = get_default_iface()
        assert result == "eth0"

    def test_exits_when_no_non_loopback_interfaces(self):
        from arp_detector.capture import get_default_iface
        with patch("arp_detector.capture.get_if_list", return_value=["lo"]):
            with pytest.raises(SystemExit):
                get_default_iface()

    def test_exits_when_interface_list_empty(self):
        from arp_detector.capture import get_default_iface
        with patch("arp_detector.capture.get_if_list", return_value=[]):
            with pytest.raises(SystemExit):
                get_default_iface()

    def test_wsl_style_interface_names(self):
        """WSL2 may use enX0 or enp0s3 — must handle these names."""
        from arp_detector.capture import get_default_iface
        with patch("arp_detector.capture.get_if_list", return_value=["lo", "enp0s3"]):
            result = get_default_iface()
        assert result == "enp0s3"


class TestParseCLIArgs:
    """parse_cli_args() accepts --iface; defaults to None when omitted."""

    def test_parse_iface_argument(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py", "--iface", "eth0"]):
            args = parse_cli_args()
        assert args.iface == "eth0"

    def test_parse_iface_absent_defaults_to_none(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py"]):
            args = parse_cli_args()
        assert args.iface is None

    def test_parse_custom_iface_name(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py", "--iface", "enp0s3"]):
            args = parse_cli_args()
        assert args.iface == "enp0s3"

    def test_visualize_flag_default_false(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py"]):
            args = parse_cli_args()
        assert args.visualize is False

    def test_visualize_flag_present(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py", "--visualize"]):
            args = parse_cli_args()
        assert args.visualize is True

    def test_logfile_arg_default(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py"]):
            args = parse_cli_args()
        assert args.logfile == "arp_detector.log"

    def test_logfile_arg_custom(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py", "--logfile", "/tmp/custom.log"]):
            args = parse_cli_args()
        assert args.logfile == "/tmp/custom.log"

    def test_report_arg_default(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py"]):
            args = parse_cli_args()
        assert args.report == "attack_report.csv"

    def test_report_arg_custom(self):
        from arp_detector.capture import parse_cli_args
        with patch("sys.argv", ["capture.py", "--report", "/tmp/rep.csv"]):
            args = parse_cli_args()
        assert args.report == "/tmp/rep.csv"


# ---------------------------------------------------------------------------
# CAP-01 + CAP-04: Callback filtering and Queue delivery
# ---------------------------------------------------------------------------

class TestBuildPacketCallback:
    """build_packet_callback() returns a closure that filters and enqueues correctly."""

    def _make_arp_pkt(self, op, psrc, hwsrc, pdst, hwdst="ff:ff:ff:ff:ff:ff"):
        return Ether(dst=hwdst, src=hwsrc) / ARP(
            op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst
        )

    def test_op2_reply_is_enqueued(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkt = self._make_arp_pkt(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:00:00:01",
                                 pdst="10.0.0.2")
        callback(pkt)
        assert q.qsize() == 1

    def test_op1_request_is_not_enqueued(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkt = self._make_arp_pkt(op=1, psrc="10.0.0.1", hwsrc="aa:bb:cc:00:00:01",
                                 pdst="10.0.0.2", hwdst="00:00:00:00:00:00")
        callback(pkt)
        assert q.qsize() == 0

    def test_enqueued_dict_has_src_ip(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkt = self._make_arp_pkt(op=2, psrc="192.168.0.5", hwsrc="aa:bb:cc:00:00:05",
                                 pdst="192.168.0.1")
        callback(pkt)
        item = q.get_nowait()
        assert item["src_ip"] == "192.168.0.5"

    def test_enqueued_dict_has_src_mac(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkt = self._make_arp_pkt(op=2, psrc="192.168.0.6", hwsrc="aa:bb:cc:00:00:06",
                                 pdst="192.168.0.1")
        callback(pkt)
        item = q.get_nowait()
        assert item["src_mac"] == "aa:bb:cc:00:00:06"

    def test_enqueued_dict_has_dst_ip(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkt = self._make_arp_pkt(op=2, psrc="192.168.0.7", hwsrc="aa:bb:cc:00:00:07",
                                 pdst="192.168.0.99")
        callback(pkt)
        item = q.get_nowait()
        assert item["dst_ip"] == "192.168.0.99"

    def test_enqueued_dict_has_op(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkt = self._make_arp_pkt(op=2, psrc="192.168.0.8", hwsrc="aa:bb:cc:00:00:08",
                                 pdst="192.168.0.1")
        callback(pkt)
        item = q.get_nowait()
        assert item["op"] == 2

    def test_enqueued_dict_has_timestamp(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        before = time.time()
        pkt = self._make_arp_pkt(op=2, psrc="192.168.0.9", hwsrc="aa:bb:cc:00:00:09",
                                 pdst="192.168.0.1")
        callback(pkt)
        after = time.time()
        item = q.get_nowait()
        assert before <= item["timestamp"] <= after

    def test_multiple_op2_packets_all_enqueued(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        for i in range(5):
            pkt = self._make_arp_pkt(op=2, psrc=f"10.0.0.{i+1}",
                                     hwsrc=f"aa:bb:cc:dd:ee:{i+1:02x}",
                                     pdst="10.0.0.100")
            callback(pkt)
        assert q.qsize() == 5

    def test_non_arp_packet_is_not_enqueued(self):
        """Callback must check haslayer(ARP) — non-ARP packets must be dropped."""
        from arp_detector.capture import build_packet_callback
        from scapy.all import IP, TCP
        q = queue.Queue()
        callback = build_packet_callback(q)
        tcp_pkt = Ether() / IP(dst="1.2.3.4") / TCP()
        callback(tcp_pkt)
        assert q.qsize() == 0


# ---------------------------------------------------------------------------
# CAP-01: store=False verified on AsyncSniffer construction
# ---------------------------------------------------------------------------

class TestStartCapture:
    """start_capture() must pass store=False to AsyncSniffer."""

    def test_start_capture_uses_store_false(self):
        from arp_detector.capture import start_capture
        captured_kwargs = {}

        class MockSniffer:
            def __init__(self, **kwargs):
                captured_kwargs.update(kwargs)
            def start(self):
                pass

        with patch("arp_detector.capture.AsyncSniffer", MockSniffer):
            start_capture("eth0", queue.Queue())

        assert captured_kwargs.get("store") is False, \
            f"store must be False, got: {captured_kwargs.get('store')!r}"

    def test_start_capture_passes_iface(self):
        from arp_detector.capture import start_capture
        captured_kwargs = {}

        class MockSniffer:
            def __init__(self, **kwargs):
                captured_kwargs.update(kwargs)
            def start(self):
                pass

        with patch("arp_detector.capture.AsyncSniffer", MockSniffer):
            start_capture("enp0s3", queue.Queue())

        assert captured_kwargs.get("iface") == "enp0s3"

    def test_start_capture_uses_arp_filter(self):
        from arp_detector.capture import start_capture
        captured_kwargs = {}

        class MockSniffer:
            def __init__(self, **kwargs):
                captured_kwargs.update(kwargs)
            def start(self):
                pass

        with patch("arp_detector.capture.AsyncSniffer", MockSniffer):
            start_capture("eth0", queue.Queue())

        assert captured_kwargs.get("filter") == "arp", \
            f"BPF filter must be 'arp', got: {captured_kwargs.get('filter')!r}"


# ---------------------------------------------------------------------------
# Integration: pcap replay through callback
# ---------------------------------------------------------------------------

class TestPcapReplay:
    """Replay synthetic_arp.pcap through the callback and verify Queue contents."""

    FIXTURE_PATH = "tests/fixtures/synthetic_arp.pcap"

    def test_pcap_has_correct_packet_count(self):
        pkts = rdpcap(self.FIXTURE_PATH)
        assert len(pkts) == 5

    def test_pcap_replay_enqueues_only_op2_non_gratuitous(self):
        """
        synthetic_arp.pcap contains:
          Pkt 1: op=2 reply for 192.168.1.1  -> enqueued
          Pkt 2: op=2 reply for 192.168.1.2  -> enqueued
          Pkt 3: op=1 request                -> NOT enqueued (op filter)
          Pkt 4: op=2 spoofed for 192.168.1.1 -> enqueued
          Pkt 5: op=2 gratuitous (psrc==pdst) -> enqueued by callback
                 (gratuitous ARP skip is in detector.check_packet, not the callback)

        The callback only filters by op — gratuitous ARP filtering is
        detector.py's responsibility. So 4 packets should be enqueued (all op=2).
        """
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkts = rdpcap(self.FIXTURE_PATH)
        for pkt in pkts:
            callback(pkt)
        # op=2 packets: indices 0, 1, 3, 4 -> 4 packets
        assert q.qsize() == 4, f"Expected 4 enqueued packets, got {q.qsize()}"

    def test_pcap_replay_first_packet_content(self):
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkts = rdpcap(self.FIXTURE_PATH)
        for pkt in pkts:
            callback(pkt)
        first = q.get_nowait()
        assert first["src_ip"] == "192.168.1.1"
        assert first["src_mac"] == "aa:bb:cc:dd:ee:01"
        assert first["op"] == 2

    def test_pcap_replay_spoofed_packet_content(self):
        """Packet 4 in fixture: 192.168.1.1 with spoofed MAC de:ad:be:ef:00:01."""
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkts = rdpcap(self.FIXTURE_PATH)
        for pkt in pkts:
            callback(pkt)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        # Third enqueued item (index 2) is the spoofed packet
        spoofed = items[2]
        assert spoofed["src_ip"] == "192.168.1.1"
        assert spoofed["src_mac"] == "de:ad:be:ef:00:01"

    def test_pcap_replay_no_packets_dropped(self):
        """All op=2 packets must reach the Queue — none silently dropped."""
        from arp_detector.capture import build_packet_callback
        q = queue.Queue()
        callback = build_packet_callback(q)
        pkts = rdpcap(self.FIXTURE_PATH)
        op2_count = sum(1 for p in pkts if p.haslayer(ARP) and p[ARP].op == 2)
        for pkt in pkts:
            callback(pkt)
        assert q.qsize() == op2_count, \
            f"Queue has {q.qsize()} items but {op2_count} op=2 packets were in pcap"
