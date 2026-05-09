"""test_detector.py — unit tests for conflict detection logic.

All tests use synthetic packet dicts (no scapy, no root, no network).
Packet dict shape mirrors what capture.py will produce in Phase 1 Plan 3.
"""
import time
import pytest
from arp_detector.arp_table import ARPTable
from arp_detector.detector import check_packet


def make_pkt(src_ip, src_mac, dst_ip="192.168.1.100", op=2):
    """Helper: build a synthetic packet dict matching capture.py's output format."""
    return {
        'src_ip': src_ip,
        'src_mac': src_mac,
        'dst_ip': dst_ip,
        'op': op,
        'timestamp': time.time(),
    }


class TestFirstSeen:
    """First ARP reply for a given IP — table is empty — should return None."""

    def test_first_reply_returns_none(self):
        table = ARPTable()
        pkt = make_pkt("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        result = check_packet(pkt, table)
        assert result is None

    def test_first_reply_records_mapping(self):
        table = ARPTable()
        pkt = make_pkt("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        check_packet(pkt, table)
        df = table.get_all()
        assert "192.168.1.1" in df.index
        assert df.at["192.168.1.1", "mac"] == "aa:bb:cc:dd:ee:ff"


class TestConflictDetection:
    """Second ARP reply for a known IP with a different MAC — must return conflict dict."""

    def test_conflict_returns_dict(self):
        table = ARPTable()
        check_packet(make_pkt("10.0.0.1", "aa:aa:aa:aa:aa:aa"), table)
        result = check_packet(make_pkt("10.0.0.1", "bb:bb:bb:bb:bb:bb"), table)
        assert isinstance(result, dict)

    def test_conflict_dict_ip(self):
        table = ARPTable()
        check_packet(make_pkt("10.0.0.1", "aa:aa:aa:aa:aa:aa"), table)
        result = check_packet(make_pkt("10.0.0.1", "bb:bb:bb:bb:bb:bb"), table)
        assert result["ip"] == "10.0.0.1"

    def test_conflict_dict_known_mac(self):
        table = ARPTable()
        check_packet(make_pkt("10.0.0.1", "aa:aa:aa:aa:aa:aa"), table)
        result = check_packet(make_pkt("10.0.0.1", "bb:bb:bb:bb:bb:bb"), table)
        assert result["known_mac"] == "aa:aa:aa:aa:aa:aa"

    def test_conflict_dict_new_mac(self):
        table = ARPTable()
        check_packet(make_pkt("10.0.0.1", "aa:aa:aa:aa:aa:aa"), table)
        result = check_packet(make_pkt("10.0.0.1", "bb:bb:bb:bb:bb:bb"), table)
        assert result["new_mac"] == "bb:bb:bb:bb:bb:bb"

    def test_conflict_dict_has_timestamp(self):
        table = ARPTable()
        check_packet(make_pkt("10.0.0.1", "aa:aa:aa:aa:aa:aa"), table)
        before = time.time()
        result = check_packet(make_pkt("10.0.0.1", "bb:bb:bb:bb:bb:bb"), table)
        assert before <= result["timestamp"] <= time.time()

    def test_third_packet_same_ip_third_mac_also_conflicts(self):
        """Each new MAC for a known IP generates a fresh conflict."""
        table = ARPTable()
        check_packet(make_pkt("10.0.0.2", "aa:aa:aa:aa:aa:01"), table)
        check_packet(make_pkt("10.0.0.2", "aa:aa:aa:aa:aa:02"), table)
        result = check_packet(make_pkt("10.0.0.2", "aa:aa:aa:aa:aa:03"), table)
        assert isinstance(result, dict)
        assert result["new_mac"] == "aa:aa:aa:aa:aa:03"


class TestSameMacRepeat:
    """Repeat ARP reply for a known IP with the same MAC — should return None."""

    def test_same_mac_repeat_returns_none(self):
        table = ARPTable()
        check_packet(make_pkt("172.16.0.1", "cc:cc:cc:cc:cc:cc"), table)
        result = check_packet(make_pkt("172.16.0.1", "cc:cc:cc:cc:cc:cc"), table)
        assert result is None

    def test_same_mac_many_repeats_all_return_none(self):
        table = ARPTable()
        check_packet(make_pkt("172.16.0.2", "dd:dd:dd:dd:dd:dd"), table)
        for _ in range(10):
            result = check_packet(make_pkt("172.16.0.2", "dd:dd:dd:dd:dd:dd"), table)
            assert result is None


class TestOpFilter:
    """ARP op=1 (request) packets must be ignored — only op=2 (reply) triggers detection."""

    def test_op1_request_returns_none_always(self):
        table = ARPTable()
        pkt = make_pkt("192.168.0.1", "ee:ee:ee:ee:ee:ee", op=1)
        assert check_packet(pkt, table) is None

    def test_op1_request_does_not_populate_table(self):
        table = ARPTable()
        pkt = make_pkt("192.168.0.5", "ff:ff:ff:ff:ff:ff", op=1)
        check_packet(pkt, table)
        assert "192.168.0.5" not in table.get_all().index

    def test_op1_followed_by_op2_same_ip_treats_op2_as_first_seen(self):
        """op=1 must not seed the table — op=2 after op=1 is first-seen."""
        table = ARPTable()
        check_packet(make_pkt("192.168.0.10", "11:11:11:11:11:11", op=1), table)
        result = check_packet(make_pkt("192.168.0.10", "22:22:22:22:22:22", op=2), table)
        assert result is None  # op=2 with this IP is genuinely first-seen


class TestGratuitousARPFilter:
    """Gratuitous ARPs (src_ip == dst_ip) must be skipped — return None, no table update."""

    def test_gratuitous_arp_returns_none(self):
        table = ARPTable()
        pkt = make_pkt("192.168.1.50", "ab:cd:ef:01:23:45", dst_ip="192.168.1.50")
        assert check_packet(pkt, table) is None

    def test_gratuitous_arp_does_not_populate_table(self):
        table = ARPTable()
        pkt = make_pkt("192.168.1.51", "ab:cd:ef:01:23:46", dst_ip="192.168.1.51")
        check_packet(pkt, table)
        assert "192.168.1.51" not in table.get_all().index

    def test_gratuitous_arp_does_not_mask_real_conflict(self):
        """A gratuitous ARP after a real entry is established must not overwrite the table."""
        table = ARPTable()
        check_packet(make_pkt("192.168.1.52", "11:22:33:44:55:66"), table)
        gratuitous = make_pkt("192.168.1.52", "aa:bb:cc:dd:ee:ff", dst_ip="192.168.1.52")
        result = check_packet(gratuitous, table)
        assert result is None
        # original MAC must still be the known entry
        assert table.get_all().at["192.168.1.52", "mac"] == "11:22:33:44:55:66"


class TestMultipleIPs:
    """Each IP is tracked independently — conflicts on one IP do not affect others."""

    def test_independent_ips_no_cross_contamination(self):
        table = ARPTable()
        check_packet(make_pkt("10.1.1.1", "aa:00:00:00:00:01"), table)
        check_packet(make_pkt("10.1.1.2", "aa:00:00:00:00:02"), table)
        # change MAC on 10.1.1.1 only
        result_1 = check_packet(make_pkt("10.1.1.1", "bb:00:00:00:00:01"), table)
        result_2 = check_packet(make_pkt("10.1.1.2", "aa:00:00:00:00:02"), table)
        assert isinstance(result_1, dict)
        assert result_2 is None
