"""test_arp_table.py — unit tests for ARPTable using synthetic in-memory data only.
No root, no network, no scapy required.
"""
import time
import pytest
import pandas as pd
from arp_detector.arp_table import ARPTable


class TestARPTableFirstSeen:
    """update() with a brand-new IP should record the mapping and return None."""

    def test_update_first_seen_returns_none(self):
        table = ARPTable()
        result = table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        assert result is None

    def test_update_first_seen_records_ip(self):
        table = ARPTable()
        table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        df = table.get_all()
        assert "192.168.1.1" in df.index

    def test_update_first_seen_records_mac(self):
        table = ARPTable()
        table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        df = table.get_all()
        assert df.at["192.168.1.1", "mac"] == "aa:bb:cc:dd:ee:ff"

    def test_update_first_seen_sets_first_seen_timestamp(self):
        before = time.time()
        table = ARPTable()
        table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        after = time.time()
        df = table.get_all()
        assert before <= df.at["192.168.1.1", "first_seen"] <= after

    def test_update_first_seen_sets_last_seen_equal_to_first_seen(self):
        table = ARPTable()
        table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        df = table.get_all()
        assert df.at["192.168.1.1", "first_seen"] == df.at["192.168.1.1", "last_seen"]


class TestARPTableSameMac:
    """update() with same IP + same MAC should update last_seen and return None."""

    def test_update_same_mac_returns_none(self):
        table = ARPTable()
        table.update("192.168.1.2", "11:22:33:44:55:66")
        result = table.update("192.168.1.2", "11:22:33:44:55:66")
        assert result is None

    def test_update_same_mac_preserves_first_seen(self):
        table = ARPTable()
        table.update("192.168.1.2", "11:22:33:44:55:66")
        first_seen_before = table.get_all().at["192.168.1.2", "first_seen"]
        time.sleep(0.01)
        table.update("192.168.1.2", "11:22:33:44:55:66")
        assert table.get_all().at["192.168.1.2", "first_seen"] == first_seen_before

    def test_update_same_mac_updates_last_seen(self):
        table = ARPTable()
        table.update("192.168.1.2", "11:22:33:44:55:66")
        time.sleep(0.01)
        before_second = time.time()
        table.update("192.168.1.2", "11:22:33:44:55:66")
        assert table.get_all().at["192.168.1.2", "last_seen"] >= before_second


class TestARPTableConflict:
    """update() with same IP but different MAC should return a conflict dict."""

    def test_update_conflict_returns_dict(self):
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        result = table.update("10.0.0.1", "bb:bb:bb:bb:bb:bb")
        assert isinstance(result, dict)

    def test_update_conflict_dict_has_ip(self):
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        result = table.update("10.0.0.1", "bb:bb:bb:bb:bb:bb")
        assert result["ip"] == "10.0.0.1"

    def test_update_conflict_dict_has_known_mac(self):
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        result = table.update("10.0.0.1", "bb:bb:bb:bb:bb:bb")
        assert result["known_mac"] == "aa:aa:aa:aa:aa:aa"

    def test_update_conflict_dict_has_new_mac(self):
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        result = table.update("10.0.0.1", "bb:bb:bb:bb:bb:bb")
        assert result["new_mac"] == "bb:bb:bb:bb:bb:bb"

    def test_update_conflict_dict_has_timestamp(self):
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        before = time.time()
        result = table.update("10.0.0.1", "bb:bb:bb:bb:bb:bb")
        assert before <= result["timestamp"] <= time.time()


class TestARPTableCheckConflict:
    """check_conflict() is a read-only probe — never modifies the table."""

    def test_check_conflict_unknown_ip_returns_none(self):
        table = ARPTable()
        assert table.check_conflict("172.16.0.1", "cc:cc:cc:cc:cc:cc") is None

    def test_check_conflict_known_ip_same_mac_returns_none(self):
        table = ARPTable()
        table.update("172.16.0.2", "dd:dd:dd:dd:dd:dd")
        assert table.check_conflict("172.16.0.2", "dd:dd:dd:dd:dd:dd") is None

    def test_check_conflict_known_ip_different_mac_returns_dict(self):
        table = ARPTable()
        table.update("172.16.0.3", "ee:ee:ee:ee:ee:ee")
        result = table.check_conflict("172.16.0.3", "ff:ff:ff:ff:ff:ff")
        assert isinstance(result, dict)
        assert result["ip"] == "172.16.0.3"
        assert result["known_mac"] == "ee:ee:ee:ee:ee:ee"
        assert result["new_mac"] == "ff:ff:ff:ff:ff:ff"

    def test_check_conflict_does_not_modify_table(self):
        table = ARPTable()
        table.update("172.16.0.4", "11:11:11:11:11:11")
        snapshot_before = table.get_all().copy()
        table.check_conflict("172.16.0.4", "22:22:22:22:22:22")
        pd.testing.assert_frame_equal(table.get_all(), snapshot_before)


class TestARPTableGetAll:
    """get_all() returns a copy — mutations do not affect internal state."""

    def test_get_all_returns_dataframe(self):
        table = ARPTable()
        assert isinstance(table.get_all(), pd.DataFrame)

    def test_get_all_index_is_ip(self):
        table = ARPTable()
        table.update("1.2.3.4", "aa:00:00:00:00:01")
        df = table.get_all()
        assert df.index.name == "ip"

    def test_get_all_returns_copy_not_reference(self):
        table = ARPTable()
        table.update("1.2.3.4", "aa:00:00:00:00:01")
        df = table.get_all()
        df.drop("1.2.3.4", inplace=True)   # mutate the returned copy
        assert "1.2.3.4" in table.get_all().index  # internal table unchanged

    def test_get_all_multiple_ips(self):
        table = ARPTable()
        table.update("10.0.0.1", "aa:bb:cc:dd:ee:01")
        table.update("10.0.0.2", "aa:bb:cc:dd:ee:02")
        table.update("10.0.0.3", "aa:bb:cc:dd:ee:03")
        df = table.get_all()
        assert len(df) == 3
        assert set(df.index) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
