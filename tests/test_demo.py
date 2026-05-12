"""test_demo.py — Tests for Phase 5: Integration + Demo Prep.

Verifies DEMO-01 (simulate_attack.py) and DEMO-02 (demo_capture.pcap).

All tests are offline — no root, no live network, no packet transmission.
scapy-dependent tests are skipped if scapy is not installed.
"""
import argparse
import importlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
DEMO_PCAP = PROJECT_ROOT / "demo_capture.pcap"

scapy = pytest.importorskip("scapy", reason="scapy not installed")


# ---------------------------------------------------------------------------
# DEMO-01: simulate_attack.py structure
# ---------------------------------------------------------------------------

class TestSimulateAttack:
    """DEMO-01: simulate_attack.py must be a well-formed attack simulator."""

    def test_simulate_attack_exists(self):
        """simulate_attack.py must exist in the project root."""
        assert (PROJECT_ROOT / "simulate_attack.py").exists(), (
            "simulate_attack.py not found in project root"
        )

    def test_simulate_attack_importable(self):
        """simulate_attack.py must be importable (no import-time sendp calls)."""
        # Add project root to sys.path temporarily
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))
        spec = importlib.util.spec_from_file_location(
            "simulate_attack", PROJECT_ROOT / "simulate_attack.py"
        )
        module = importlib.util.module_from_spec(spec)
        # Import should not raise and should not send any packets
        spec.loader.exec_module(module)
        assert hasattr(module, "main"), "simulate_attack.py must define main()"
        assert hasattr(module, "craft_spoof_packet"), (
            "simulate_attack.py must define craft_spoof_packet()"
        )
        assert hasattr(module, "run_attack"), (
            "simulate_attack.py must define run_attack()"
        )

    def test_craft_spoof_packet_returns_arp_reply(self):
        """craft_spoof_packet() must return an Ether/ARP op=2 frame."""
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))
        from scapy.all import ARP
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "simulate_attack", PROJECT_ROOT / "simulate_attack.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        pkt = module.craft_spoof_packet("192.168.1.1", "de:ad:be:ef:ca:fe")
        assert ARP in pkt, "craft_spoof_packet() must return an ARP layer"
        assert pkt[ARP].op == 2, "Spoofed packet must be an ARP reply (op=2)"
        assert pkt[ARP].psrc == "192.168.1.1", "psrc must match target_ip"
        assert pkt[ARP].hwsrc == "de:ad:be:ef:ca:fe", "hwsrc must match attacker_mac"

    def test_parse_args_has_required_flags(self):
        """simulate_attack.py CLI must expose --iface, --target-ip, --count, --interval."""
        src = (PROJECT_ROOT / "simulate_attack.py").read_text()
        for flag in ["--iface", "--target-ip", "--count", "--interval"]:
            assert flag in src, f"simulate_attack.py must define CLI flag {flag}"

    def test_uses_sendp_not_send(self):
        """simulate_attack.py must use sendp() (layer 2), not send() (layer 3)."""
        src = (PROJECT_ROOT / "simulate_attack.py").read_text()
        assert "sendp(" in src, "simulate_attack.py must use scapy sendp() for L2 sending"

    def test_no_shell_true(self):
        """simulate_attack.py must not use shell=True in any subprocess call."""
        import re
        src = (PROJECT_ROOT / "simulate_attack.py").read_text()
        stripped = re.sub(r'""".*?"""', '""', src, flags=re.DOTALL)
        stripped = re.sub(r"'''.*?'''", "''", stripped, flags=re.DOTALL)
        stripped = re.sub(r'#[^\n]*', '', stripped)
        assert "shell=True" not in stripped, "simulate_attack.py must not use shell=True"


# ---------------------------------------------------------------------------
# DEMO-02: demo_capture.pcap structure and replay correctness
# ---------------------------------------------------------------------------

class TestDemoPcap:
    """DEMO-02: demo_capture.pcap must be a valid pcap with detectable attack traffic."""

    def test_demo_pcap_exists(self):
        """demo_capture.pcap must exist in the project root."""
        assert DEMO_PCAP.exists(), (
            "demo_capture.pcap not found — run tests/fixtures/create_demo_pcap.py"
        )

    def test_demo_pcap_readable(self):
        """demo_capture.pcap must be readable by scapy rdpcap()."""
        from scapy.all import rdpcap
        packets = rdpcap(str(DEMO_PCAP))
        assert len(packets) > 0, "demo_capture.pcap must contain at least one packet"

    def test_demo_pcap_contains_arp_replies(self):
        """demo_capture.pcap must contain ARP op=2 reply packets."""
        from scapy.all import ARP, rdpcap
        packets = rdpcap(str(DEMO_PCAP))
        replies = [p for p in packets if ARP in p and p[ARP].op == 2]
        assert len(replies) >= 3, (
            f"demo_capture.pcap must contain at least 3 ARP replies, got {len(replies)}"
        )

    def test_demo_pcap_contains_conflicts(self):
        """Replaying demo_capture.pcap through the detector must produce at least one conflict."""
        from scapy.all import ARP, rdpcap

        from arp_detector.arp_table import ARPTable
        from arp_detector.detector import check_packet

        packets = rdpcap(str(DEMO_PCAP))
        table = ARPTable()
        conflicts = []
        for pkt in packets:
            if ARP not in pkt:
                continue
            pkt_dict = {
                "op": pkt[ARP].op,
                "src_ip": pkt[ARP].psrc,
                "src_mac": pkt[ARP].hwsrc,
                "dst_ip": pkt[ARP].pdst,
            }
            result = check_packet(pkt_dict, table)
            if result is not None:
                conflicts.append(result)

        assert len(conflicts) >= 3, (
            f"Replaying demo_capture.pcap must produce at least 3 conflicts, "
            f"got {len(conflicts)}: {conflicts}"
        )

    def test_demo_pcap_conflict_has_det05_fields(self):
        """Conflicts from demo_capture.pcap must have the DET-05 field set."""
        from scapy.all import ARP, rdpcap

        from arp_detector.arp_table import ARPTable
        from arp_detector.detector import check_packet
        from arp_detector.logger import build_event

        packets = rdpcap(str(DEMO_PCAP))
        table = ARPTable()
        for pkt in packets:
            if ARP not in pkt:
                continue
            pkt_dict = {
                "op": pkt[ARP].op,
                "src_ip": pkt[ARP].psrc,
                "src_mac": pkt[ARP].hwsrc,
                "dst_ip": pkt[ARP].pdst,
            }
            conflict = check_packet(pkt_dict, table)
            if conflict is not None:
                event = build_event(conflict)
                required_keys = {
                    "timestamp", "attacker_mac", "victim_ip",
                    "original_mac", "spoofed_mac", "attack_type",
                }
                assert required_keys.issubset(event.keys()), (
                    f"Event missing DET-05 fields: {required_keys - event.keys()}"
                )
                return  # Pass on first valid conflict
        pytest.fail("No conflict found in demo_capture.pcap")

    def test_demo_pcap_attacker_mac_consistent(self):
        """All spoofed packets in demo_capture.pcap must use the same attacker MAC."""
        from scapy.all import ARP, rdpcap

        from arp_detector.arp_table import ARPTable
        from arp_detector.detector import check_packet

        packets = rdpcap(str(DEMO_PCAP))
        table = ARPTable()
        attacker_macs = set()
        for pkt in packets:
            if ARP not in pkt:
                continue
            pkt_dict = {
                "op": pkt[ARP].op,
                "src_ip": pkt[ARP].psrc,
                "src_mac": pkt[ARP].hwsrc,
                "dst_ip": pkt[ARP].pdst,
            }
            conflict = check_packet(pkt_dict, table)
            if conflict is not None:
                attacker_macs.add(conflict["new_mac"])

        assert len(attacker_macs) == 1, (
            f"Expected 1 unique attacker MAC, got {len(attacker_macs)}: {attacker_macs}"
        )
        assert "de:ad:be:ef:ca:fe" in attacker_macs, (
            f"Expected attacker MAC de:ad:be:ef:ca:fe, got {attacker_macs}"
        )
