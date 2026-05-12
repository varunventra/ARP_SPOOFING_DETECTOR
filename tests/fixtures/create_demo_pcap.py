"""create_demo_pcap.py — Generates demo_capture.pcap for offline demo use.

Run once: python tests/fixtures/create_demo_pcap.py
Output:   demo_capture.pcap (in project root)

Does not require root — scapy wrpcap() writes to file without sending packets.

Packet sequence:
  Packets 1-3: Legitimate ARP replies — establish baseline mappings
  Packets 4-6: Spoofed ARP replies — same IPs, attacker MAC de:ad:be:ef:ca:fe
  Packets 7-8: Additional attack replies on different victim IPs

The detector replaying this pcap will raise 3 conflicts (one per spoofed IP).
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "demo_capture.pcap")

try:
    from scapy.all import ARP, Ether, wrpcap
except ImportError:
    print("ERROR: scapy not installed.  Run: pip install scapy", file=sys.stderr)
    sys.exit(1)

# Legitimate MAC addresses (what the real hosts use)
LEGIT = {
    "192.168.1.1": "aa:bb:cc:dd:ee:01",    # Gateway
    "192.168.1.100": "aa:bb:cc:dd:ee:64",  # Host A
    "192.168.1.200": "aa:bb:cc:dd:ee:c8",  # Host B
}

ATTACKER_MAC = "de:ad:be:ef:ca:fe"
DETECTOR_IP = "192.168.1.50"   # Simulated detector machine


def _arp_reply(src_ip: str, src_mac: str, dst_ip: str = DETECTOR_IP) -> "Ether":
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
        / ARP(op=2, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst="ff:ff:ff:ff:ff:ff")
    )


packets = [
    # --- Baseline traffic: legitimate ARP replies ---
    # The detector (or baseline scan) learns these mappings first.
    _arp_reply("192.168.1.1", LEGIT["192.168.1.1"]),       # Gateway legit reply
    _arp_reply("192.168.1.100", LEGIT["192.168.1.100"]),   # Host A legit reply
    _arp_reply("192.168.1.200", LEGIT["192.168.1.200"]),   # Host B legit reply

    # --- Attack phase: spoofed ARP replies (attacker claims each IP) ---
    # Detector sees these after the legitimate entries are seeded → conflict!
    _arp_reply("192.168.1.1", ATTACKER_MAC),               # CONFLICT: gateway spoofed
    _arp_reply("192.168.1.100", ATTACKER_MAC),             # CONFLICT: Host A spoofed
    _arp_reply("192.168.1.200", ATTACKER_MAC),             # CONFLICT: Host B spoofed

    # --- Continued attack: repeated spoofs to poison cache ---
    _arp_reply("192.168.1.1", ATTACKER_MAC),               # Repeat gateway spoof
    _arp_reply("192.168.1.100", ATTACKER_MAC),             # Repeat Host A spoof
]

wrpcap(OUTPUT_PATH, packets)
print(f"Written: {OUTPUT_PATH} ({len(packets)} packets)")
print(f"  Baseline packets:  3")
print(f"  Conflict packets:  5 (3 unique victim IPs)")
print(f"  Attacker MAC:      {ATTACKER_MAC}")
