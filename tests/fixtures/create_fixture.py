"""create_fixture.py — generates synthetic_arp.pcap for offline test use.

Run once: python tests/fixtures/create_fixture.py
Output:   tests/fixtures/synthetic_arp.pcap

Does not require root — scapy wrpcap() writes to file without sending packets.
"""
import os
from scapy.all import ARP, Ether, wrpcap

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "synthetic_arp.pcap")

packets = [
    # Packet 1: op=2 reply — first seen for 192.168.1.1
    Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:01") /
    ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01",
        pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

    # Packet 2: op=2 reply — first seen for 192.168.1.2
    Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:02") /
    ARP(op=2, psrc="192.168.1.2", hwsrc="aa:bb:cc:dd:ee:02",
        pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

    # Packet 3: op=1 request — must NOT be enqueued by callback
    Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:03") /
    ARP(op=1, psrc="192.168.1.3", hwsrc="aa:bb:cc:dd:ee:03",
        pdst="192.168.1.1", hwdst="00:00:00:00:00:00"),

    # Packet 4: op=2 reply — SPOOFED, same IP 192.168.1.1 with different MAC
    Ether(dst="ff:ff:ff:ff:ff:ff", src="de:ad:be:ef:00:01") /
    ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01",
        pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff"),

    # Packet 5: op=2 gratuitous ARP (psrc == pdst) — must NOT be enqueued
    Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:05") /
    ARP(op=2, psrc="192.168.1.5", hwsrc="aa:bb:cc:dd:ee:05",
        pdst="192.168.1.5", hwdst="ff:ff:ff:ff:ff:ff"),
]

wrpcap(OUTPUT_PATH, packets)
print(f"Written: {OUTPUT_PATH} ({len(packets)} packets)")
