"""detector.py — ARP conflict detection logic (CAP-04, DET-01).

This module applies detection rules to parsed packet dicts and delegates
state management to ARPTable. It does NOT import scapy — packet dicts are
produced by capture.py and passed in as plain Python dicts.

Detection rules (applied in order):
  1. op != 2  -> skip (only ARP replies carry spoofing signatures)
  2. src_ip == dst_ip  -> skip (gratuitous ARP — device announcing itself;
                         logging these is a Phase 2 task)
  3. Delegate to table.update(src_ip, src_mac)
     -> returns None (new entry or same-MAC repeat) or conflict dict

Packet dict contract (produced by capture.py):
  {
      'src_ip':   str,    # ARP sender IP   (pkt[ARP].psrc)
      'src_mac':  str,    # ARP sender MAC  (pkt[ARP].hwsrc)
      'dst_ip':   str,    # ARP target IP   (pkt[ARP].pdst)
      'op':       int,    # ARP operation   (1=request, 2=reply)
      'timestamp': float  # time.time() at capture
  }
"""
from __future__ import annotations
from arp_detector.arp_table import ARPTable


def check_packet(pkt: dict, table: ARPTable) -> dict | None:
    """Apply ARP spoofing detection rules to a single parsed packet dict.

    Args:
        pkt:   Packet dict with keys src_ip, src_mac, dst_ip, op, timestamp.
        table: ARPTable instance (written exclusively from the main thread).

    Returns:
        None if the packet is not a spoofing candidate.
        A conflict dict if a known IP->MAC mapping has been violated:
          {'ip': str, 'known_mac': str, 'new_mac': str, 'timestamp': float}
    """
    # Rule 1: Only ARP replies (op=2) carry the IP->MAC claims we need to check.
    # Requests (op=1) ask "who has IP X?" — they do not assert a MAC mapping.
    if pkt['op'] != 2:
        return None

    src_ip = pkt['src_ip']
    src_mac = pkt['src_mac']
    dst_ip = pkt['dst_ip']

    # Rule 2: Gratuitous ARP — sender's IP equals the target IP.
    # Devices use these at boot or after IP changes to announce themselves.
    # They look structurally identical to spoofed replies but are legitimate.
    # Per PITFALLS M1: filter before table lookup to avoid false positives.
    if src_ip == dst_ip:
        return None

    # Rule 3: Delegate to the table. update() handles:
    #   - New IP: records mapping, returns None
    #   - Known IP, same MAC: refreshes last_seen, returns None
    #   - Known IP, different MAC: returns conflict dict (the spoofing signal)
    return table.update(src_ip, src_mac)
