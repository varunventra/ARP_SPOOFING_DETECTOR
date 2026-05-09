"""capture.py — ARP packet capture engine (CAP-01, CAP-02, CAP-03, CAP-04).

Architecture contract (Phase 1 lock — do not violate):
  - AsyncSniffer runs in a daemon thread managed by scapy internals.
  - The packet callback (build_packet_callback closure) ONLY puts dicts onto
    a threading.Queue. It never writes to a DataFrame, never calls
    ARPTable.update(), never calls detector.check_packet().
  - The main thread is the SOLE writer to ARPTable. It reads from the Queue
    in a loop and dispatches to detector.check_packet().
  - This single-writer contract means no threading.Lock is needed on ARPTable.
    If you feel you need a lock, the caller is breaking this contract.

store=False contract (Phase 1 lock — do not change):
  - All AsyncSniffer and sniff() calls MUST set store=False.
  - Default is store=True which accumulates every packet in RAM.
  - A demo session OOMs without this. Retrofitting requires rewriting the loop.
"""
from __future__ import annotations

import argparse
import os
import queue
import sys
import time

from scapy.all import ARP, AsyncSniffer, get_if_list


def check_root() -> None:
    """Verify the process is running as root (uid=0).

    Per PITFALLS C1: add this check as the very first operation before any
    scapy import side effects. An ungraceful PermissionError during a graded
    demo is a hard fail. This prints a clear, actionable message.

    On Windows/environments without os.geteuid (non-POSIX), the check is skipped
    gracefully — packet capture still requires appropriate privileges in WSL/Linux.

    Exits with code 1 if not root.
    """
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        # Non-POSIX platform (Windows native) — skip uid check
        return
    if geteuid() != 0:
        print(
            "[ERROR] This tool requires root privileges.\n"
            "        Run with: sudo python3 capture.py",
            file=sys.stderr,
        )
        sys.exit(1)


def get_default_iface() -> str:
    """Return the first non-loopback interface from scapy get_if_list().

    Per PITFALLS C2: WSL2 interface names are not guaranteed to be eth0.
    Always discover at runtime. Print the available list before selecting.

    Exits with code 1 if no usable interface is found.
    """
    all_ifaces = get_if_list()
    candidates = [i for i in all_ifaces if i != "lo"]
    if not candidates:
        print(
            f"[ERROR] No non-loopback network interfaces found.\n"
            f"        Available interfaces: {all_ifaces}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"[*] Available interfaces: {candidates}")
    print(f"[*] Auto-selected interface: {candidates[0]}")
    return candidates[0]


def parse_cli_args() -> argparse.Namespace:
    """Parse CLI arguments for capture.py.

    --iface: Network interface to sniff on. If omitted, get_default_iface()
             is called to auto-detect.

    Returns:
        argparse.Namespace with attribute .iface (str or None).
    """
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Detector — packet capture module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--iface",
        default=None,
        help=(
            "Network interface to sniff (e.g. eth0, enp0s3). "
            "If omitted, the first non-loopback interface is used."
        ),
    )
    return parser.parse_args()


def build_packet_callback(packet_queue: queue.Queue):
    """Return a closure that filters ARP op=2 packets and enqueues parsed dicts.

    Threading contract: this closure runs in the AsyncSniffer thread.
    It ONLY enqueues — it never writes to ARPTable or calls check_packet().

    The closure filters:
      - Non-ARP packets -> dropped (haslayer(ARP) check)
      - ARP op=1 requests -> dropped (only op=2 replies carry MAC claims)
      - op=2 replies -> enqueued as dict

    Note on gratuitous ARP: gratuitous ARP filtering (psrc == pdst) is
    detector.check_packet()'s responsibility, not the callback's. The callback
    enqueues all op=2 packets and lets detector.py apply semantic rules.

    Packet dict shape produced (matches detector.check_packet() contract):
      {
          'src_ip':    str,    # ARP sender IP   (pkt[ARP].psrc)
          'src_mac':   str,    # ARP sender MAC  (pkt[ARP].hwsrc)
          'dst_ip':    str,    # ARP target IP   (pkt[ARP].pdst)
          'op':        int,    # ARP operation   (always 2 here)
          'timestamp': float,  # time.time() at enqueue moment
      }
    """
    def callback(pkt) -> None:
        # Gate 1: must be an ARP packet
        if not pkt.haslayer(ARP):
            return
        # Gate 2: only ARP replies carry IP->MAC claims (CAP-04)
        if pkt[ARP].op != 2:
            return
        # Enqueue parsed dict — no DataFrame writes here (threading contract)
        packet_queue.put({
            'src_ip':    pkt[ARP].psrc,
            'src_mac':   pkt[ARP].hwsrc,
            'dst_ip':    pkt[ARP].pdst,
            'op':        pkt[ARP].op,
            'timestamp': time.time(),
        })

    return callback


def start_capture(iface: str, packet_queue: queue.Queue) -> AsyncSniffer:
    """Create and start an AsyncSniffer for ARP capture on the given interface.

    store=False is mandatory — see module docstring.
    The sniffer runs as a daemon thread (scapy default for AsyncSniffer).

    Args:
        iface:        Network interface name (e.g. "eth0", "enp0s3").
        packet_queue: Queue that the callback will put packet dicts onto.

    Returns:
        The running AsyncSniffer object. Caller is responsible for calling
        sniffer.stop() during graceful shutdown.
    """
    sniffer = AsyncSniffer(
        iface=iface,
        filter="arp",                                  # BPF: kernel-level ARP filter
        prn=build_packet_callback(packet_queue),       # callback runs in sniffer thread
        store=False,                                   # MANDATORY — prevents RAM OOM
    )
    sniffer.start()
    return sniffer


def main() -> None:
    """Entry point for running capture.py directly (not as a module).

    Full startup sequence:
      1. Root check (must be first — see PITFALLS C1)
      2. Parse CLI args
      3. Resolve interface (--iface or auto-detect)
      4. Start AsyncSniffer
      5. Main thread reads Queue and dispatches to detection (Phase 2)
    """
    check_root()  # exit(1) if not root — must be first

    args = parse_cli_args()
    iface = args.iface if args.iface else get_default_iface()

    print(f"[*] Starting ARP capture on interface: {iface}")

    packet_queue: queue.Queue = queue.Queue()
    sniffer = start_capture(iface, packet_queue)

    print(f"[*] Sniffer started. Waiting for ARP packets... (Ctrl+C to stop)")

    try:
        while True:
            try:
                pkt_dict = packet_queue.get(timeout=0.1)
                # Phase 2 will wire this to detector.check_packet() + alerts
                print(f"    ARP reply: {pkt_dict['src_ip']} is at {pkt_dict['src_mac']}")
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
        sniffer.stop()
        print("[*] Capture stopped. Goodbye.")


if __name__ == "__main__":
    main()
