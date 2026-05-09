"""baseline.py — arp-scan subprocess wrapper that seeds ARPTable before sniffing (DET-02).

Subprocess contract:
  - Uses subprocess.run() with list-form args (NEVER shell=True).
  - capture_output=True, text=True, timeout parameter (default 30 s).
  - Runs: ["arp-scan", "--localnet"]
  - On FileNotFoundError (binary absent): prints warning to stderr, returns 0.
  - On subprocess.TimeoutExpired: prints warning to stderr, returns 0.

Output lines parsed:
  - Only lines where the first tab-separated field matches an IPv4 pattern are data lines.
  - All header/footer lines (e.g. "Interface:", "Starting", "packets received") are silently skipped.
"""
import re
import subprocess
import sys

from arp_detector.arp_table import ARPTable

# Compiled IPv4 address pattern — used to distinguish data lines from header/footer.
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

__all__ = ["load_baseline"]


def load_baseline(table: ARPTable, timeout: int = 30) -> int:
    """Run arp-scan --localnet and seed *table* with every discovered IP/MAC pair.

    Args:
        table:   An ARPTable instance to populate with baseline host entries.
        timeout: Seconds to wait for arp-scan before giving up (default 30).

    Returns:
        The number of valid host entries loaded into *table*.
        Returns 0 if arp-scan is not installed or if it times out.
    """
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print(
            "WARNING: arp-scan binary not found — baseline table will be empty. "
            "Install arp-scan or run as root in a Linux/WSL environment.",
            file=sys.stderr,
        )
        return 0
    except subprocess.TimeoutExpired:
        print(
            f"WARNING: arp-scan timed out after {timeout} s — baseline table will be empty.",
            file=sys.stderr,
        )
        return 0

    count = 0
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and _IP_RE.match(parts[0].strip()):
            ip = parts[0].strip()
            mac = parts[1].strip()
            table.update(ip, mac)
            count += 1

    return count
