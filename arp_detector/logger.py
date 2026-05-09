"""logger.py — Persistent JSONL event logger for the ARP spoofing detector.

Implements two components:
  1. JSONLLogger — opens a log file in append mode, writes one JSON line per event,
     flushes immediately after each write, and closes cleanly on shutdown.
  2. build_event() — transforms the ARPTable conflict dict into the locked
     DET-05 event dict (6 required keys).

Requirements addressed:
  DET-05 — Structured attack event dict (6 locked fields)
  ALT-03 — Persistent log file written on every detected attack
  ALT-04 — Log file flushed immediately so content is readable between events
"""
import json
from datetime import datetime


def build_event(conflict: dict) -> dict:
    """Transform an ARPTable conflict dict into the locked DET-05 event dict.

    Args:
        conflict: dict returned by ARPTable.update() on a conflict:
            {'ip': str, 'known_mac': str, 'new_mac': str, 'timestamp': float}

    Returns:
        DET-05 event dict with exactly 6 keys:
            timestamp   — ISO 8601 string derived from conflict['timestamp']
            attacker_mac — the MAC claiming the IP (conflict['new_mac'])
            victim_ip    — the IP being spoofed (conflict['ip'])
            original_mac — the legitimate MAC (conflict['known_mac'])
            spoofed_mac  — same as attacker_mac per DET-05 spec
            attack_type  — constant "ARP_SPOOFING"
    """
    return {
        'timestamp': datetime.fromtimestamp(conflict['timestamp']).isoformat(),
        'attacker_mac': conflict['new_mac'],
        'victim_ip': conflict['ip'],
        'original_mac': conflict['known_mac'],
        'spoofed_mac': conflict['new_mac'],
        'attack_type': 'ARP_SPOOFING',
    }


class JSONLLogger:
    """Append-mode JSONL log writer.

    Opens the log file in append mode ('a') so existing entries are preserved
    across restarts. Each log_event() call writes exactly one JSON line and
    flushes the OS buffer immediately (ALT-04) so the file is readable between
    events with `cat` or `tail -f`.

    Usage::

        logger = JSONLLogger("arp_detector.log")
        logger.log_event(build_event(conflict))
        # ... later on shutdown ...
        logger.close()
    """

    def __init__(self, path: str = "arp_detector.log") -> None:
        """Open the log file in append mode.

        Args:
            path: Path to the log file. Defaults to "arp_detector.log" in the
                  current working directory.
        """
        self._fh = open(path, "a", encoding="utf-8")

    def log_event(self, event: dict) -> None:
        """Write one JSON line and flush immediately.

        Args:
            event: Any dict (typically the DET-05 event dict from build_event()).
                   Written as a single line of JSON followed by a newline.
        """
        self._fh.write(json.dumps(event) + "\n")
        self._fh.flush()

    def flush(self) -> None:
        """Explicitly flush the file buffer to disk."""
        self._fh.flush()

    def close(self) -> None:
        """Flush and close the file handle.

        Safe to call multiple times only if the caller checks _fh.closed first.
        After close(), _fh.closed is True.
        """
        self._fh.flush()
        self._fh.close()
