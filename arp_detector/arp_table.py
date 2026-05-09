"""arp_table.py — In-memory IP->MAC mapping table (DET-01).

Threading contract (Phase 1 lock):
  - This class is written EXCLUSIVELY from the main thread.
  - The AsyncSniffer callback thread (capture.py) only enqueues dicts into a
    threading.Queue — it never calls update() or check_conflict() directly.
  - This single-writer contract means no locks are needed inside this class.
  - DO NOT add threading.Lock() here; if you feel you need one, the caller is
    violating the single-writer contract instead.

Pandas 2.x note:
  - Use .loc[] and .at[] assignment only.
  - DataFrame.append() was removed in pandas 2.0 — never use it.
"""
import time
import pandas as pd


class ARPTable:
    """Pandas DataFrame wrapper for IP->MAC association tracking."""

    def __init__(self):
        self._df = pd.DataFrame(columns=['ip', 'mac', 'first_seen', 'last_seen'])
        self._df = self._df.set_index('ip')

    def update(self, ip: str, mac: str) -> dict | None:
        """Record or update an IP->MAC mapping.

        Returns:
            None if this is a new IP or a repeat of a known IP->MAC pair.
            A conflict dict if ip was previously mapped to a different MAC:
              {'ip': str, 'known_mac': str, 'new_mac': str, 'timestamp': float}
        """
        now = time.time()

        if ip in self._df.index:
            known_mac = self._df.at[ip, 'mac']
            if known_mac != mac:
                # IP is claiming a different MAC — spoofing candidate
                self._df.at[ip, 'last_seen'] = now
                return {
                    'ip': ip,
                    'known_mac': known_mac,
                    'new_mac': mac,
                    'timestamp': now,
                }
            else:
                # Same MAC re-announcing — refresh last_seen only
                self._df.at[ip, 'last_seen'] = now
                return None
        else:
            # New IP — record it; .loc[] is the pandas 2.x pattern
            self._df.loc[ip] = [mac, now, now]
            return None

    def check_conflict(self, ip: str, mac: str) -> dict | None:
        """Read-only conflict probe — does NOT modify the table.

        Returns:
            None if ip is unknown or if ip maps to the same mac.
            A conflict dict if ip maps to a different mac:
              {'ip': str, 'known_mac': str, 'new_mac': str, 'timestamp': float}
        """
        if ip not in self._df.index:
            return None
        known_mac = self._df.at[ip, 'mac']
        if known_mac != mac:
            return {
                'ip': ip,
                'known_mac': known_mac,
                'new_mac': mac,
                'timestamp': time.time(),
            }
        return None

    def get_all(self) -> pd.DataFrame:
        """Return a snapshot copy of the table.

        Callers receive a copy — mutations do not affect internal state.
        The DataFrame index is 'ip'; columns are 'mac', 'first_seen', 'last_seen'.
        """
        return self._df.copy()
