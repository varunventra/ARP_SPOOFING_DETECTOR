"""reporter.py — CSV attack report writer for the ARP spoofing detector.

Implements generate_report() which wraps a list of DET-05 event dicts in a
pandas DataFrame, saves it to a CSV file (index=False), and returns both the
DataFrame and a summary statistics dict.

Requirements addressed:
  LOG-01 — generate_report() creates a CSV from DET-05 events
  LOG-02 — CSV is loadable by pd.read_csv() without errors (round-trip safe)
"""
import pandas as pd

_COLUMNS = [
    "timestamp",
    "attacker_mac",
    "victim_ip",
    "original_mac",
    "spoofed_mac",
    "attack_type",
]


def generate_report(
    events: list,
    total_packets: int = 0,
    output_path: str = "attack_report.csv",
) -> tuple:
    """Build a pandas DataFrame from DET-05 events and write it to CSV.

    Args:
        events: List of DET-05 event dicts (from logger.build_event()).
                Each dict must have the 6 locked keys: timestamp, attacker_mac,
                victim_ip, original_mac, spoofed_mac, attack_type.
        total_packets: Total ARP packets captured in the session (default 0).
        output_path: Destination path for the CSV file.
                     Defaults to "attack_report.csv" in the current directory.

    Returns:
        (df, summary) where:
          df      — pandas DataFrame of all events (0 rows if events is empty,
                    but with all 6 column headers preserved).
          summary — dict with keys:
                      total_packets       — the total_packets argument value
                      total_attacks       — number of rows in df (len(events))
                      unique_attacker_macs — count of distinct attacker MACs
                                             (plain Python int, not numpy int64)

    Notes:
        - Empty events list → pd.DataFrame(columns=_COLUMNS) so that the
          written CSV retains the 6 column headers (LOG-02 round-trip check).
        - index=False ensures no row index column is written to the CSV.
        - unique_attacker_macs is cast with int() to avoid returning a numpy
          int64, which would break equality checks against Python int literals.
    """
    if events:
        df = pd.DataFrame(events)
        # Ensure column order and presence even if input dicts have extra keys
        df = df.loc[:, [col for col in _COLUMNS if col in df.columns]]
    else:
        df = pd.DataFrame(columns=_COLUMNS)

    df.to_csv(output_path, index=False)

    summary = {
        "total_packets": total_packets,
        "total_attacks": len(df),
        "unique_attacker_macs": int(df["attacker_mac"].nunique()) if len(df) > 0 else 0,
    }

    return df, summary
