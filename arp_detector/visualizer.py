"""visualizer.py — networkx/matplotlib topology visualization.

IMPORTANT: matplotlib.use("Agg") is set here before any pyplot import.
Moving this line after a pyplot import breaks all visualization (no-op once
pyplot has initialized a backend). This placement is locked per Phase 1 decisions.
"""
import matplotlib
matplotlib.use("Agg")          # must precede all pyplot imports — do not reorder
import matplotlib.pyplot as plt


def draw_topology(arp_table_df, spoofed_ips=None, output_path="topology.png"):
    """Stub — generates networkx bipartite topology PNG. Implemented in Phase 3."""
    pass


def save_final(output_path="topology.png"):
    """Stub — saves final topology PNG on session end. Implemented in Phase 3."""
    pass
