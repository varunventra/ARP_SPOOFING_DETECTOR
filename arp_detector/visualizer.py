"""visualizer.py — networkx/matplotlib topology visualization.

IMPORTANT: matplotlib.use("Agg") is set here before any pyplot import.
Moving this line after a pyplot import breaks all visualization (no-op once
pyplot has initialized a backend). This placement is locked per Phase 1 decisions.
"""
import matplotlib
matplotlib.use("Agg")          # must precede all pyplot imports — do not reorder
import matplotlib.pyplot as plt
import networkx as nx
from networkx.drawing.layout import bipartite_layout


def draw_topology(arp_table_df, spoofed_ips=None, output_path="topology.png"):
    """Build a bipartite networkx graph (IPs left, MACs right) and save as PNG.

    Args:
        arp_table_df: pd.DataFrame with index name "ip" and column "mac".
                      Matches ARPTable.get_all() return shape.
        spoofed_ips:  set of IP strings to highlight red (and their MACs).
                      If None, defaults to empty set (all nodes green).
        output_path:  File path for the output PNG. Overwritten on each call.

    Returns:
        None. Creates a PNG file at output_path when DataFrame is non-empty.
        Returns immediately without creating a file when DataFrame is empty.
    """
    if len(arp_table_df) == 0:
        return

    if spoofed_ips is None:
        spoofed_ips = set()

    # Determine spoofed MACs: any MAC associated with a spoofed IP in the table
    spoofed_macs = set(
        arp_table_df.loc[ip, "mac"]
        for ip in spoofed_ips
        if ip in arp_table_df.index
    )
    red_nodes = spoofed_ips | spoofed_macs

    # Build bipartite graph: IPs on left (bipartite=0), MACs on right (bipartite=1)
    G = nx.Graph()
    ip_nodes = list(arp_table_df.index)
    mac_nodes = list(arp_table_df["mac"].unique())

    G.add_nodes_from(ip_nodes, bipartite=0)
    G.add_nodes_from(mac_nodes, bipartite=1)

    for ip, row in arp_table_df.iterrows():
        G.add_edge(ip, row["mac"])

    # Build node color list in G.nodes() iteration order
    node_colors = ["red" if n in red_nodes else "green" for n in G.nodes()]

    # Compute bipartite layout with IP nodes on the left side
    pos = bipartite_layout(G, ip_nodes)

    # Draw and save — plt.close(fig) MANDATORY to prevent figure accumulation
    fig, ax = plt.subplots(figsize=(12, 7))
    nx.draw_networkx(
        G,
        pos=pos,
        ax=ax,
        node_color=node_colors,
        node_size=1200,
        font_size=7,
        arrows=False,
    )
    ax.set_title("ARP Network Topology")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close(fig)   # CRITICAL: prevents figure accumulation across repeated calls


def save_final(output_path="topology.png"):
    """Thin wrapper kept as no-op — superseded by direct draw_topology() calls in main.py."""
    pass
