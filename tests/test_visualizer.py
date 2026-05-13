"""tests/test_visualizer.py — Unit tests for draw_topology() and save_final().

Tests use synthetic DataFrames and pytest tmp_path — no root, no network, no display.
All tests designed to FAIL against the stub (RED state) and PASS after implementation (GREEN).
"""
import matplotlib.pyplot as plt
import pandas as pd
import pytest

from arp_detector.visualizer import draw_topology, save_final


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_df():
    """Two-row ARP table DataFrame matching ARPTable.get_all() shape."""
    return pd.DataFrame(
        [
            {"mac": "aa:bb:cc:dd:ee:ff", "first_seen": 1000.0, "last_seen": 1001.0},
            {"mac": "11:22:33:44:55:66", "first_seen": 1002.0, "last_seen": 1003.0},
        ],
        index=pd.Index(["192.168.1.1", "192.168.1.2"], name="ip"),
    )


@pytest.fixture()
def empty_df():
    """Zero-row ARP table DataFrame."""
    return pd.DataFrame(
        columns=["mac", "first_seen", "last_seen"],
        index=pd.Index([], name="ip", dtype=str),
    )


# ---------------------------------------------------------------------------
# TestDrawTopology
# ---------------------------------------------------------------------------

class TestDrawTopology:

    def test_creates_png_file(self, sample_df, tmp_path):
        """draw_topology() with a populated DataFrame creates a file at output_path."""
        out = tmp_path / "topology.png"
        draw_topology(sample_df, output_path=str(out))
        assert out.exists(), "draw_topology() must create a PNG file at output_path"

    def test_empty_dataframe_no_crash(self, empty_df, tmp_path):
        """draw_topology() with an empty DataFrame returns without raising and creates no file."""
        out = tmp_path / "topology.png"
        result = draw_topology(empty_df, output_path=str(out))
        assert result is None, "draw_topology() with empty DataFrame must return None"
        assert not out.exists(), "draw_topology() must NOT create a file for empty DataFrame"

    def test_overwrites_existing_file(self, sample_df, tmp_path):
        """draw_topology() called twice with same path overwrites the file."""
        out = tmp_path / "topology.png"
        draw_topology(sample_df, output_path=str(out))
        assert out.exists(), "first call must create the file"
        mtime_first = out.stat().st_mtime

        # Second call — file must be rewritten (mtime equal or newer)
        draw_topology(sample_df, output_path=str(out))
        assert out.exists(), "second call must keep the file present"
        mtime_second = out.stat().st_mtime
        assert mtime_second >= mtime_first, (
            "second call must overwrite (mtime of second call must be >= first)"
        )

    def test_spoofed_ip_in_red_nodes(self, sample_df, tmp_path):
        """draw_topology() with spoofed_ips set does not raise and creates the PNG.

        Red coloring is internal to the function; we verify no ValueError is raised
        and that the PNG is saved successfully.
        """
        out = tmp_path / "topology.png"
        # Should not raise even when a spoofed IP is provided
        draw_topology(sample_df, spoofed_ips={"192.168.1.2"}, output_path=str(out))
        assert out.exists(), "draw_topology() with spoofed_ips must still create the PNG"

    def test_save_final_no_crash(self, tmp_path):
        """save_final() is callable and does not raise (no-op stub in Phase 3)."""
        out = tmp_path / "final.png"
        # Must not raise regardless of whether it does anything
        save_final(output_path=str(out))

    def test_no_figure_leak(self, sample_df, tmp_path):
        """After 3 calls to draw_topology(), plt.get_fignums() returns an empty list.

        plt.close(fig) must be called after every savefig() call to prevent
        figure accumulation across repeated invocations.
        """
        # Close any pre-existing figures from other tests
        plt.close("all")

        for i in range(3):
            out = tmp_path / f"topology_{i}.png"
            draw_topology(sample_df, output_path=str(out))

        remaining = plt.get_fignums()
        assert remaining == [], (
            f"plt.close(fig) must be called after each savefig(); "
            f"{len(remaining)} figure(s) still open: {remaining}"
        )
