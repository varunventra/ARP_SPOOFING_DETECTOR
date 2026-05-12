#!/bin/bash
# capture_raw.sh — Capture raw ARP traffic to a .pcap file using tcpdump.
# Usage: sudo bash scripts/capture_raw.sh [output.pcap]
# Argument $1: output file path (default: capture.pcap)
# Press Ctrl+C to stop capture. The .pcap file is usable by rdpcap() in scapy.

OUTPUT="${1:-capture.pcap}"
echo "[*] Starting ARP capture -> ${OUTPUT}"
echo "[*] Press Ctrl+C to stop."
tcpdump -n arp -w "${OUTPUT}"
echo "[*] Capture saved to ${OUTPUT}"
