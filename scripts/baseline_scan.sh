#!/bin/bash
# baseline_scan.sh — Run arp-scan --localnet and output IP<TAB>MAC lines.
# Usage: sudo bash scripts/baseline_scan.sh
# Output: one line per discovered host, format: IP<TAB>MAC
# Header and footer lines from arp-scan are silently discarded.

arp-scan --localnet | awk -F'\t' '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1 "\t" $2 }'
