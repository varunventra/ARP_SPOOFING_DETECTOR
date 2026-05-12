#!/bin/bash
# analyze_log.sh — Parse arp_detector.log (JSONL) and print a human-readable summary.
# Usage: bash scripts/analyze_log.sh [logfile]
# Argument $1: path to JSONL log file (default: arp_detector.log)
# Uses only grep and awk — no Python required.

LOGFILE="${1:-arp_detector.log}"

if [ ! -f "${LOGFILE}" ]; then
    echo "[ERROR] Log file not found: ${LOGFILE}" >&2
    exit 1
fi

echo "=== ARP Spoofing Attack Summary ==="
echo "Log file: ${LOGFILE}"
echo ""

# Total attack events: count lines containing "attacker_mac" key
ATTACK_COUNT=$(grep -c '"attacker_mac"' "${LOGFILE}" 2>/dev/null || echo 0)
echo "Total attacks detected: ${ATTACK_COUNT}"
echo ""

# Unique attacker MACs: extract attacker_mac values, sort, deduplicate
echo "Unique attacker MACs:"
grep -o '"attacker_mac": *"[^"]*"' "${LOGFILE}" \
    | awk -F'"' '{ print $4 }' \
    | sort -u \
    | awk '{ print "  " $0 }'
echo ""

# Attack timeline: extract timestamp + victim_ip fields
echo "Attack timeline:"
grep '"attacker_mac"' "${LOGFILE}" \
    | awk -F'"' '
        {
            ts = ""; vic = ""
            for (i=1; i<=NF; i++) {
                if ($i == "timestamp") ts = $(i+2)
                if ($i == "victim_ip") vic = $(i+2)
            }
            if (ts != "" && vic != "") print "  " ts " -> victim: " vic
        }
    '
echo ""
echo "=== End of Summary ==="
