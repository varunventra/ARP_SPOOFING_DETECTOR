# Demo Guide

## Setup (Do This Before Walking In)

Open **two WSL terminals** side by side. In both, run:
```bash
cd /mnt/c/Users/varun/OneDrive/Desktop/teamproject
```

---

## Step 1 — Start the Detector

**Terminal 1:**
```bash
sudo python3 -m arp_detector.main --iface eth0 --visualize
```

Wait until you see `172.26.160.1` appear in the ARP table with its real MAC.

**Say:**
> "This is our ARP spoofing detector running live. It's listening to all ARP traffic on the network and building a table of which IP belongs to which MAC address."

---

## Step 2 — Trigger the Attack

**Terminal 2:**
```bash
sudo python3 simulate_attack.py --iface eth0 --target-ip 172.26.160.1
```

Red alerts will immediately appear in Terminal 1.

**Say:**
> "This simulates an attacker sending fake ARP packets claiming that IP 172.26.160.1 belongs to a different MAC address. The detector catches it instantly — you can see the alerts firing in real time with the timestamp, the victim IP, and the attacker's MAC."

---

## Step 3 — Show the Log

Press **Ctrl+C** in Terminal 1, then run:
```bash
bash scripts/analyze_log.sh arp_detector.log
```

**Say:**
> "On shutdown it saves everything to a log file. This shell script uses grep and awk to parse it and give a summary — total attacks, the attacker's MAC, and a full timeline. No Python needed for this part."

---

## Done.

---

## If Something Goes Wrong

If no alerts appear — you ran the attack before the detector was ready. Just restart:
1. Ctrl+C in both terminals
2. Delete the old log: `rm -f arp_detector.log`
3. Start Terminal 1 again, wait for the IP to appear, then run Terminal 2
