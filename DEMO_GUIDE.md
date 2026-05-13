# Demo Guide — 2 Minutes

## Setup (Do This Before Walking In)

Open two WSL terminals side by side. In both, cd to the project folder.

---

## The Demo

**Terminal 1 — start the detector:**
```bash
sudo python3 -m arp_detector.main --iface eth0 --visualize
```

Point at the live dashboard that appears.

> "This is our ARP spoofing detector running live. It already ran arp-scan at startup to learn every real IP-to-MAC mapping on the network — that's the baseline."

---

**Terminal 2 — trigger the attack:**
```bash
sudo python3 simulate_attack.py --iface eth0 --target-ip 192.168.1.1
```

A red alert panel immediately appears in Terminal 1.

> "That's our attack simulator sending forged ARP packets. The detector caught it instantly — it saw that 192.168.1.1 suddenly claimed a different MAC address, which is the exact signature of ARP spoofing. You can see the victim IP, the attacker's MAC, and the real MAC it should be."

---

**Ctrl+C in Terminal 1, then:**
```bash
bash scripts/analyze_log.sh arp_detector.log
```

> "On shutdown it saves a CSV report and a network topology PNG. This shell script uses grep and awk to parse the log — no Python. Shows total attacks, attacker MACs, and a timeline."

---

Done. That's the whole demo.

---

## If Something Breaks

Run this instead — no root, no live network needed:

```bash
python3 -c "
from scapy.all import rdpcap, ARP
from arp_detector.arp_table import ARPTable
from arp_detector.detector import check_packet
from arp_detector.logger import build_event
packets = rdpcap('demo_capture.pcap')
table = ARPTable()
for p in packets:
    if ARP in p:
        d = {'op': p[ARP].op, 'src_ip': p[ARP].psrc, 'src_mac': p[ARP].hwsrc, 'dst_ip': p[ARP].pdst}
        c = check_packet(d, table)
        if c: print('ATTACK:', build_event(c)['victim_ip'], '<-', build_event(c)['attacker_mac'])
"
```

> "This replays our pre-recorded attack pcap file and produces the same detections offline."
