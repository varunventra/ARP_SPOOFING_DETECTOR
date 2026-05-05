# Research Summary: ARP Spoofing Detector

**Synthesized:** 2026-05-05
**Sources:** STACK.md, FEATURES.md, ARCHITECTURE.md, PITFALLS.md

---

## Recommended Stack

| Tool / Library    | Version     | Role                                          |
|-------------------|-------------|-----------------------------------------------|
| Python            | 3.11+       | Runtime (Ubuntu 22.04/24.04 default)          |
| scapy             | 2.5.x       | Packet capture and ARP packet parsing         |
| pandas            | 2.1+        | IP-MAC mapping table; CSV report export       |
| networkx          | 3.x         | Graph data structure and layout algorithms    |
| matplotlib        | 3.8.x       | Rendering backend for networkx (Agg/PNG only) |
| rich              | 13.x        | Live terminal dashboard, colored alerts       |
| logging (stdlib)  | stdlib      | Persistent flat log file                      |
| argparse (stdlib) | stdlib      | CLI interface (--iface, --baseline, --log)    |
| arp-scan          | apt package | Active baseline scan of LAN at startup        |
| tcpdump           | apt package | Parallel pcap capture (evidence + demo req.)  |

**Do not use:** colorama (rich supersedes it), dpkt/pyshark (heavier than scapy), SQLite (overkill),
plt.show() inside the capture loop (blocks), pandas .append() (removed in 2.0).

---

## Table Stakes Features

These are non-negotiable -- missing any one means the tool does not function as claimed.

- **Live ARP packet capture** -- scapy.sniff(filter="arp", prn=callback, store=False) in a background thread; requires root
- **In-memory IP-MAC mapping table** -- pandas DataFrame keyed on IP; tracks first_seen, last_seen, count
- **Conflict detection on ARP reply** -- compare arp.hwsrc against known table entry on every op==2 packet
- **Gratuitous ARP detection** -- detect and log (but not alarm on) packets where psrc == pdst
- **Baseline population at startup** -- call arp-scan --localnet via subprocess before sniffing; cold-start without this produces false positives from the first minute
- **Root privilege guard** -- os.geteuid() != 0 check at startup with a clear exit message; ungraceful PermissionError during demo is a hard fail
- **Dynamic interface detection** -- get_if_list() at startup + --iface CLI arg; hardcoding eth0 silently captures nothing in many WSL2 configurations
- **Colored console alert** -- rich Panel/Console with red highlight on conflict detection
- **Persistent log file** -- JSONL format (grep-friendly; pandas-loadable for the summary report)
- **Graceful Ctrl+C shutdown** -- flush log, save final topology PNG, print summary stats

---

## Architecture in One Diagram

```
[WSL2 Network Interface]
          |
          | raw packets (BPF filter="arp")
          v
  [capture.py]  <-- background Thread (daemon=True)
  AsyncSniffer
          |
          | parsed dict: {ip, mac, op, timestamp}
          | -> threading.Queue  (ONLY shared state between threads)
          v
  [main.py -- Main Thread]
  reads Queue, dispatches
          |
          +--> [arp_table.py]  -- pandas DataFrame, write-only from main thread
          |          |
          |          | conflict? (same IP, different MAC)
          |          v
          |    [detector.py]  -- rule: op==2, psrc in table, hwsrc != known
          |          |
          |     -----+------
          |     |          |
          v     v          v
   [alerts.py]        [logger.py]
   rich Console        JSONL append
   red panel           -> arp_spoofing.log
          |
          | on-demand (attack event or --visualize flag)
          v
   [visualizer.py]
   networkx graph -> matplotlib Agg -> topology.png
   (NEVER plt.show() -- always savefig to PNG)

[shell_tools.py]  -- called at startup and on exit
  subprocess.run(arp-scan)       -> seeds arp_table.py baseline
  subprocess.Popen(tcpdump)      -> background pcap for evidence
  subprocess.run(analyze_log.sh) -> post-run summary

[scripts/]
  baseline_scan.sh    arp-scan | awk -> CSV
  analyze_log.sh      grep/awk summary of JSONL log
  capture_raw.sh      tcpdump to .pcap
  simulate_attack.py  crafts spoofed ARP replies via scapy sendp()
```

---

## Critical Decisions (make these in Phase 1)

These are expensive to reverse if deferred. All four research files converge on them.

**1. Threading model: AsyncSniffer + Queue + single-writer DataFrame**
scapy sniff() blocks, so it must run in a background thread. The safest pattern is one Queue
between the capture thread and the main thread, with the DataFrame written exclusively from the
main thread. Adding locks to a shared-write DataFrame later is painful to retrofit.

**2. matplotlib backend: Agg (file output only)**
plt.show() inside WSL2 will either block the capture loop or fail entirely due to no $DISPLAY
variable. Set matplotlib.use("Agg") before any import of matplotlib.pyplot. One-line decision
with high penalty if missed -- refactoring touches every visualization code path.

**3. store=False on sniff() -- mandatory, not default**
The default store=True accumulates every packet in RAM. A demo session with moderate traffic
will OOM. Set store=False in Phase 1; retrofitting means rewriting the capture loop.

**4. Demo strategy: self-contained simulation, not real LAN traffic**
WSL2 runs behind Hyper-V NAT -- real LAN ARP traffic does not reach the WSL2 interface. The
demo cannot rely on physical devices. Commit to simulate_attack.py (crafted scapy sendp()
packets) plus a pre-recorded demo_capture.pcap as fallback. This decision shapes test
infrastructure from Phase 1.

**5. Pandas 2.x: use .loc[] assignment, never .append()**
DataFrame.append() was removed in pandas 2.0. Many tutorials still use it. Establish the
correct arp_table.loc[src_ip] = [...] pattern in arp_table.py once and use it everywhere.

---

## Watch Out For

Ranked by demo-breaking severity (highest first):

**1. (Demo killer) Root privilege not checked early**
scapy.sniff() silently captures nothing or crashes without root. Add os.geteuid() != 0 guard
as the very first line of main(). Run the entire tool with: sudo python3 main.py  [PITFALLS C1]

**2. (Demo killer) Wrong or hardcoded network interface**
eth0 can be enX0 or enp0s3 depending on WSL version. Use get_if_list() to discover at runtime;
accept --iface override; print the active interface at startup.  [PITFALLS C2]

**3. (Demo killer) plt.show() blocks capture loop**
Calling plt.show() in any code path that runs during capture freezes detection. Use
matplotlib.use("Agg") at the top of visualizer.py, always use plt.savefig().  [PITFALLS C4, W1]

**4. (False positives that confuse demo) Gratuitous ARP not filtered**
Devices at boot send op==2 with psrc == pdst. These look structurally identical to spoofed
replies. Filter before checking the table: if pkt[ARP].psrc == pkt[ARP].pdst: return
[PITFALLS M1]

**5. (Cold-start noise) No baseline before live detection**
Without a pre-populated table, the first ARP reply for any IP is treated as ground truth, and
the second reply for that IP fires a false alarm. Always run arp-scan baseline before the
sniffer starts.  [PITFALLS M2]

---

## Demo Strategy

WSL2 Hyper-V NAT means real LAN devices are invisible to the sniffer. The entire demo must be
self-contained inside WSL2.

**Primary: Two-terminal simulation**

Terminal 1 -- run the detector:

    sudo python3 main.py --iface eth0

Terminal 2 -- run simulate_attack.py (find gateway first: ip route | grep default):

    from scapy.all import ARP, Ether, sendp
    import time
    GATEWAY_IP = '172.x.x.1'         # replace with your actual gateway IP
    FAKE_MAC   = 'de:ad:be:ef:00:01'
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(
        op=2, psrc=GATEWAY_IP, hwsrc=FAKE_MAC,
        pdst='0.0.0.0', hwdst='ff:ff:ff:ff:ff:ff'
    )
    for i in range(5):
        sendp(pkt, iface='eth0', verbose=False)
        time.sleep(1)

The detector fires after the second packet (first establishes the table entry; second conflicts).

**Backup: Pre-recorded pcap replay**

Record once before demo day:

    sudo tcpdump -i eth0 arp -w demo_capture.pcap
    # run simulate_attack.py in Terminal 2, then Ctrl+C

On demo day, pass --demo flag to replay rdpcap(demo_capture.pcap) if live capture fails.

**Pre-demo checklist:**

- ip route | grep default  ->  confirm gateway IP; update GATEWAY_IP in simulate_attack.py
- ip link show  ->  confirm interface name; use with --iface
- sudo python3 main.py --iface eth0 runs without errors
- simulate_attack.py produces visible red alerts in the detector
- topology.png is saved after the attack
- demo_capture.pcap exists as offline fallback

---

## Build Order

Dependencies flow strictly downward. Each phase is independently testable before the next begins.

**Phase 1 -- Core data layer + capture skeleton (no root needed for unit tests)**

    arp_table.py   -- pandas DataFrame; update() and check_conflict() methods; zero dependencies
         |
    detector.py    -- conflict logic; testable with synthetic {ip, mac} dicts
         |
    capture.py     -- AsyncSniffer -> Queue -> callback; test by replaying .pcap

Set matplotlib.use("Agg"), threading architecture, store=False, root guard, and dynamic
interface detection in this phase before writing any detection logic.

**Phase 2 -- Output and alerting**

    logger.py        -- JSONL append; flush on exit; no network needed
         |
    alerts.py        -- rich Console + Panel; test with dummy conflict dicts
         |
    main.py (stub)   -- wire capture -> detector -> alerts + logger; Ctrl+C shutdown

Add gratuitous ARP filtering (psrc == pdst guard). Build baseline phase: arp-scan load before
live detection starts. Add VM/Docker MAC whitelist (low effort, prevents startup false alarms).

**Phase 3 -- Visualization**

    visualizer.py      -- networkx bipartite graph -> matplotlib Agg -> PNG
                          test with synthetic arp_table data; no live capture needed
         |
    main.py (update)   -- call visualizer on attack event and on shutdown

Use bipartite layout (IPs on left, MACs on right) -- cleaner than spring layout for small
networks. Batch refresh every 2s, not per-packet, to prevent flicker.

**Phase 4 -- Shell integration**

    shell_tools.py     -- subprocess wrappers: arp-scan, tcpdump Popen, log summary
         |
    scripts/           -- baseline_scan.sh, analyze_log.sh, capture_raw.sh
         |
    simulate_attack.py -- attacker simulation script (separate file, demo use only)

Always set timeout=30 on subprocess.run() calls. Test arp-scan output parsing against a saved
file before integrating. Test analyze_log.sh on a pre-built log file.

**Phase 5 -- Integration and demo prep**

    main.py (final) -- full startup sequence:
        1. root check
        2. dynamic iface detection
        3. arp-scan baseline -> arp_table
        4. start tcpdump Popen
        5. start AsyncSniffer
        6. rich.Live main loop
        7. Ctrl+C -> flush log -> save PNG -> run analyze_log.sh -> exit
         |
    demo_capture.pcap   -- record once with simulate_attack.py
    requirements.txt    -- pin all versions
    README.md           -- run instructions, WSL2 notes, demo steps

---

## Confidence Assessment

| Area                | Confidence | Notes                                                                   |
|---------------------|------------|-------------------------------------------------------------------------|
| Stack choices       | HIGH       | All APIs stable across multiple major versions                          |
| Detection algorithm | HIGH       | Deterministic conflict detection; established RFC 826 practice          |
| Architecture        | HIGH       | Queue + daemon thread is standard Python; no WSL concerns in data layer |
| Shell integration   | MEDIUM     | arp-scan output format stable but not verified vs. current apt package  |
| WSL2 behavior       | MEDIUM     | Hyper-V NAT confirmed; WSLg display is Windows-version-dependent        |
| Visualization       | MEDIUM     | networkx API stable; bipartite layout from community patterns           |

**Key gap:** arp-scan output parsing is the most fragile integration point. Test it first on
the actual lab machine before building the baseline loader around it.

---

## Sources

- RFC 826 (ARP protocol), RFC 5227 (Gratuitous ARP behavior)
- scapy 2.5.x documentation (sniff, AsyncSniffer, ARP layer fields)
- pandas 2.x migration guide (DataFrame.append removal)
- networkx 3.x documentation (draw, spring_layout, bipartite)
- matplotlib documentation (Agg backend, savefig)
- rich 13.x documentation (Console, Table, Live, Panel)
- arpwatch (LBNL reference implementation) -- pattern reference only
- ettercap / arpspoof attack signatures -- detection target characterization
- WSL2 networking architecture (Microsoft docs, training data to Aug 2025)