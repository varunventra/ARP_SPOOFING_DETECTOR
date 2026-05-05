# Pitfalls: ARP Spoofing Detector

**Domain:** Python network security tool (scapy + pandas + matplotlib + shell)
**Researched:** 2026-05-05
**Confidence:** HIGH for scapy/networking (stable, well-documented domain) | MEDIUM for WSL2 quirks (version-dependent)

---

## Critical Pitfalls (blockers if not addressed)

These will break the demo or prevent the tool from running at all.

---

### C1: scapy requires root — ungraceful failure kills the demo

**What goes wrong:** `scapy.sniff()` calls raw sockets under the hood. If run as a non-root user, scapy raises `PermissionError` (or silently captures nothing on some versions). A bare uncaught exception during a graded demo is a hard fail.

**Warning sign:** Running `python detector.py` as normal user — either crashes immediately or `sniff()` returns with 0 packets and the tool appears to "work" but does nothing.

**Prevention:**
```python
import os, sys

def check_root():
    if os.geteuid() != 0:
        sys.exit("[ERROR] This tool requires root privileges. Run with: sudo python detector.py")
```
Add this check at the very top of `main()`, before any scapy import side effects. Print a clear, helpful message — not a raw traceback.

**Phase:** Address in Phase 1 (core capture skeleton) before anything else is built on top.

---

### C2: Wrong network interface — sniff() captures nothing

**What goes wrong:** `scapy.sniff(iface="eth0", ...)` hardcoded to `eth0` will fail silently on WSL2 (interface is typically `eth0` but can be `enX0`, `enp0s...`, etc. depending on WSL version and host NIC). On a VM it might be `ens33` or `virbr0`. No error is thrown — it just captures nothing. The demo shows zero detections.

**Warning sign:** `sniff()` runs without error but the packet count stays at 0 even with network activity.

**Prevention:**
```python
from scapy.arch import get_if_list

def get_default_interface():
    """Return first non-loopback interface, or let user specify via --iface."""
    ifaces = [i for i in get_if_list() if i != "lo"]
    if not ifaces:
        sys.exit("[ERROR] No network interfaces found.")
    return ifaces[0]
```
Also accept `--iface` as a CLI argument so the demo operator can override. Print which interface is being used at startup: `[*] Sniffing on interface: eth0`.

**Phase:** Phase 1. Hardcoded interface is a demo-day risk — make it dynamic from the start.

---

### C3: scapy sniff() with store=True fills RAM on long-running capture

**What goes wrong:** `sniff(filter="arp", store=True)` accumulates every packet in a list in memory. In a long demo session or if general traffic is heavy, this can consume hundreds of MB. The process eventually slows or OOMs.

**Warning sign:** Memory usage climbs steadily during capture. The tool gets sluggish after a few minutes.

**Prevention:** Always use the `prn` callback pattern — never `store=True` for a live tool:
```python
def process_packet(pkt):
    if pkt.haslayer(ARP):
        detect_spoofing(pkt)

scapy.sniff(filter="arp", prn=process_packet, store=False)
```
`store=False` is not the default — you must explicitly set it. The `prn` callback processes each packet immediately and discards it.

**Phase:** Phase 1. This is an architectural decision — retrofitting it later means rewriting the capture loop.

---

### C4: matplotlib plt.show() blocks the main thread — live detection freezes

**What goes wrong:** Calling `plt.show()` in the same thread as `scapy.sniff()` blocks. The packet capture loop stops while the graph window is open, or vice versa. You cannot have both running "live" without threading or the non-interactive backend.

**Warning sign:** Graph opens, all ARP detection stops. Or the graph never opens because sniff() never yields.

**Prevention (two options — pick one):**

Option A: Run visualization in a separate thread:
```python
import threading
import matplotlib
matplotlib.use("Agg")  # non-interactive — saves to file, no GUI block
```

Option B: Use `plt.pause(interval)` instead of `plt.show()` and call it periodically from a thread:
```python
# In a dedicated visualization thread
plt.ion()  # interactive mode
while running:
    update_graph()
    plt.pause(0.5)  # yields control, updates display
```

For a WSL demo: Option A (save graph to PNG, display path in terminal) is the most reliable because WSL display forwarding adds its own complexity (see WSL-Specific section). The grader can open the PNG after the demo.

**Phase:** Phase 3 (visualization). But choose the approach in Phase 1 architecture — threading model must be decided early.

---

### C5: WSL2 ARP sniffing may not see real LAN traffic

**What goes wrong:** WSL2 runs behind a virtual NAT switch (Hyper-V vEthernet). ARP traffic from real LAN devices (your physical network) does not reach the WSL2 network interface. `scapy.sniff(filter="arp")` inside WSL2 only sees ARP traffic between WSL2 itself, the Windows host, and the virtual gateway. This means a demo relying on "real" LAN devices being detected will show nothing.

**Warning sign:** `tcpdump -i eth0 arp` inside WSL2 shows only a handful of hosts (WSL IP, Windows IP, default gateway) — not the full LAN.

**Prevention:** The demo must be self-contained — simulate the attacker and victim within WSL2 using scapy's `send()` (see Demo/Testing Strategy section). Do not rely on capturing traffic from physical LAN devices. The detection logic itself is network-agnostic; the key is getting ARP packets into the capture stream, which simulated packets achieve perfectly.

**Phase:** Address in Phase 1 before writing the detection logic. Designing for simulated input from the start avoids a last-minute architecture scramble.

---

## Moderate Pitfalls (degrade quality)

These cause false positives, misleading output, or reduced demo quality — but the tool still runs.

---

### M1: Gratuitous ARPs trigger false positives

**What goes wrong:** A gratuitous ARP is a device announcing its own IP-MAC mapping (used at boot, after IP change, for failover). It looks structurally identical to a spoofed ARP — same IP appearing with a new MAC. Naively flagging every IP-MAC conflict fires false alarms during normal network operation.

**Warning sign:** Every time a device rejoins the network or renews its IP, the detector alerts.

**Prevention:** Distinguish op codes:
```python
# ARP op=1 is request, op=2 is reply
if pkt[ARP].op == 2:  # only analyze replies
    src_ip = pkt[ARP].psrc
    src_mac = pkt[ARP].hwsrc
    # check if src_ip already mapped to a DIFFERENT mac
```
For gratuitous ARPs specifically: if the sender's IP and the target IP are the same (`pkt[ARP].psrc == pkt[ARP].pdst`), it is a gratuitous ARP. Log it but don't alert:
```python
if pkt[ARP].psrc == pkt[ARP].pdst:
    logger.debug(f"Gratuitous ARP from {src_ip} ({src_mac}) — skipped")
    return
```

**Phase:** Phase 2 (detection logic).

---

### M2: Cold-start problem — no baseline means everything looks suspicious

**What goes wrong:** When the tool starts, its IP-MAC table is empty. The first ARP packet for any IP populates it. Any subsequent packet for the same IP from a different MAC is flagged — but the "first" MAC was itself just assumed to be legitimate. In a churning network (devices reconnecting), the first minute of operation generates noise.

**Warning sign:** Tool fires alerts immediately on startup before settling into accurate detection.

**Prevention:** Implement a baseline phase before live detection:
```python
BASELINE_DURATION = 10  # seconds

print("[*] Building ARP baseline for 10 seconds...")
baseline_packets = sniff(filter="arp", timeout=BASELINE_DURATION, store=True)
for pkt in baseline_packets:
    populate_table(pkt)  # fill table without alerting
print(f"[*] Baseline complete. {len(arp_table)} IP-MAC mappings loaded.")
print("[*] Live detection active.")
```
Also support loading a pre-built baseline from `arp-scan` output (which the project already requires), so the table is pre-populated before sniffing starts.

**Phase:** Phase 2 (detection logic). Design the baseline + live detection pipeline together.

---

### M3: DHCP lease changes cause false positives

**What goes wrong:** When a DHCP server reassigns an IP to a new device (or the same device gets a new MAC after hardware change), the detector sees IP X mapped to old MAC, then IP X mapped to new MAC, and fires. This is legitimate behavior.

**Warning sign:** Alerts fire when devices leave and rejoin the network over time.

**Prevention:** This is hard to fully solve without DHCP log correlation (out of scope for a course project). Mitigation: add a cooldown/debounce — don't alert the second time an IP-MAC pair changes within N seconds of the first alert. Also, document this limitation in the demo: "false positive rate is acceptable given no DHCP server integration." Evaluators expect this caveat.

**Phase:** Phase 2.

---

### M4: Virtual machine / Docker MACs cause false positives

**What goes wrong:** VMs, Docker containers, and bridges can assign multiple virtual interfaces to the same IP (NAT masquerading, bridged networking). The detector will see one IP with multiple MACs.

**Warning sign:** If the demo machine runs Docker or VirtualBox, the detector fires immediately on startup.

**Prevention:** Add a `--whitelist` option accepting known-safe MACs:
```python
# --whitelist 00:0c:29:xx:xx:xx  (VMware prefix)
WHITELIST_PREFIXES = {"00:0c:29", "00:50:56", "08:00:27"}  # VMware, VirtualBox OUIs
```
Also: test the demo on a clean WSL2 environment without extra VM software running.

**Phase:** Phase 2. Low effort, high payoff for demo reliability.

---

### M5: tcpdump output format varies by version — parsing breaks

**What goes wrong:** `subprocess` calls to `tcpdump` and parsing its stdout with `awk`/`grep` patterns can break when the tcpdump version changes its output format. For example, timestamp format and interface name prefixes differ between tcpdump 4.x and 4.9x.

**Warning sign:** The shell integration portion of the demo produces garbled output or `IndexError` when splitting parsed lines.

**Prevention:**
- Pin your parsing to the minimal fields you need (IP, MAC) using `-e` flag for MAC addresses in tcpdump.
- Test the parsing with `tcpdump -r <pcap_file>` on a captured file first — decouples parsing logic from live capture.
- For the course demo, tcpdump is only needed to satisfy the "shell integration" requirement — use it for log analysis post-capture, not as the primary detection path.

**Phase:** Phase 4 (shell integration).

---

## Minor Pitfalls (polish issues)

These are annoyances that reduce demo impressiveness but won't cause failure.

---

### P1: arp-scan sudo requirement — subprocess hangs without TTY

**What goes wrong:** `subprocess.run(["sudo", "arp-scan", "-l"])` hangs if the user's sudo session has expired and sudo prompts for a password. The subprocess has no TTY, so the password prompt never appears and the call hangs indefinitely.

**Prevention:**
```python
result = subprocess.run(
    ["sudo", "arp-scan", "--localnet"],
    capture_output=True, text=True, timeout=30  # always set timeout
)
if result.returncode != 0:
    print(f"[WARN] arp-scan failed: {result.stderr}. Proceeding without baseline.")
```
For the demo, run the tool as root from the start (`sudo python detector.py`) so `sudo arp-scan` inherits the session without re-prompting.

**Phase:** Phase 4.

---

### P2: scapy ARP filter string — case and syntax errors

**What goes wrong:** The BPF filter string `"arp"` is correct and simple, but developers sometimes overthink it: `"ARP"` (uppercase) or `"ether proto 0x0806"` (equivalent but verbose). The real trap is adding a malformed filter that scapy passes to libpcap without validation — scapy may raise a cryptic error or silently capture nothing.

**Prevention:** Keep it simple:
```python
sniff(filter="arp", prn=process_packet, store=False, iface=iface)
```
Test the filter independently with `tcpdump -i eth0 arp` at the shell first to confirm ARP packets are visible on that interface.

**Phase:** Phase 1.

---

### P3: networkx graph refresh on each packet causes flicker

**What goes wrong:** Calling `plt.clf()` and redrawing the entire networkx graph on every ARP packet causes visible flicker and sluggish rendering, especially if `plt.pause()` is called frequently.

**Prevention:** Batch graph updates — redraw only every N seconds, not on every packet:
```python
GRAPH_REFRESH_INTERVAL = 2.0  # seconds
last_refresh = time.time()

def maybe_refresh_graph():
    global last_refresh
    if time.time() - last_refresh > GRAPH_REFRESH_INTERVAL:
        draw_graph()
        last_refresh = time.time()
```

**Phase:** Phase 3.

---

### P4: Colored terminal output — Windows Terminal vs WSL vs plain terminal

**What goes wrong:** ANSI escape codes for colored output (`\033[91mALERT\033[0m`) work in most Linux terminals and Windows Terminal, but may render as literal characters in some environments (older CMD, output redirected to a log file).

**Prevention:** Use the `colorama` library which handles cross-platform ANSI gracefully, or check `sys.stdout.isatty()` and disable color when output is redirected:
```python
USE_COLOR = sys.stdout.isatty()

def alert(msg):
    if USE_COLOR:
        print(f"\033[91m[ALERT] {msg}\033[0m")
    else:
        print(f"[ALERT] {msg}")
```

**Phase:** Phase 2 (alerting output).

---

## WSL-Specific Gotchas

---

### W1: matplotlib GUI window — DISPLAY not set in WSL2

**What goes wrong:** WSL2 does not have a native X display. `plt.show()` will throw `cannot connect to X server` or a similar display error because `$DISPLAY` is not set.

**Warning sign:** `Error: no display name and no $DISPLAY environment variable` on the first visualization call.

**Options (choose one before building visualization):**

A. **Recommended for demo:** Use `matplotlib.use("Agg")` backend — renders to PNG file, no display needed:
```python
import matplotlib
matplotlib.use("Agg")  # must be set BEFORE importing pyplot
import matplotlib.pyplot as plt

# After drawing:
plt.savefig("network_topology.png")
print("[*] Graph saved to network_topology.png")
```

B. **If you need live GUI:** Install an X server on Windows (VcXsrv or X410), then in WSL: `export DISPLAY=:0.0` before running. This works but adds a setup dependency that may not be present in the grading lab.

C. **WSL2 with WSLg (Windows 11):** WSLg provides built-in GUI support. If the lab machines run Windows 11 with WSL2, `plt.show()` may work without any extra setup. Do not rely on this — confirm before demo day.

**Recommendation:** Use Agg backend + save to PNG. It is always reliable regardless of display setup, and the PNG output is actually impressive to show a grader.

**Phase:** Phase 3. Set the backend in Phase 1 architecture decisions to avoid late refactoring.

---

### W2: WSL2 network namespace isolation

**What goes wrong:** WSL2 runs in an isolated network namespace with its own IP range (typically 172.x.x.x). The Windows host communicates with WSL2 through a virtual Ethernet adapter. ARP traffic is entirely virtual — you will not see ARP broadcasts from real LAN devices (phones, printers, other computers on the same WiFi).

**Implication for demo:** The demo must be self-contained within WSL2. The simulated attacker and victim must both be processes running inside WSL2 (or be scapy-crafted packets). This is not a limitation that can be fixed without either WSL1 mode or a real Linux VM.

**Phase:** Acknowledge in Phase 1 design. Plan the demo simulation strategy from day one.

---

### W3: WSL1 vs WSL2 — different networking behavior

If somehow running WSL1 (older setup), networking is different: WSL1 shares the Windows network stack (bridged mode), so ARP sniffing may actually see real LAN traffic. WSL2 (default since Windows 10 2004) uses the isolated virtual switch.

Check: `wsl --list --verbose` in PowerShell to see which version is running. The project targets WSL2 (the standard), so design for the isolated model.

---

### W4: Interface naming in WSL2

WSL2 interfaces are typically `eth0` but can vary. After a Windows update or WSL reinstall, the interface name may change. Always use `get_if_list()` to discover available interfaces at runtime (see C2).

---

## Demo / Testing Strategy

This is the most practical section for a course project — you need a real-looking attack to demonstrate without a second machine acting as an attacker.

---

### Strategy 1: Self-contained scapy attack simulation (Recommended)

Run two terminals inside WSL2:

**Terminal 1 (detector):**
```bash
sudo python detector.py --iface eth0
```

**Terminal 2 (simulated attacker — run this during the demo):**
```python
# simulate_attack.py
from scapy.all import ARP, Ether, sendp
import time

# Craft a spoofed ARP reply:
# Claim that IP 192.168.1.1 (gateway) has attacker MAC de:ad:be:ef:00:01
victim_ip = "192.168.1.1"      # IP being spoofed (use your WSL gateway IP)
fake_mac = "de:ad:be:ef:00:01" # attacker's fake MAC
target_mac = "ff:ff:ff:ff:ff:ff"  # broadcast

pkt = Ether(dst=target_mac) / ARP(
    op=2,          # ARP reply
    pdst="0.0.0.0",
    hwdst=target_mac,
    psrc=victim_ip,
    hwsrc=fake_mac
)

print(f"[*] Sending spoofed ARP: {victim_ip} is at {fake_mac}")
for i in range(5):
    sendp(pkt, iface="eth0", verbose=False)
    time.sleep(1)
    print(f"    Packet {i+1}/5 sent")
```

This sends ARP replies claiming the gateway IP maps to a fake MAC. The detector will see these packets and fire an alert — exactly what the demo needs.

**Key:** Find the actual WSL2 gateway IP first:
```bash
ip route | grep default  # shows gateway IP, e.g. 172.19.0.1
```

---

### Strategy 2: Pre-recorded pcap replay (Backup)

If live simulation feels risky, record a pcap in advance and replay it:

```bash
# Record real ARP traffic (including simulated attack) once
sudo tcpdump -i eth0 arp -w arp_capture.pcap

# Replay during demo
sudo tcpreplay --intf1=eth0 arp_capture.pcap
```

This makes the demo 100% reproducible. The detector sniffs the replayed traffic the same way it would sniff live traffic.

Note: `tcpreplay` may need to be installed separately (`sudo apt install tcpreplay`).

---

### Strategy 3: Offline/unit-test mode (Fallback)

If network capture fails entirely during the demo (permissions issue, interface problem), have an offline mode that reads from a pre-captured `.pcap` file using scapy's `rdpcap`:

```python
# Fallback: read from pcap if --demo flag is passed
if args.demo:
    from scapy.all import rdpcap
    pkts = rdpcap("demo_capture.pcap")
    for pkt in pkts:
        process_packet(pkt)
```

This guarantees the detection logic can be demonstrated even if live capture is broken. Prepare a `demo_capture.pcap` file containing a mix of normal ARP traffic and crafted spoofed packets.

---

### Demo Day Checklist

- [ ] Confirmed `sudo python detector.py` works with no errors
- [ ] Identified the correct interface with `ip link show` — hardcode it in the demo run command
- [ ] Tested `simulate_attack.py` produces alerts in the detector
- [ ] `matplotlib` backend confirmed (Agg saves PNG, or WSLg display works)
- [ ] `arp-scan` and `tcpdump` commands run without hanging
- [ ] Prepared `demo_capture.pcap` as offline fallback
- [ ] Gateway IP confirmed (`ip route | grep default`) and used in simulate_attack.py
- [ ] Log file written and readable after the demo run

---

## Phase-Specific Warning Map

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|----------------|------------|
| Phase 1: Capture skeleton | C1 (no root check), C2 (wrong iface), C3 (store=True) | Root guard + dynamic iface + prn callback on day one |
| Phase 1: Architecture | C4 (threading model), C5 (WSL isolation) | Decide threading + simulation strategy before writing detection logic |
| Phase 2: Detection logic | M1 (gratuitous ARP), M2 (cold start), M3 (DHCP churn) | Filter op=2 only, build baseline phase, add debounce |
| Phase 2: Alerting | P4 (ANSI color portability) | `isatty()` guard |
| Phase 3: Visualization | C4 (plt.show blocks), W1 (no DISPLAY), P3 (flicker) | Agg backend + batch refresh |
| Phase 4: Shell integration | M5 (tcpdump format), P1 (sudo hang) | Timeout all subprocesses, test parsing offline first |
| Demo prep | C5 (WSL isolation), full demo strategy | simulate_attack.py + pcap fallback ready before final submission |

---

*Confidence notes: scapy behavior (HIGH — official docs + widely reproduced), WSL2 network topology (MEDIUM — confirmed for WSL2 but WSLg display support is Windows 11 version-dependent), tcpdump format variation (MEDIUM — known issue, specific version differences not verified without search access).*
