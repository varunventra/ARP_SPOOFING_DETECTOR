# Getting Started

## Requirements
- Windows with WSL (Ubuntu) installed
- Python 3.x inside WSL

---

## 1. Clone the repo

```bash
git clone <repo-url>
cd teamproject
```

---

## 2. Install system tools (WSL only, needs sudo)

```bash
sudo apt-get install arp-scan tcpdump -y
```

---

## 3. Install Python packages

```bash
pip install -r requirements.txt
```

---

## 4. Verify everything works

```bash
python -m pytest tests/ -q
```

You should see: **187 passed**

---

## 5. You're ready

To run the detector:
```bash
sudo python3 -m arp_detector.main --iface eth0 --visualize
```

To trigger a test attack (second terminal):
```bash
sudo python3 simulate_attack.py --iface eth0 --target-ip 192.168.1.1
```

---

## Files to read

| File | What it is |
|------|------------|
| `PROJECT_EXPLAINER.md` | How the project works + your section to present |
| `DEMO_GUIDE.md` | Exact steps for the 2-minute professor demo |
