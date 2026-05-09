---
phase: 2
slug: detection-pipeline-alerting
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-09
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest |
| **Config file** | none — using pytest defaults |
| **Quick run command** | `python -m pytest tests/test_baseline.py tests/test_logger.py tests/test_alerts.py -q` |
| **Full suite command** | `python -m pytest tests/ -v` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `python -m pytest tests/ -q --tb=short`
- **After every plan wave:** Run `python -m pytest tests/ -v`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 2-01-01 | 01 | 1 | DET-02 | unit | `python -m pytest tests/test_baseline.py -v` | ❌ W0 | ⬜ pending |
| 2-01-02 | 01 | 1 | DET-05 | unit | `python -m pytest tests/test_logger.py -v` | ❌ W0 | ⬜ pending |
| 2-01-03 | 01 | 1 | ALT-01 | unit | `python -m pytest tests/test_alerts.py -v` | ❌ W0 | ⬜ pending |
| 2-02-01 | 02 | 2 | ALT-02 ALT-04 | integration | `python -m pytest tests/test_main.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_baseline.py` — stubs for DET-02 (arp-scan baseline loader)
- [ ] `tests/test_logger.py` — stubs for DET-05, ALT-03 (JSONL logger)
- [ ] `tests/test_alerts.py` — stubs for ALT-01 (rich console alerts)
- [ ] `tests/test_main.py` — stubs for ALT-02, ALT-04 (main loop, shutdown)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| rich.Live dashboard renders without flicker | ALT-02 | Terminal rendering can't be captured in unit tests | Run `sudo python3 arp_detector/main.py --iface eth0` and visually verify live table |
| Ctrl+C session summary output | ALT-04 | KeyboardInterrupt behavior in subprocess context | Run tool, press Ctrl+C, verify summary lines appear |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
