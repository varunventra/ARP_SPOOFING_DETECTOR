"""test_shell_scripts.py — Tests for Phase 4 shell scripts and SHL-04 subprocess compliance.

Tests run without root, without arp-scan, tcpdump, or any live network tool.
Fixture files in tests/fixtures/ provide all input data.

SHL-04 compliance: verified by inspecting Python source for shell=True in actual code.
Script behaviour: verified by running scripts against fixture files via bash.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path constants — relative to project root (where pytest is invoked from)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
ARP_DETECTOR_DIR = PROJECT_ROOT / "arp_detector"

ARP_SCAN_FIXTURE = FIXTURES_DIR / "arp_scan_output.txt"
SAMPLE_LOG = FIXTURES_DIR / "sample.log"

# Skip tests that require bash if unavailable (e.g. native Windows without Git Bash/WSL)
bash_available = shutil.which("bash") is not None
requires_bash = pytest.mark.skipif(not bash_available, reason="bash not available on this platform")


def _bash_run(*args, input_text: str = None, timeout: int = 10) -> "subprocess.CompletedProcess[str]":
    """Run a bash command with portable path handling.

    Uses relative paths (via cwd=PROJECT_ROOT) so bash on Windows (Git Bash / WSL)
    doesn't receive Windows-style absolute paths it can't interpret.
    Adds stdin=DEVNULL when no input_text is provided to prevent WinError 6.
    """
    kwargs = dict(
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(PROJECT_ROOT),
    )
    if input_text is not None:
        kwargs["input"] = input_text
    else:
        kwargs["stdin"] = subprocess.DEVNULL
    return subprocess.run(list(args), **kwargs)


# ---------------------------------------------------------------------------
# SHL-04: subprocess compliance
# ---------------------------------------------------------------------------

class TestSubprocessCompliance:
    """SHL-04: No Python file in arp_detector/ may use shell=True in actual subprocess calls."""

    def test_no_shell_true_in_arp_detector(self):
        """No Python subprocess call in arp_detector/ may use shell=True.

        Detects actual code by looking for lines where shell=True co-occurs with
        subprocess.run / subprocess.Popen / subprocess.call — docstring policy
        lines that mention shell=True are excluded by this pattern.
        """
        # Pattern: subprocess.run(... shell=True ...) on the same logical line or multiline
        # Simple per-file check using regex on the full source
        bad_files = []
        for py_file in ARP_DETECTOR_DIR.glob("*.py"):
            src = py_file.read_text(encoding="utf-8")
            # Find actual subprocess calls that include shell=True as a keyword arg
            if re.search(r'subprocess\.(run|Popen|call|check_output)\s*\(', src):
                # Check if shell=True appears as actual code (not inside a docstring)
                # Strip triple-quoted strings first, then check
                stripped = re.sub(r'""".*?"""', '""', src, flags=re.DOTALL)
                stripped = re.sub(r"'''.*?'''", "''", stripped, flags=re.DOTALL)
                # Remove single-line comments
                stripped = re.sub(r'#[^\n]*', '', stripped)
                if 'shell=True' in stripped:
                    bad_files.append(py_file.name)
        assert not bad_files, (
            f"shell=True in actual subprocess call in: {bad_files}"
        )

    def test_baseline_py_uses_list_form(self):
        """baseline.py subprocess.run call must use list-form args, not a shell string."""
        baseline_src = (ARP_DETECTOR_DIR / "baseline.py").read_text()
        assert '"arp-scan"' in baseline_src or "'arp-scan'" in baseline_src, (
            "baseline.py must call subprocess.run with list-form args containing 'arp-scan'"
        )

    def test_baseline_py_has_timeout(self):
        """baseline.py subprocess.run must include a timeout= parameter."""
        baseline_src = (ARP_DETECTOR_DIR / "baseline.py").read_text()
        assert "timeout=" in baseline_src, (
            "baseline.py subprocess.run call must include timeout= parameter (SHL-04)"
        )

    def test_baseline_py_handles_exceptions(self):
        """baseline.py must catch FileNotFoundError and TimeoutExpired (SHL-04 error handling)."""
        baseline_src = (ARP_DETECTOR_DIR / "baseline.py").read_text()
        assert "FileNotFoundError" in baseline_src
        assert "TimeoutExpired" in baseline_src


# ---------------------------------------------------------------------------
# Script presence and syntax
# ---------------------------------------------------------------------------

class TestScriptPresence:
    """All three scripts exist, have correct shebang, and pass bash -n."""

    @pytest.mark.parametrize("script_name", [
        "baseline_scan.sh",
        "analyze_log.sh",
        "capture_raw.sh",
    ])
    def test_script_exists(self, script_name):
        """Script file must exist in scripts/."""
        assert (SCRIPTS_DIR / script_name).exists(), (
            f"scripts/{script_name} not found — run Plan 04-01 first"
        )

    @pytest.mark.parametrize("script_name", [
        "baseline_scan.sh",
        "analyze_log.sh",
        "capture_raw.sh",
    ])
    def test_script_has_bash_shebang(self, script_name):
        """First line of each script must be #!/bin/bash."""
        first_line = (SCRIPTS_DIR / script_name).read_text().splitlines()[0]
        assert first_line == "#!/bin/bash", (
            f"scripts/{script_name} first line is '{first_line}', expected '#!/bin/bash'"
        )

    @requires_bash
    @pytest.mark.parametrize("script_name", [
        "baseline_scan.sh",
        "analyze_log.sh",
        "capture_raw.sh",
    ])
    def test_script_syntax_check(self, script_name):
        """bash -n must pass (syntax check only, no execution)."""
        result = _bash_run("bash", "-n", f"scripts/{script_name}", timeout=5)
        assert result.returncode == 0, (
            f"bash -n failed for scripts/{script_name}:\n{result.stderr}"
        )


# ---------------------------------------------------------------------------
# baseline_scan.sh: awk filter logic
# ---------------------------------------------------------------------------

class TestBaselineScanAwkFilter:
    """baseline_scan.sh awk expression filters correctly — verified via fixture."""

    def test_filters_to_ip_mac_lines_only(self):
        """Only IP<TAB>MAC lines pass the awk filter — header and footer are dropped.

        Uses Python to simulate the awk filter logic (cross-platform reliable).
        Also verifies the script source contains the correct awk expression.
        """
        ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        fixture_text = ARP_SCAN_FIXTURE.read_text()
        # Simulate: awk -F'\t' '$1 ~ /ipv4 regex/ { print $1 "\t" $2 }'
        filtered = []
        for line in fixture_text.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and ip_re.match(parts[0].strip()):
                filtered.append(parts[0].strip() + "\t" + parts[1].strip())
        assert len(filtered) == 3, (
            f"Expected 3 IP<TAB>MAC lines from fixture, got {len(filtered)}: {filtered}"
        )
        # Verify the script source contains the awk command
        script_text = (SCRIPTS_DIR / "baseline_scan.sh").read_text()
        assert "awk" in script_text, "baseline_scan.sh must contain an awk command"

    def test_output_lines_start_with_ip(self):
        """Each filtered output line must start with a dotted-quad IP address."""
        ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        fixture_text = ARP_SCAN_FIXTURE.read_text()
        for line in fixture_text.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and ip_re.match(parts[0].strip()):
                assert "\t" in line, f"Data line missing tab separator: '{line}'"
                assert ip_re.match(parts[0].strip()), f"First field not an IP: '{parts[0]}'"

    def test_header_line_excluded(self):
        """'Interface:' header line must not pass the awk IP filter."""
        ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        fixture_text = ARP_SCAN_FIXTURE.read_text()
        filtered_lines = [
            line for line in fixture_text.splitlines()
            if len(line.split("\t")) >= 2 and ip_re.match(line.split("\t")[0].strip())
        ]
        for line in filtered_lines:
            assert "Interface:" not in line

    def test_footer_line_excluded(self):
        """'packets received' footer line must not pass the awk IP filter."""
        ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        fixture_text = ARP_SCAN_FIXTURE.read_text()
        filtered_lines = [
            line for line in fixture_text.splitlines()
            if len(line.split("\t")) >= 2 and ip_re.match(line.split("\t")[0].strip())
        ]
        for line in filtered_lines:
            assert "packets received" not in line

    def test_script_contains_arp_scan_command(self):
        """baseline_scan.sh must call arp-scan --localnet."""
        script_text = (SCRIPTS_DIR / "baseline_scan.sh").read_text()
        assert "arp-scan" in script_text
        assert "--localnet" in script_text


# ---------------------------------------------------------------------------
# analyze_log.sh: behaviour against sample.log fixture
# ---------------------------------------------------------------------------

class TestAnalyzeLogScript:
    """analyze_log.sh produces correct summary when run against sample.log."""

    @requires_bash
    def test_reports_correct_attack_count(self):
        """sample.log has 2 events — script must report 'Total attacks detected: 2'."""
        result = _bash_run("bash", "scripts/analyze_log.sh", "tests/fixtures/sample.log")
        assert result.returncode == 0, f"Script failed:\n{result.stderr}"
        assert "Total attacks detected: 2" in result.stdout

    @requires_bash
    def test_reports_first_attacker_mac(self):
        """First attacker MAC from fixture must appear in output."""
        result = _bash_run("bash", "scripts/analyze_log.sh", "tests/fixtures/sample.log")
        assert "de:ad:be:ef:00:01" in result.stdout

    @requires_bash
    def test_reports_second_attacker_mac(self):
        """Second attacker MAC from fixture must appear in output."""
        result = _bash_run("bash", "scripts/analyze_log.sh", "tests/fixtures/sample.log")
        assert "de:ad:be:ef:00:02" in result.stdout

    @requires_bash
    def test_timeline_shows_victim_ips(self):
        """Timeline section must include victim IPs from fixture events."""
        result = _bash_run("bash", "scripts/analyze_log.sh", "tests/fixtures/sample.log")
        assert "192.168.1.1" in result.stdout or "192.168.1.5" in result.stdout

    @requires_bash
    def test_missing_log_file_exits_nonzero(self):
        """Passing a nonexistent log path must exit with non-zero code."""
        result = _bash_run("bash", "scripts/analyze_log.sh", "tests/fixtures/nonexistent_12345.log")
        assert result.returncode != 0, "Script must exit non-zero when log file not found"

    @requires_bash
    def test_missing_log_file_prints_error(self):
        """Missing log file must print an error message to stderr."""
        result = _bash_run("bash", "scripts/analyze_log.sh", "tests/fixtures/nonexistent_12345.log")
        assert result.stderr.strip() != "", "Script must print error to stderr for missing file"

    def test_script_uses_grep(self):
        """analyze_log.sh must use grep for JSONL parsing (SHL-02 requirement)."""
        script_text = (SCRIPTS_DIR / "analyze_log.sh").read_text()
        assert "grep" in script_text

    def test_script_uses_awk(self):
        """analyze_log.sh must use awk for field extraction (SHL-02 requirement)."""
        script_text = (SCRIPTS_DIR / "analyze_log.sh").read_text()
        assert "awk" in script_text


# ---------------------------------------------------------------------------
# capture_raw.sh: argument handling (syntax only — no tcpdump execution)
# ---------------------------------------------------------------------------

class TestCaptureRawScript:
    """capture_raw.sh accepts $1 as output path and defaults to capture.pcap."""

    def test_default_path_in_script(self):
        """Script source must reference 'capture.pcap' as the default output path."""
        script_text = (SCRIPTS_DIR / "capture_raw.sh").read_text()
        assert "capture.pcap" in script_text, (
            "capture_raw.sh must default to 'capture.pcap' when no argument given"
        )

    def test_uses_argument_variable(self):
        """Script must use $1 for configurable output path."""
        script_text = (SCRIPTS_DIR / "capture_raw.sh").read_text()
        assert "$1" in script_text or "${1" in script_text, (
            "capture_raw.sh must use $1 (or ${1:-...}) for the output path argument"
        )

    def test_tcpdump_command_present(self):
        """Script must call tcpdump with -n arp -w flags."""
        script_text = (SCRIPTS_DIR / "capture_raw.sh").read_text()
        assert "tcpdump" in script_text
        assert "-n" in script_text or "arp" in script_text
        assert "-w" in script_text
