"""Tests for the command-line interface (analyzer.py), run as a real process."""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "analyzer.py", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_writes_alerts_to_jsonl(tmp_path):
    output_file = tmp_path / "alerts.jsonl"

    result = run_cli(str(FIXTURE), "-o", str(output_file))

    assert result.returncode == 0, result.stderr
    alerts = [json.loads(line) for line in output_file.read_text(encoding="utf-8").splitlines()]
    assert [(a["type"], a["ip_address"]) for a in alerts] == [
        ("Brute Force", "10.0.0.1"),
        ("Scanning", "10.0.0.3"),
    ]


def test_cli_reports_missing_log_file(tmp_path):
    result = run_cli(str(tmp_path / "does_not_exist.log"), "-o", str(tmp_path / "alerts.jsonl"))

    assert result.returncode == 1
    assert "not found" in result.stderr.lower()
