"""Unit tests for app/service.py - the analysis service, without HTTP."""
from pathlib import Path

import pytest

from app.service import AnalysisSettings, NotALogFileError, analyze_file

FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"


def test_analyze_fixture_with_default_settings():
    result = analyze_file(FIXTURE, AnalysisSettings())

    assert result.lines_parsed == 32
    assert [(a["type"], a["ip_address"]) for a in result.alerts] == [
        ("Brute Force", "10.0.0.1"),
        ("Scanning", "10.0.0.3"),
    ]


def test_settings_are_passed_to_the_engine():
    # with a threshold of 3, 10.0.0.2 (4 failed logins) is now also an attack
    result = analyze_file(FIXTURE, AnalysisSettings(brute_force_threshold=3))

    assert [(a["type"], a["ip_address"]) for a in result.alerts] == [
        ("Brute Force", "10.0.0.1"),
        ("Brute Force", "10.0.0.2"),
        ("Scanning", "10.0.0.3"),
    ]


def test_clean_log_gives_zero_alerts(tmp_path):
    clean = tmp_path / "clean.log"
    clean.write_text('1.2.3.4 - - [10/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512\n', encoding="utf-8")

    result = analyze_file(clean, AnalysisSettings())

    assert result.lines_parsed == 1
    assert result.alerts == []


def test_file_that_is_not_a_log_raises(tmp_path):
    not_a_log = tmp_path / "shopping.txt"
    not_a_log.write_text("milk\nbread\n", encoding="utf-8")

    with pytest.raises(NotALogFileError):
        analyze_file(not_a_log, AnalysisSettings())


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze_file(tmp_path / "missing.log", AnalysisSettings())
