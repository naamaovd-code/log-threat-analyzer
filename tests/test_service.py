"""Unit tests for app/service.py - the analysis service, without HTTP and without MySQL.

The upload flow is tested with a FakeRepository that keeps everything in memory,
so these tests check the service's decisions (reuse, store, fail) quickly and in isolation.
The real repository is tested separately in test_repository.py.
"""
import hashlib
from pathlib import Path

import pytest

from app.service import AnalysisSettings, NotALogFileError, analyze_file, analyze_upload, file_sha256

FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"


class FakeRepository:
    """In-memory stand-in for app.repository.Repository (same method names)."""

    def __init__(self):
        self.runs = {}
        self.alerts = {}
        self.fail_on_save = False
        self.fail_on_fail_run = False

    def find_completed_run(self, file_hash, settings):
        matches = [run_id for run_id, run in self.runs.items()
                   if run["file_hash"] == file_hash and run["settings"] == settings and run["status"] == "completed"]
        return max(matches) if matches else None

    def create_run(self, filename, file_hash, settings):
        run_id = len(self.runs) + 1
        self.runs[run_id] = {"filename": filename, "file_hash": file_hash, "settings": settings,
                             "status": "pending", "lines_parsed": None, "error_message": None}
        return run_id

    def save_alerts(self, run_id, alerts):
        if self.fail_on_save:
            raise RuntimeError("database connection lost")
        self.alerts[run_id] = list(alerts)

    def complete_run(self, run_id, lines_parsed):
        self.runs[run_id].update(status="completed", lines_parsed=lines_parsed)

    def fail_run(self, run_id, error_message, lines_parsed=None):
        if self.fail_on_fail_run:
            raise RuntimeError("database is down too")
        self.alerts.pop(run_id, None)
        self.runs[run_id].update(status="failed", error_message=error_message, lines_parsed=lines_parsed)


# ---------- file_sha256 ----------

def test_file_sha256_is_the_hash_of_the_content(tmp_path):
    log_file = tmp_path / "a.log"
    log_file.write_bytes(b"hello")

    assert file_sha256(log_file) == hashlib.sha256(b"hello").hexdigest()


def test_same_content_with_different_name_has_the_same_hash(tmp_path):
    (tmp_path / "a.log").write_bytes(b"same content")
    (tmp_path / "b.txt").write_bytes(b"same content")

    assert file_sha256(tmp_path / "a.log") == file_sha256(tmp_path / "b.txt")


# ---------- analyze_upload ----------

def test_new_upload_is_analyzed_and_stored():
    repo = FakeRepository()

    outcome = analyze_upload(FIXTURE, "sample_logs.txt", AnalysisSettings(), repo)

    assert outcome.reused is False
    run = repo.runs[outcome.run_id]
    assert run["status"] == "completed"
    assert run["lines_parsed"] == 32
    assert run["file_hash"] == file_sha256(FIXTURE)
    assert len(repo.alerts[outcome.run_id]) == 2


def test_second_upload_of_same_content_reuses_the_run():
    repo = FakeRepository()
    first = analyze_upload(FIXTURE, "a.log", AnalysisSettings(), repo)

    second = analyze_upload(FIXTURE, "b.log", AnalysisSettings(), repo)

    assert second.reused is True
    assert second.run_id == first.run_id
    assert len(repo.runs) == 1   # nothing new was stored


def test_same_content_with_other_settings_is_analyzed_again():
    repo = FakeRepository()
    analyze_upload(FIXTURE, "a.log", AnalysisSettings(), repo)

    second = analyze_upload(FIXTURE, "a.log", AnalysisSettings(brute_force_threshold=3), repo)

    assert second.reused is False
    assert len(repo.runs) == 2


def test_not_a_log_file_is_stored_as_failed_and_raised(tmp_path):
    repo = FakeRepository()
    not_a_log = tmp_path / "shopping.txt"
    not_a_log.write_text("milk\n", encoding="utf-8")

    with pytest.raises(NotALogFileError):
        analyze_upload(not_a_log, "shopping.txt", AnalysisSettings(), repo)

    [run] = repo.runs.values()
    assert run["status"] == "failed"
    assert run["lines_parsed"] == 0
    assert run["error_message"] == "No log lines in a supported format were found"


def test_failure_while_saving_marks_the_run_failed_and_raises():
    repo = FakeRepository()
    repo.fail_on_save = True

    with pytest.raises(RuntimeError, match="database connection lost"):
        analyze_upload(FIXTURE, "a.log", AnalysisSettings(), repo)

    [run] = repo.runs.values()
    assert run["status"] == "failed"
    assert "database connection lost" in run["error_message"]


def test_original_error_is_kept_when_marking_failed_also_fails():
    repo = FakeRepository()
    repo.fail_on_save = True
    repo.fail_on_fail_run = True

    # the caller must see the REAL cause, not "database is down too"
    with pytest.raises(RuntimeError, match="database connection lost"):
        analyze_upload(FIXTURE, "a.log", AnalysisSettings(), repo)


def test_failed_run_is_not_reused():
    repo = FakeRepository()
    repo.fail_on_save = True
    with pytest.raises(RuntimeError):
        analyze_upload(FIXTURE, "a.log", AnalysisSettings(), repo)
    repo.fail_on_save = False

    retry = analyze_upload(FIXTURE, "a.log", AnalysisSettings(), repo)

    assert retry.reused is False
    assert repo.runs[retry.run_id]["status"] == "completed"


# ---------- analyze_file ----------


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
