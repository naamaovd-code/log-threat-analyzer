"""Tests for app/repository.py against a REAL MySQL database: the separate test database
(DB_TEST_NAME in .env), never the app database. Every test starts with empty tables.

If MySQL is not set up (no .env), these tests are skipped instead of failing:
run scripts/setup_db.sh to enable them.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mysql.connector
import pytest

from app.config import ConfigError, database_config
from app.repository import Repository
from app.service import AnalysisSettings, analyze_file

PROJECT_ROOT = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"
HASH_A = "a" * 64
HASH_B = "b" * 64
DEFAULT = AnalysisSettings()
ISRAEL = timezone(timedelta(hours=2))


# ---------- fixtures ----------

@pytest.fixture(scope="module")
def test_db_config():
    try:
        config = database_config(test=True)
        connection = mysql.connector.connect(
            host=config.host, port=config.port, user=config.user,
            password=config.password, database=config.database,
        )
    except (ConfigError, mysql.connector.Error) as error:
        pytest.skip(f"MySQL test database not available ({error}). Run scripts/setup_db.sh")

    # create the tables from the real schema.sql
    cursor = connection.cursor()
    for statement in (PROJECT_ROOT / "schema.sql").read_text(encoding="utf-8").split(";"):
        if statement.strip():
            cursor.execute(statement)
    connection.commit()
    connection.close()
    return config


@pytest.fixture
def db(test_db_config):
    """Empty tables before every test, then a connection for test-only SQL."""
    connection = mysql.connector.connect(
        host=test_db_config.host, port=test_db_config.port, user=test_db_config.user,
        password=test_db_config.password, database=test_db_config.database, time_zone="+00:00",
    )
    cursor = connection.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM analysis_runs")
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def repo(db, test_db_config):
    return Repository(test_db_config)


def set_created_at(db, run_id, utc_naive):
    """Test helper: move a run to a known time, to test date filters."""
    cursor = db.cursor()
    cursor.execute("UPDATE analysis_runs SET created_at = %s WHERE id = %s", (utc_naive, run_id))
    db.commit()


# ---------- runs ----------

def test_create_run_is_pending_with_settings(repo):
    before = datetime.now(timezone.utc).replace(microsecond=0)

    run_id = repo.create_run("server.log", HASH_A, AnalysisSettings(30, 3, 10))
    run = repo.get_run(run_id)

    assert run["filename"] == "server.log"
    assert run["file_hash"] == HASH_A
    assert run["status"] == "pending"
    assert run["lines_parsed"] is None
    assert run["settings"] == AnalysisSettings(30, 3, 10)
    assert run["alert_count"] == 0
    # created_at is set by MySQL, in UTC
    assert before <= run["created_at"] <= datetime.now(timezone.utc) + timedelta(seconds=1)


def test_get_run_that_does_not_exist_returns_none(repo):
    assert repo.get_run(999999) is None


def test_complete_run(repo):
    run_id = repo.create_run("server.log", HASH_A, DEFAULT)

    repo.complete_run(run_id, lines_parsed=32)

    run = repo.get_run(run_id)
    assert run["status"] == "completed"
    assert run["lines_parsed"] == 32


# ---------- alerts ----------

def test_alerts_from_the_engine_are_saved_and_read_back_identically(repo):
    result = analyze_file(FIXTURE, DEFAULT)
    run_id = repo.create_run("sample_logs.txt", HASH_A, DEFAULT)

    repo.save_alerts(run_id, result.alerts)

    stored = repo.get_alerts(run_id)
    assert [(a["threat_type"], a["ip_address"], a["detected_at"].strftime("%Y-%m-%d %H:%M:%S"), a["details"])
            for a in stored] == \
           [(a["type"], a["ip_address"], a["timestamp"], a["details"]) for a in result.alerts]
    assert stored[0]["detected_at"].tzinfo == timezone.utc
    assert repo.get_run(run_id)["alert_count"] == 2


def test_get_alerts_filtered_by_threat_type(repo):
    run_id = repo.create_run("sample_logs.txt", HASH_A, DEFAULT)
    repo.save_alerts(run_id, analyze_file(FIXTURE, DEFAULT).alerts)

    scanning = repo.get_alerts(run_id, threat_type="Scanning")

    assert [a["ip_address"] for a in scanning] == ["10.0.0.3"]


def test_run_without_alerts_returns_empty_list(repo):
    run_id = repo.create_run("clean.log", HASH_A, DEFAULT)
    repo.save_alerts(run_id, [])

    assert repo.get_alerts(run_id) == []


def test_alert_for_a_run_that_does_not_exist_is_rejected_by_the_foreign_key(repo):
    alert = {"type": "Scanning", "ip_address": "1.1.1.1", "timestamp": "2026-11-10 10:00:00", "details": "x"}

    with pytest.raises(mysql.connector.IntegrityError):
        repo.save_alerts(999999, [alert])


# ---------- failure ----------

def test_fail_run_deletes_partial_alerts_and_keeps_the_reason(repo):
    run_id = repo.create_run("server.log", HASH_A, DEFAULT)
    repo.save_alerts(run_id, analyze_file(FIXTURE, DEFAULT).alerts)

    repo.fail_run(run_id, "Database connection lost")

    run = repo.get_run(run_id)
    assert run["status"] == "failed"
    assert run["error_message"] == "Database connection lost"
    assert run["alert_count"] == 0
    assert repo.get_alerts(run_id) == []


def test_long_error_message_is_cut_to_column_size(repo):
    run_id = repo.create_run("server.log", HASH_A, DEFAULT)

    repo.fail_run(run_id, "x" * 2000)

    assert len(repo.get_run(run_id)["error_message"]) == 500


# ---------- duplicate detection (D11) ----------

def test_find_completed_run_with_same_content_and_settings(repo):
    run_id = repo.create_run("a.log", HASH_A, DEFAULT)
    repo.complete_run(run_id, 10)

    assert repo.find_completed_run(HASH_A, DEFAULT) == run_id


def test_same_content_with_different_settings_is_not_a_duplicate(repo):
    run_id = repo.create_run("a.log", HASH_A, DEFAULT)
    repo.complete_run(run_id, 10)

    assert repo.find_completed_run(HASH_A, AnalysisSettings(brute_force_threshold=3)) is None


def test_different_content_is_not_a_duplicate(repo):
    run_id = repo.create_run("a.log", HASH_A, DEFAULT)
    repo.complete_run(run_id, 10)

    assert repo.find_completed_run(HASH_B, DEFAULT) is None


def test_pending_and_failed_runs_are_not_reused(repo):
    repo.create_run("a.log", HASH_A, DEFAULT)                 # stays pending
    failed_id = repo.create_run("a.log", HASH_A, DEFAULT)
    repo.fail_run(failed_id, "boom")

    assert repo.find_completed_run(HASH_A, DEFAULT) is None


def test_newest_completed_run_is_reused(repo, db):
    old_id = repo.create_run("a.log", HASH_A, DEFAULT)
    repo.complete_run(old_id, 10)
    set_created_at(db, old_id, datetime(2026, 11, 1, 10, 0))
    new_id = repo.create_run("a.log", HASH_A, DEFAULT)
    repo.complete_run(new_id, 10)

    assert repo.find_completed_run(HASH_A, DEFAULT) == new_id


# ---------- history by analysis date (D12) ----------

def test_list_runs_in_date_range_newest_first(repo, db):
    ids = {}
    for name, created in [("before", datetime(2026, 11, 4, 21, 59)),
                          ("first_day", datetime(2026, 11, 4, 22, 0)),     # 5 Nov 00:00 in Israel
                          ("last_day", datetime(2026, 11, 11, 21, 59)),    # 11 Nov 23:59 in Israel
                          ("after", datetime(2026, 11, 11, 22, 0))]:       # 12 Nov 00:00 in Israel
        ids[name] = repo.create_run(f"{name}.log", HASH_A, DEFAULT)
        set_created_at(db, ids[name], created)

    # "5 to 11 November" in Israel time, sent with the +02:00 offset like the browser will
    runs = repo.list_runs(datetime(2026, 11, 5, tzinfo=ISRAEL), datetime(2026, 11, 12, tzinfo=ISRAEL))

    assert [r["id"] for r in runs] == [ids["last_day"], ids["first_day"]]


def test_list_runs_includes_alert_count(repo):
    run_id = repo.create_run("sample_logs.txt", HASH_A, DEFAULT)
    repo.save_alerts(run_id, analyze_file(FIXTURE, DEFAULT).alerts)

    assert repo.list_runs()[0]["alert_count"] == 2


def test_list_runs_with_no_match_returns_empty_list(repo):
    repo.create_run("a.log", HASH_A, DEFAULT)

    assert repo.list_runs(datetime(2000, 1, 1, tzinfo=timezone.utc), datetime(2000, 1, 2, tzinfo=timezone.utc)) == []


def test_list_runs_rejects_dates_without_time_zone(repo):
    with pytest.raises(ValueError):
        repo.list_runs(datetime(2026, 11, 5))


# ---------- security ----------

def test_sql_injection_in_filename_is_stored_as_plain_text(repo):
    evil_name = "x'); DROP TABLE alerts; --"
    run_id = repo.create_run(evil_name, HASH_A, DEFAULT)

    assert repo.get_run(run_id)["filename"] == evil_name
    assert repo.get_alerts(run_id) == []   # the alerts table still exists
