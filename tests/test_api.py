"""Tests for the web API (app/main.py).

TestClient sends real HTTP requests to the app in memory - no server process is started.
Endpoints that use the database run against the TEST database: the `client` fixture
replaces the app's repository (dependency override). See tests/conftest.py.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mysql.connector
import pytest
from fastapi.testclient import TestClient

import app.main
from app.main import app as fastapi_app, get_repository
from app.repository import Repository

PROJECT_ROOT = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"
CLEAN_LOG = b'1.2.3.4 - - [10/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512\n'


@pytest.fixture
def client(repo):
    """API client whose repository points to the empty test database."""
    fastapi_app.dependency_overrides[get_repository] = lambda: repo
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.clear()


def upload(client, content: bytes, filename: str = "server.log", **settings):
    """POST a file (and optional settings) to /api/analyses."""
    return client.post(
        "/api/analyses",
        files={"file": (filename, content, "text/plain")},
        data={key: str(value) for key, value in settings.items()},
    )


# ---------- health (no database needed) ----------

def test_health_returns_ok():
    response = TestClient(fastapi_app).get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_unknown_endpoint_returns_404():
    assert TestClient(fastapi_app).get("/api/does-not-exist").status_code == 404


def test_health_rejects_wrong_http_method():
    assert TestClient(fastapi_app).post("/api/health").status_code == 405


# ---------- the web page (no database needed) ----------

def test_home_page_is_served():
    response = TestClient(fastapi_app).get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<title>Log Threat Analyzer</title>" in response.text


@pytest.mark.parametrize("path, content_type", [
    ("/static/app.js", "javascript"),
    ("/static/style.css", "text/css"),
])
def test_page_assets_are_served(path, content_type):
    response = TestClient(fastapi_app).get(path)

    assert response.status_code == 200
    assert content_type in response.headers["content-type"]


def test_files_outside_static_folder_are_not_served():
    # path traversal: must not be able to read .env or source code through /static
    client = TestClient(fastapi_app)
    for path in ("/static/../.env", "/static/..%2F.env", "/static/../app/config.py"):
        assert client.get(path).status_code == 404


def test_page_never_inserts_server_data_as_html():
    # XSS protection: values from the server (e.g. a filename) are set with textContent only
    script = (PROJECT_ROOT / "static" / "app.js").read_text(encoding="utf-8")

    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script


# ---------- POST /api/analyses: new analysis ----------

def test_analyze_fixture_is_stored_and_returned(client):
    response = upload(client, FIXTURE.read_bytes(), filename="sample_logs.txt")

    assert response.status_code == 201
    body = response.json()
    assert isinstance(body["id"], int)
    assert body["filename"] == "sample_logs.txt"
    assert body["status"] == "completed"
    assert body["reused"] is False
    assert body["created_at"].endswith("Z")
    assert body["settings"] == {"time_window_seconds": 60, "brute_force_threshold": 5, "scanning_threshold": 15}
    assert body["lines_parsed"] == 32
    assert body["alert_count"] == 2
    assert body["error_message"] is None
    assert body["alerts"][0] == {
        "threat_type": "Brute Force",
        "ip_address": "10.0.0.1",
        "detected_at": "2026-11-10T10:00:05Z",
        "details": "5 failed attempts in 60 seconds",
    }


def test_api_gives_the_same_alerts_as_the_cli(client, tmp_path):
    output_file = tmp_path / "cli_alerts.jsonl"
    subprocess.run(
        [sys.executable, "analyzer.py", str(FIXTURE), "-o", str(output_file)],
        cwd=PROJECT_ROOT, check=True, capture_output=True,
    )
    cli_alerts = [json.loads(line) for line in output_file.read_text(encoding="utf-8").splitlines()]

    api_alerts = upload(client, FIXTURE.read_bytes()).json()["alerts"]

    assert [(a["threat_type"], a["ip_address"], a["details"]) for a in api_alerts] == \
           [(a["type"], a["ip_address"], a["details"]) for a in cli_alerts]


def test_custom_settings_are_used_and_stored(client):
    body = upload(client, FIXTURE.read_bytes(), brute_force_threshold=3).json()

    assert body["settings"]["brute_force_threshold"] == 3
    assert body["alert_count"] == 3   # 10.0.0.2 (4 attempts) is now also an attack


def test_windows_line_endings_are_supported(client):
    windows_content = FIXTURE.read_text(encoding="utf-8").replace("\n", "\r\n").encode("utf-8")

    body = upload(client, windows_content).json()

    assert body["lines_parsed"] == 32
    assert body["alert_count"] == 2


def test_clean_log_is_201_with_zero_alerts(client):
    response = upload(client, CLEAN_LOG)

    assert response.status_code == 201
    assert response.json()["lines_parsed"] == 1
    assert response.json()["alerts"] == []


# ---------- POST /api/analyses: duplicates (D11) ----------

def test_same_content_and_settings_is_reused(client):
    first = upload(client, FIXTURE.read_bytes(), filename="monday.log").json()

    second = upload(client, FIXTURE.read_bytes(), filename="renamed.log")

    assert second.status_code == 200
    assert second.json()["reused"] is True
    assert second.json()["id"] == first["id"]
    assert second.json()["alerts"] == first["alerts"]


def test_same_content_with_other_settings_is_a_new_analysis(client):
    first = upload(client, FIXTURE.read_bytes()).json()

    second = upload(client, FIXTURE.read_bytes(), scanning_threshold=10)

    assert second.status_code == 201
    assert second.json()["id"] != first["id"]


# ---------- POST /api/analyses: errors ----------

def test_file_that_is_not_a_log_returns_400_and_is_stored_as_failed(client):
    response = upload(client, b"milk\nbread\neggs\n", filename="shopping.txt")

    assert response.status_code == 400
    assert response.json() == {"detail": "No log lines in a supported format were found"}
    history = client.get("/api/analyses").json()
    assert [(r["filename"], r["status"], r["lines_parsed"]) for r in history] == [("shopping.txt", "failed", 0)]


def test_empty_file_returns_400_and_stores_nothing(client):
    response = upload(client, b"")

    assert response.status_code == 400
    assert response.json() == {"detail": "File is empty"}
    assert client.get("/api/analyses").json() == []


def test_missing_file_returns_422(client):
    assert client.post("/api/analyses").status_code == 422


def test_file_larger_than_limit_returns_413(client, monkeypatch):
    monkeypatch.setattr(app.main, "MAX_UPLOAD_BYTES", 100)

    assert upload(client, FIXTURE.read_bytes()).status_code == 413


def test_invalid_threshold_returns_422(client):
    assert upload(client, FIXTURE.read_bytes(), brute_force_threshold=0).status_code == 422


def test_time_window_out_of_range_returns_422(client):
    assert upload(client, FIXTURE.read_bytes(), time_window_seconds=4000).status_code == 422


def test_database_failure_mid_analysis_returns_500_and_leaves_no_partial_result(client, repo, monkeypatch):
    def broken_save_alerts(self, run_id, alerts):
        raise mysql.connector.Error("connection lost")

    monkeypatch.setattr(Repository, "save_alerts", broken_save_alerts)
    safe_client = TestClient(fastapi_app, raise_server_exceptions=False)

    response = upload(safe_client, FIXTURE.read_bytes())

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    [run] = repo.list_runs()
    assert run["status"] == "failed"
    assert run["alert_count"] == 0
    assert "connection lost" in run["error_message"]


# ---------- POST /api/analyses: no copies of uploaded logs are kept ----------

@pytest.fixture
def seen_temp_paths(monkeypatch):
    paths = []
    real_analyze_upload = app.main.analyze_upload

    def spy(path, filename, settings, repository):
        paths.append(path)
        return real_analyze_upload(path, filename, settings, repository)

    monkeypatch.setattr(app.main, "analyze_upload", spy)
    return paths


def test_temporary_file_is_deleted_after_analysis(client, seen_temp_paths):
    upload(client, FIXTURE.read_bytes())

    assert len(seen_temp_paths) == 1
    assert not os.path.exists(seen_temp_paths[0])


def test_temporary_file_is_deleted_when_analysis_fails(client, seen_temp_paths):
    upload(client, b"not a log\n")

    assert not os.path.exists(seen_temp_paths[0])


# ---------- GET /api/analyses (history by analysis date, D12 / D15) ----------

def test_history_defaults_to_last_two_days(client, set_created_at):
    recent = upload(client, FIXTURE.read_bytes()).json()["id"]
    old = upload(client, CLEAN_LOG).json()["id"]
    set_created_at(old, datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=3))

    history = client.get("/api/analyses").json()

    assert [r["id"] for r in history] == [recent]
    assert set(history[0]) == {"id", "filename", "created_at", "status", "lines_parsed", "alert_count"}
    assert history[0]["alert_count"] == 2


def test_history_for_one_day_in_israel_time(client, set_created_at):
    inside = upload(client, FIXTURE.read_bytes()).json()["id"]
    set_created_at(inside, datetime(2026, 11, 11, 21, 59))            # 11 Nov 23:59 in Israel
    outside = upload(client, CLEAN_LOG).json()["id"]
    set_created_at(outside, datetime(2026, 11, 11, 22, 0))            # 12 Nov 00:00 in Israel

    history = client.get("/api/analyses", params={
        "from": "2026-11-11T00:00:00+02:00", "to": "2026-11-12T00:00:00+02:00"}).json()

    assert [r["id"] for r in history] == [inside]


def test_history_with_only_to_covers_two_days_before_it(client, set_created_at):
    in_range = upload(client, FIXTURE.read_bytes()).json()["id"]
    set_created_at(in_range, datetime(2026, 11, 9, 12, 0))
    too_old = upload(client, CLEAN_LOG).json()["id"]
    set_created_at(too_old, datetime(2026, 11, 7, 12, 0))

    history = client.get("/api/analyses", params={"to": "2026-11-10T00:00:00Z"}).json()

    assert [r["id"] for r in history] == [in_range]


def test_history_is_newest_first(client, set_created_at):
    older = upload(client, FIXTURE.read_bytes()).json()["id"]
    newer = upload(client, CLEAN_LOG).json()["id"]
    set_created_at(older, datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=5))

    assert [r["id"] for r in client.get("/api/analyses").json()] == [newer, older]


def test_history_with_no_runs_is_an_empty_list(client):
    response = client.get("/api/analyses")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize("params", [
    {"from": "2026-11-12T00:00:00+02:00", "to": "2026-11-11T00:00:00+02:00"},   # from after to
    {"from": "2026-11-12T00:00:00"},                                             # no time zone
    {"to": "not-a-date"},                                                        # not a date
], ids=["from_after_to", "no_time_zone", "not_a_date"])
def test_invalid_history_range_returns_422(client, params):
    assert client.get("/api/analyses", params=params).status_code == 422


# ---------- GET /api/analyses/{id} and /alerts ----------

def test_get_one_analysis(client):
    run_id = upload(client, FIXTURE.read_bytes(), filename="sample_logs.txt").json()["id"]

    body = client.get(f"/api/analyses/{run_id}").json()

    assert body["id"] == run_id
    assert body["filename"] == "sample_logs.txt"
    assert body["alert_count"] == 2
    assert "alerts" not in body


def test_get_analysis_that_does_not_exist_returns_404(client):
    response = client.get("/api/analyses/999999")

    assert response.status_code == 404
    assert response.json() == {"detail": "Analysis 999999 not found"}


def test_get_alerts_of_an_analysis(client):
    run_id = upload(client, FIXTURE.read_bytes()).json()["id"]

    alerts = client.get(f"/api/analyses/{run_id}/alerts").json()

    assert [(a["threat_type"], a["ip_address"]) for a in alerts] == [
        ("Brute Force", "10.0.0.1"), ("Scanning", "10.0.0.3")]


def test_get_alerts_filtered_by_type(client):
    run_id = upload(client, FIXTURE.read_bytes()).json()["id"]

    alerts = client.get(f"/api/analyses/{run_id}/alerts", params={"threat_type": "Scanning"}).json()

    assert [a["ip_address"] for a in alerts] == ["10.0.0.3"]


def test_get_alerts_of_clean_run_is_an_empty_list(client):
    run_id = upload(client, CLEAN_LOG).json()["id"]

    response = client.get(f"/api/analyses/{run_id}/alerts")

    assert response.status_code == 200
    assert response.json() == []


def test_get_alerts_of_analysis_that_does_not_exist_returns_404(client):
    assert client.get("/api/analyses/999999/alerts").status_code == 404
