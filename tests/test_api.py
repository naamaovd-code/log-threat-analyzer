"""Tests for the web API (app/main.py).

TestClient sends real HTTP requests to the app in memory - no server process is started.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

import app.main
from app.main import app as fastapi_app

client = TestClient(fastapi_app)

PROJECT_ROOT = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"


def upload(content: bytes, filename: str = "server.log", **settings):
    """POST a file (and optional settings) to /api/analyses."""
    return client.post(
        "/api/analyses",
        files={"file": (filename, content, "text/plain")},
        data={key: str(value) for key, value in settings.items()},
    )


# ---------- health ----------

def test_health_returns_ok():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_unknown_endpoint_returns_404():
    assert client.get("/api/does-not-exist").status_code == 404


def test_health_rejects_wrong_http_method():
    # /api/health only supports GET
    assert client.post("/api/health").status_code == 405


# ---------- POST /api/analyses: success ----------

def test_analyze_fixture():
    response = upload(FIXTURE.read_bytes(), filename="sample_logs.txt")

    assert response.status_code == 201
    body = response.json()
    assert body["filename"] == "sample_logs.txt"
    assert body["status"] == "completed"
    assert body["settings"] == {"time_window_seconds": 60, "brute_force_threshold": 5, "scanning_threshold": 15}
    assert body["lines_parsed"] == 32
    assert body["alert_count"] == 2
    assert body["alerts"][0] == {
        "threat_type": "Brute Force",
        "ip_address": "10.0.0.1",
        "detected_at": "2026-11-10T10:00:05Z",
        "details": "5 failed attempts in 60 seconds",
    }


def test_api_gives_the_same_alerts_as_the_cli(tmp_path):
    output_file = tmp_path / "cli_alerts.jsonl"
    subprocess.run(
        [sys.executable, "analyzer.py", str(FIXTURE), "-o", str(output_file)],
        cwd=PROJECT_ROOT, check=True, capture_output=True,
    )
    cli_alerts = [json.loads(line) for line in output_file.read_text(encoding="utf-8").splitlines()]

    api_alerts = upload(FIXTURE.read_bytes()).json()["alerts"]

    assert [(a["threat_type"], a["ip_address"], a["details"]) for a in api_alerts] == \
           [(a["type"], a["ip_address"], a["details"]) for a in cli_alerts]


def test_custom_settings_are_used_and_returned():
    response = upload(FIXTURE.read_bytes(), brute_force_threshold=3)

    body = response.json()
    assert body["settings"]["brute_force_threshold"] == 3
    assert body["alert_count"] == 3   # 10.0.0.2 (4 attempts) is now also an attack


def test_windows_line_endings_are_supported():
    windows_content = FIXTURE.read_text(encoding="utf-8").replace("\n", "\r\n").encode("utf-8")

    body = upload(windows_content).json()

    assert body["lines_parsed"] == 32
    assert body["alert_count"] == 2


def test_clean_log_is_201_with_zero_alerts():
    response = upload(b'1.2.3.4 - - [10/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512\n')

    assert response.status_code == 201
    assert response.json()["lines_parsed"] == 1
    assert response.json()["alerts"] == []


# ---------- POST /api/analyses: errors ----------

def test_file_that_is_not_a_log_returns_400():
    response = upload(b"milk\nbread\neggs\n", filename="shopping.txt")

    assert response.status_code == 400
    assert response.json() == {"detail": "No log lines in a supported format were found"}


def test_empty_file_returns_400():
    response = upload(b"")

    assert response.status_code == 400
    assert response.json() == {"detail": "File is empty"}


def test_missing_file_returns_422():
    assert client.post("/api/analyses").status_code == 422


def test_file_larger_than_limit_returns_413(monkeypatch):
    monkeypatch.setattr(app.main, "MAX_UPLOAD_BYTES", 100)

    response = upload(FIXTURE.read_bytes())   # the fixture is larger than 100 bytes

    assert response.status_code == 413


def test_invalid_threshold_returns_422():
    assert upload(FIXTURE.read_bytes(), brute_force_threshold=0).status_code == 422


def test_time_window_out_of_range_returns_422():
    assert upload(FIXTURE.read_bytes(), time_window_seconds=4000).status_code == 422


# ---------- POST /api/analyses: no copies of uploaded logs are kept ----------

def test_temporary_file_is_deleted_after_analysis(monkeypatch):
    seen_paths = []
    real_analyze_file = app.main.analyze_file

    def spy(path, settings):
        seen_paths.append(path)
        return real_analyze_file(path, settings)

    monkeypatch.setattr(app.main, "analyze_file", spy)

    upload(FIXTURE.read_bytes())

    assert len(seen_paths) == 1
    assert not os.path.exists(seen_paths[0])


def test_temporary_file_is_deleted_when_analysis_fails(monkeypatch):
    seen_paths = []
    real_analyze_file = app.main.analyze_file

    def spy(path, settings):
        seen_paths.append(path)
        return real_analyze_file(path, settings)

    monkeypatch.setattr(app.main, "analyze_file", spy)

    upload(b"not a log\n")

    assert not os.path.exists(seen_paths[0])
