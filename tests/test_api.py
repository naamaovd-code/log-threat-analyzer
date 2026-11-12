"""Tests for the web API (app/main.py).

TestClient sends real HTTP requests to the app in memory - no server process is started.
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_unknown_endpoint_returns_404():
    response = client.get("/api/does-not-exist")

    assert response.status_code == 404


def test_health_rejects_wrong_http_method():
    # /api/health only supports GET
    response = client.post("/api/health")

    assert response.status_code == 405
