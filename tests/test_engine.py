"""Unit tests for engine.py (SecurityEngine)"""
from datetime import datetime, timedelta, timezone

from engine import SecurityEngine

BASE_TIME = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)


def event(ip, seconds_after_base, status):
    """Build a parsed log line, like parser.parse_line returns."""
    timestamp = (BASE_TIME + timedelta(seconds=seconds_after_base)).strftime("%d/%b/%Y:%H:%M:%S %z")
    return {"ip_address": ip, "timestamp": timestamp, "status_code": status}


def run_engine(events, **engine_options):
    """Feed events into a new engine and return the alerts it raised."""
    alerts = []
    engine = SecurityEngine(on_alert_callback=alerts.append, **engine_options)
    for e in events:
        engine.process_line(e)
    return alerts


# ---------- Brute Force (401) ----------

def test_brute_force_alert_exactly_at_threshold():
    alerts = run_engine([event("1.1.1.1", s, "401") for s in range(5)])

    assert alerts == [{
        "type": "Brute Force",
        "ip_address": "1.1.1.1",
        "timestamp": "2026-11-10 10:00:04",
        "details": "5 failed attempts in 60 seconds",
    }]


def test_no_brute_force_alert_below_threshold():
    assert run_engine([event("1.1.1.1", s, "401") for s in range(4)]) == []


def test_no_brute_force_alert_when_attempts_are_spread_beyond_window():
    # 5 attempts, 40 seconds apart -> never more than 2 inside a 60 second window
    assert run_engine([event("1.1.1.1", s * 40, "401") for s in range(5)]) == []


def test_attempts_from_different_ips_are_counted_separately():
    events = [event(f"1.1.1.{i}", i, "401") for i in range(5)]
    assert run_engine(events) == []


def test_counter_resets_after_alert():
    # 10 attempts -> two separate alerts, because the window is cleared after each alert
    alerts = run_engine([event("1.1.1.1", s, "401") for s in range(10)])
    assert len(alerts) == 2


def test_custom_brute_force_threshold():
    alerts = run_engine([event("1.1.1.1", s, "401") for s in range(3)], brute_force_threshold=3)
    assert len(alerts) == 1


# ---------- Scanning (403 / 404) ----------

def test_scanning_alert_with_mixed_403_and_404():
    events = [event("2.2.2.2", s, "404" if s % 2 == 0 else "403") for s in range(15)]
    alerts = run_engine(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Scanning"
    assert alerts[0]["ip_address"] == "2.2.2.2"


def test_401_and_404_are_tracked_separately():
    # 4 x 401 + 4 x 404 from the same IP: neither reaches its own threshold
    events = [event("3.3.3.3", s, "401") for s in range(4)]
    events += [event("3.3.3.3", s, "404") for s in range(4, 8)]
    assert run_engine(events) == []


# ---------- Edge cases ----------

def test_none_and_unrelated_status_codes_are_ignored():
    assert run_engine([None, event("4.4.4.4", 0, "200"), event("4.4.4.4", 1, "500")]) == []


def test_engine_without_callback_does_not_crash():
    engine = SecurityEngine()
    for s in range(5):
        engine.process_line(event("5.5.5.5", s, "401"))
