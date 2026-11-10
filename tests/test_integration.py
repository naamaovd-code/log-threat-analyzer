"""End-to-end test: parser + engine on a small log file with known expected alerts."""
from pathlib import Path

from engine import SecurityEngine
from parser import read_logs

FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"


def test_full_flow():
    alerts = []
    engine = SecurityEngine(on_alert_callback=alerts.append)

    for parsed_data in read_logs(FIXTURE):
        engine.process_line(parsed_data)

    # 10.0.0.1: 5 failed logins in 5 seconds  -> Brute Force
    # 10.0.0.2: only 4 failed logins           -> no alert (below threshold)
    # 10.0.0.4: 5 failed logins over 160 sec   -> no alert (outside the window)
    # 10.0.0.3: 15 x 403/404 in 15 seconds     -> Scanning
    assert alerts == [
        {
            "type": "Brute Force",
            "ip_address": "10.0.0.1",
            "timestamp": "2026-11-10 10:00:05",
            "details": "5 failed attempts in 60 seconds",
        },
        {
            "type": "Scanning",
            "ip_address": "10.0.0.3",
            "timestamp": "2026-11-10 10:05:14",
            "details": "15 scanning attempts in 60 seconds",
        },
    ]
