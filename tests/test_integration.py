"""End-to-end test: parser + engine on a small log file with known expected alerts."""
from pathlib import Path

from engine import SecurityEngine
from parser import read_logs

FIXTURE = Path(__file__).parent / "fixtures" / "sample_logs.txt"


def analyze(path):
    """Run parser + engine on a file. Return (number of log lines recognized, alerts)."""
    alerts = []
    engine = SecurityEngine(on_alert_callback=alerts.append)
    lines_parsed = 0
    for parsed_data in read_logs(path):
        lines_parsed += 1
        engine.process_line(parsed_data)
    return lines_parsed, alerts


def test_clean_server_log_is_recognized_with_zero_alerts(tmp_path):
    # a healthy server: valid log lines, nothing suspicious -> lines are counted, no alerts
    log_file = tmp_path / "clean.log"
    log_file.write_text(
        '1.2.3.4 - - [10/Nov/2026:10:00:00 +0000] "GET /home HTTP/1.1" 200 1024\n'
        '1.2.3.4 - - [10/Nov/2026:10:00:01 +0000] "GET /about HTTP/1.1" 200 2048\n',
        encoding="utf-8",
    )
    assert analyze(log_file) == (2, [])


def test_file_that_is_not_a_log_has_zero_recognized_lines(tmp_path):
    # must be distinguishable from a clean server: zero lines, not "zero alerts"
    not_a_log = tmp_path / "shopping.txt"
    not_a_log.write_text("milk\nbread\neggs\n", encoding="utf-8")
    assert analyze(not_a_log) == (0, [])


def test_full_flow():
    lines_parsed, alerts = analyze(FIXTURE)

    # 34 lines in the file, 2 of them are not log lines (ERROR, sshd)
    assert lines_parsed == 32

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
