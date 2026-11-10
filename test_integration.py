from engine import SecurityEngine
from parser import read_logs


def test_full_flow():

    log_file_path = "logs/server_logs.txt"

    print("🚀 Initialize security Engine...")
    alerts = []
    engine = SecurityEngine(on_alert_callback=alerts.append)

    print(f"📂 Read file: {log_file_path}")
    line_count = 0

    for parsed_data in read_logs(log_file_path):
        line_count += 1
        engine.process_line(parsed_data)

    print("-" * 30)
    print(f"✅ finish! read {line_count} Log lines.")
    print(f"🚨 Detected alerts: {len(alerts)}\n")

    for alert in alerts:
        print(f"[{alert['timestamp']}] {alert['type']} - IP: {alert['ip_address']} | {alert['details']}")

    assert line_count > 0, "No log lines were read"
    assert len(alerts) > 0, "Expected at least one alert"
    detected_types = {alert['type'] for alert in alerts}
    assert "Brute Force" in detected_types
    assert "Scanning" in detected_types


if __name__ == "__main__":
    test_full_flow()
