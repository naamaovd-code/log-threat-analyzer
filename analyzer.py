"""Identifying threat risks by scanning log lines"""
import argparse
import json
import os
from parser import read_logs
from engine import securityEngine

def setup_cli():

    """Sets up the command-line interface for the log threat analyzer."""
    parser = argparse.ArgumentParser(description="Log Threat Analyzer")
    parser.add_argument(
        "log_file",
        type=str,
        help="Path to the log file to be analyzed."
    )
    parser.add_argument(
        "-w", "--window",
        type = int,
        default = 60,
        help = "Time window in seconds for detecting threats (default: 60)."
    )
    parser.add_argument(
        "-b", "--brute-force-threshold",
        type = int,
        default = 5,
        help = "Number of failed attempts to trigger a brute force alert (default: 5)."
    )
    parser.add_argument(
        "-s", "--scanning-threshold",
        type = int,
        default = 15,
        help = "Number of scanning attempts to trigger a scanning alert (default: 15)."
    )
    parser.add_argument(
        "-o", "--output",
        type = str,
        default = "output/alerts.jsonl",
        help = "Path to output file for alerts in JSON format (default: None, prints to console)."
    )
    return parser.parse_args()

def main() -> None:

    """Entry point for the log threat analyzer CLI. Manages file I/O and streaming alerts."""
    args = setup_cli()
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    print(f"Starting analysis on {args.log_file}...")
    with open(args.output, 'w', encoding='utf-8') as outfile:
        def handle_alert(alert: Dict[str, str]) -> None:
            """Callback function to print alerts and append them to a JSONL file."""
            print(f"ALERT! {alert['type']} attempt detected from IP {alert['ip_address']}")
            outfile.write(json.dumps(alert) + '\n')
        engine = securityEngine(
            time_window_seconds=args.window, 
            brute_force_threshold=args.brute_force_threshold, 
            scanning_threshold=args.scanning_threshold,
            on_alert_callback=handle_alert
        )
        for log_data in read_logs(args.log_file):
            engine.process_line(log_data)
    print(f"Analysis complete! Alerts successfully saved to {args.output}")

    
if __name__ == "__main__":
    main()
