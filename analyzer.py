"""Identifying threat risks by scanning log lines"""
import argparse
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
    return parser.parse_args()

def main():

    """main function to run the log threat analyzer"""
    args = setup_cli()
    engine = securityEngine(
    time_window_seconds = args.window, 
    brute_force_threshold = args.brute_force_threshold, 
    scanning_threshold = args.scanning_threshold
    )

    print(f"Starting analysis on {args.log_file}...")
    for log_data in read_logs(args.log_file):
        engine.process_line(log_data)
    
    print("Analysis complete! Alerts generated:")
    for alert in engine.alerts:
        print(alert)

if __name__ == "__main__":
    main()
