# Log Threat Analyzer

A Python CLI tool for real-time log analysis and cyber threat detection. Built with an emphasis on low memory consumption and efficient data streaming.

## Key Features
* **Lazy Loading:** Processes massive log files line-by-line using Python Generators.
* **Real-time Threat Detection:** Employs a Sliding Window algorithm to detect Brute Force and Vulnerability Scanning attacks.
* **JSONL Streaming:** Exports alerts instantly to a JSON Lines format, ensuring zero data loss during potential system crashes.
* **CLI Interface:** Fully customizable thresholds and window sizes via command-line arguments.

## Technologies Used
* Python (Standard Library: `argparse`, `collections`, `json`, `re`)
* Linux / Ubuntu environment

## Usage
Run the analyzer with custom thresholds:
`python analyzer.py logs/server_logs.txt -w 60 -b 5 -s 15 -o output/alerts.jsonl`