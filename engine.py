"""Analyzing log data to identify potential security threats"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Optional, Dict, Deque

class SecurityEngine:
    """Processes log lines in real-time to detect anomalous patterns."""

    def __init__(
        self, 
        time_window_seconds: int = 60, 
        brute_force_threshold: int = 5, 
        scanning_threshold: int = 15, 
        on_alert_callback: Optional[Callable[[Dict[str, str]], None]] = None
    ) -> None:
        """
        Initialize the security engine with configurable thresholds.
        """
        # אתחול הגדרות המערכת
        self.time_window_seconds = time_window_seconds
        self.brute_force_threshold = brute_force_threshold
        self.scanning_threshold = scanning_threshold
        self.on_alert_callback = on_alert_callback

        self.brute_force_history = defaultdict(deque)
        self.scanning_history = defaultdict(deque)

        
        
    def process_line(self, parsed_data: Optional[Dict[str, str]]) -> None:
        """Routes the parsed log data to the appropriate threat detection logic based on status code."""
        if not parsed_data:
            return
        ip = parsed_data['ip_address']
        timestamp_str = parsed_data['timestamp']
        status = parsed_data['status_code']

        if status == "401":
            self._check_brute_force(ip, timestamp_str)
        elif status in ["403", "404"]:
            self._check_scanning(ip, timestamp_str)
    
    def _check_brute_force(self, ip, timestamp_str):
        current_time = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")

        queue = self.brute_force_history[ip]
        if self._check_sliding_window(queue, self.brute_force_threshold, current_time):
            alert = {
                "type": "Brute Force",
                "ip_address": ip,
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "details": f"{len(queue)} failed attempts in {self.time_window_seconds} seconds"
            }
            if self.on_alert_callback:
                self.on_alert_callback(alert)
            

            queue.clear()
    def _check_scanning(self, ip, timestamp_str):
        current_time = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")

        queue = self.scanning_history[ip]
        if self._check_sliding_window(queue, self.scanning_threshold, current_time):
            alert = {
                "type": "Scanning",
                "ip_address": ip,
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "details": f"{len(queue)} scanning attempts in {self.time_window_seconds} seconds"
            }
            if self.on_alert_callback:
                self.on_alert_callback(alert)
            

            queue.clear()
    def _check_sliding_window(self, queue, limit, current_time) -> bool:

        queue.append(current_time)

        threshold_time = current_time - timedelta(seconds=self.time_window_seconds)
    
        while queue and queue[0] < threshold_time:
            queue.popleft()
        return (len(queue) >= limit)
           


