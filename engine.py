"""Analyzing log data to identify potential security threats"""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Dict, Deque

LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"     # e.g. 10/Nov/2026:12:00:00 +0200
ALERT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"      # always UTC

BRUTE_FORCE = "Brute Force"
SCANNING = "Scanning"


class SecurityEngine:
    """Processes log lines in real-time to detect anomalous patterns.

    Rules:
      * An alert is raised when an IP reaches the threshold (inclusive) inside the time window.
      * After an alert, the same IP + threat type is not alerted again until a full
        time window has passed (cooldown). One continuous attack = one alert per window.
      * All alert timestamps are converted to UTC.
    """

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
        self.time_window_seconds = time_window_seconds
        self.time_window = timedelta(seconds=time_window_seconds)
        self.brute_force_threshold = brute_force_threshold
        self.scanning_threshold = scanning_threshold
        self.on_alert_callback = on_alert_callback

        # per threat type: ip -> timestamps of recent events inside the window
        self.history: Dict[str, Dict[str, Deque[datetime]]] = {
            BRUTE_FORCE: defaultdict(deque),
            SCANNING: defaultdict(deque),
        }
        # per threat type: ip -> time of the last alert (for the cooldown)
        self.last_alert_time: Dict[str, Dict[str, datetime]] = {
            BRUTE_FORCE: {},
            SCANNING: {},
        }

    def process_line(self, parsed_data: Optional[Dict[str, str]]) -> None:
        """Routes the parsed log data to the appropriate threat detection logic based on status code."""
        if not parsed_data:
            return
        ip = parsed_data['ip_address']
        status = parsed_data['status_code']

        if status == "401":
            threat_type, threshold, description = BRUTE_FORCE, self.brute_force_threshold, "failed attempts"
        elif status in ("403", "404"):
            threat_type, threshold, description = SCANNING, self.scanning_threshold, "scanning attempts"
        else:
            return

        current_time = self._to_utc(parsed_data['timestamp'])
        self._check(threat_type, ip, current_time, threshold, description)

    def _check(self, threat_type: str, ip: str, current_time: datetime, threshold: int, description: str) -> None:
        """Add the event to the IP's sliding window and raise an alert if needed."""
        queue = self.history[threat_type][ip]
        events_in_window = self._update_sliding_window(queue, current_time)

        if events_in_window < threshold:
            return
        if self._in_cooldown(threat_type, ip, current_time):
            return

        self.last_alert_time[threat_type][ip] = current_time
        alert = {
            "type": threat_type,
            "ip_address": ip,
            "timestamp": current_time.strftime(ALERT_TIME_FORMAT),
            "details": f"{events_in_window} {description} in {self.time_window_seconds} seconds",
        }
        if self.on_alert_callback:
            self.on_alert_callback(alert)

    def _update_sliding_window(self, queue: Deque[datetime], current_time: datetime) -> int:
        """Add the current event, drop events older than the window, return how many remain."""
        queue.append(current_time)
        threshold_time = current_time - self.time_window
        while queue and queue[0] < threshold_time:
            queue.popleft()
        return len(queue)

    def _in_cooldown(self, threat_type: str, ip: str, current_time: datetime) -> bool:
        """True if this IP was already alerted for this threat less than one window ago."""
        last_alert = self.last_alert_time[threat_type].get(ip)
        return last_alert is not None and current_time - last_alert < self.time_window

    @staticmethod
    def _to_utc(timestamp_str: str) -> datetime:
        """Parse a log timestamp (with its time zone offset) and convert it to UTC."""
        return datetime.strptime(timestamp_str, LOG_TIME_FORMAT).astimezone(timezone.utc)
