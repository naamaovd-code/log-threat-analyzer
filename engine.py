"""Analyzing log data to identify potential security threats"""
import bisect
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Dict, List

LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"     # e.g. 10/Nov/2026:12:00:00 +0200
ALERT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"      # always UTC

BRUTE_FORCE = "Brute Force"
SCANNING = "Scanning"


class SecurityEngine:
    """Processes log lines in real-time to detect anomalous patterns.

    Rules:
      * An alert is raised when an IP has at least `threshold` events (inclusive)
        inside some time window of `time_window_seconds`.
      * Log lines may arrive in any time order (e.g. merged or rotated logs, or a
        server that writes a request only when it finishes). Only events that are
        really within one window of each other are counted together.
      * After an alert, the same IP + threat type is not alerted again for events
        less than one full window away from that alert (cooldown).
        One continuous attack = one alert per window.
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

        # per threat type: ip -> event times, always kept SORTED (lines may arrive out of order)
        self.history: Dict[str, Dict[str, List[datetime]]] = {
            BRUTE_FORCE: defaultdict(list),
            SCANNING: defaultdict(list),
        }
        # per threat type: ip -> times of the alerts already raised, kept sorted (for the cooldown)
        self.alert_times: Dict[str, Dict[str, List[datetime]]] = {
            BRUTE_FORCE: defaultdict(list),
            SCANNING: defaultdict(list),
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
        """Record the event and raise an alert if it completes a window with enough events."""
        times = self.history[threat_type][ip]
        bisect.insort(times, current_time)

        # checked first: skips the counting work for every event of an attack that was already reported
        if self._in_cooldown(threat_type, ip, current_time):
            return

        events_in_window = self._busiest_window_containing(times, current_time)
        if events_in_window < threshold:
            return

        bisect.insort(self.alert_times[threat_type][ip], current_time)
        alert = {
            "type": threat_type,
            "ip_address": ip,
            "timestamp": current_time.strftime(ALERT_TIME_FORMAT),
            "details": f"{events_in_window} {description} in {self.time_window_seconds} seconds",
        }
        if self.on_alert_callback:
            self.on_alert_callback(alert)

    def _busiest_window_containing(self, times: List[datetime], current_time: datetime) -> int:
        """The largest number of events in any time window that contains current_time.

        `times` is sorted. A window [start, start + window] contains current_time when
        start is between (current_time - window) and current_time. The busiest such
        window always starts exactly at an event, so every event in that range is tried
        as the start, and binary search (bisect) counts the events inside each window.
        """
        first = bisect.bisect_left(times, current_time - self.time_window)
        last = bisect.bisect_right(times, current_time)

        busiest = 0
        for start_index in range(first, last):
            end_index = bisect.bisect_right(times, times[start_index] + self.time_window)
            busiest = max(busiest, end_index - start_index)
        return busiest

    def _in_cooldown(self, threat_type: str, ip: str, current_time: datetime) -> bool:
        """True if this IP was already alerted for this threat less than one window away
        from current_time - before or after it, since lines may arrive out of order."""
        alerts = self.alert_times[threat_type][ip]
        i = bisect.bisect_left(alerts, current_time)
        nearest = alerts[max(i - 1, 0): i + 1]   # the closest alert before and after
        return any(abs(current_time - alert_time) < self.time_window for alert_time in nearest)

    @staticmethod
    def _to_utc(timestamp_str: str) -> datetime:
        """Parse a log timestamp (with its time zone offset) and convert it to UTC."""
        return datetime.strptime(timestamp_str, LOG_TIME_FORMAT).astimezone(timezone.utc)
