"""Analysis Service - orchestrates one analysis of a log file.

Uses the existing parser + engine. Knows nothing about HTTP (status codes, uploads)
and, for now, nothing about the database - that is added in Phase 5.
See docs/DESIGN.md, sections 2 and 3.
"""
from dataclasses import dataclass, field
from typing import Dict, List

from engine import SecurityEngine
from parser import read_logs


class NotALogFileError(Exception):
    """The file was read, but not a single line looked like a log line."""


@dataclass(frozen=True)
class AnalysisSettings:
    """The thresholds used for one analysis. Defaults match the CLI."""
    time_window_seconds: int = 60
    brute_force_threshold: int = 5
    scanning_threshold: int = 15


@dataclass
class AnalysisResult:
    settings: AnalysisSettings
    lines_parsed: int = 0
    alerts: List[Dict[str, str]] = field(default_factory=list)


def analyze_file(path: str, settings: AnalysisSettings) -> AnalysisResult:
    """Run parser + engine on a log file.

    Raises:
        NotALogFileError: no line in the file is a log line in a supported format
            (so "0 alerts" is never reported for a file that was not a log at all).
        OSError: the file cannot be read.
    """
    result = AnalysisResult(settings=settings)
    engine = SecurityEngine(
        time_window_seconds=settings.time_window_seconds,
        brute_force_threshold=settings.brute_force_threshold,
        scanning_threshold=settings.scanning_threshold,
        on_alert_callback=result.alerts.append,
    )

    for parsed_line in read_logs(path):
        result.lines_parsed += 1
        engine.process_line(parsed_line)

    if result.lines_parsed == 0:
        raise NotALogFileError("No log lines in a supported format were found")

    return result
