"""Analysis Service - orchestrates one analysis of a log file (docs/DESIGN.md, sections 2 and 3).

Uses the existing parser + engine, and a repository to store the results.
Knows nothing about HTTP (status codes, uploads) and contains no SQL.
"""
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List

from engine import SecurityEngine
from parser import read_logs

HASH_CHUNK_SIZE = 64 * 1024


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


@dataclass(frozen=True)
class UploadOutcome:
    run_id: int
    reused: bool   # True: the same content with the same settings was already analyzed (D11)


def analyze_file(path: str, settings: AnalysisSettings) -> AnalysisResult:
    """Run parser + engine on a log file. Stores nothing.

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


def file_sha256(path: str) -> str:
    """Fingerprint of the file CONTENT (not its name): 64 hex characters."""
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while chunk := file.read(HASH_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_upload(path: str, filename: str, settings: AnalysisSettings, repository) -> UploadOutcome:
    """The full flow for an uploaded file:

    1. fingerprint the content
    2. same content + same settings already completed -> return that run (reused)
    3. create a 'pending' run
    4. analyze with parser + engine
    5. save the alerts and mark the run 'completed'
    If anything fails after step 3, the run is marked 'failed' (and partial alerts
    are deleted by the repository), then the error is raised to the caller.
    """
    file_hash = file_sha256(path)

    existing_run_id = repository.find_completed_run(file_hash, settings)
    if existing_run_id is not None:
        return UploadOutcome(run_id=existing_run_id, reused=True)

    run_id = repository.create_run(filename, file_hash, settings)
    try:
        result = analyze_file(path, settings)
        repository.save_alerts(run_id, result.alerts)
        repository.complete_run(run_id, result.lines_parsed)
    except NotALogFileError as error:
        _mark_failed(repository, run_id, str(error), lines_parsed=0)
        raise
    except Exception as error:
        _mark_failed(repository, run_id, f"{type(error).__name__}: {error}")
        raise

    return UploadOutcome(run_id=run_id, reused=False)


def _mark_failed(repository, run_id: int, message: str, lines_parsed=None) -> None:
    """Record the failure. If even that fails (e.g. the database is down), keep the
    ORIGINAL error for the caller instead of hiding it behind a second one."""
    try:
        repository.fail_run(run_id, message, lines_parsed=lines_parsed)
    except Exception:
        pass
