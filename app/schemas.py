"""The shape of the JSON the API returns (docs/DESIGN.md, section 5).

Pydantic models: FastAPI uses them to validate the response and to document it in /docs.
Datetimes are time zone-aware UTC values and appear in JSON as ISO 8601 with "Z",
e.g. "2026-11-10T10:00:05Z".
"""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class AlertOut(BaseModel):
    threat_type: str
    ip_address: str
    detected_at: datetime
    details: str


class SettingsOut(BaseModel):
    time_window_seconds: int
    brute_force_threshold: int
    scanning_threshold: int


class RunSummaryOut(BaseModel):
    """One row of the history list."""
    id: int
    filename: str
    created_at: datetime
    status: str
    lines_parsed: Optional[int]
    alert_count: int


class RunOut(RunSummaryOut):
    """One run with all its details (GET /api/analyses/{id})."""
    settings: SettingsOut
    error_message: Optional[str]


class AnalysisOut(RunOut):
    """Response of POST /api/analyses: the run, whether it was reused, and its alerts."""
    reused: bool
    alerts: List[AlertOut]
