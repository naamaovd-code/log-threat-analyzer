"""The shape of the JSON the API returns (docs/DESIGN.md, section 5).

Pydantic models: FastAPI uses them to validate the response and to document it in /docs.
"""
from typing import List

from pydantic import BaseModel


class AlertOut(BaseModel):
    threat_type: str
    ip_address: str
    detected_at: str   # ISO 8601 in UTC, e.g. "2026-11-10T10:00:05Z"
    details: str


class SettingsOut(BaseModel):
    time_window_seconds: int
    brute_force_threshold: int
    scanning_threshold: int


class AnalysisOut(BaseModel):
    # id, created_at and reused are added in Phase 5, when runs are stored in the database
    filename: str
    status: str
    settings: SettingsOut
    lines_parsed: int
    alert_count: int
    alerts: List[AlertOut]
