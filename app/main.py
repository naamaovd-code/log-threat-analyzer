"""Log Threat Analyzer - Web API (FastAPI).

API routes only: receive HTTP requests, validate input, choose status codes, return JSON.
No detection logic and no SQL here (see docs/DESIGN.md, section 2).

Run the server from the project root:
    uvicorn app.main:app --reload --port 8000
Then open http://localhost:8000/docs
"""
import os
import tempfile
from typing import Dict

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status

from app.schemas import AlertOut, AnalysisOut, SettingsOut
from app.service import AnalysisSettings, NotALogFileError, analyze_file

MAX_UPLOAD_BYTES = 10 * 1024 * 1024   # 10 MB (docs/DESIGN.md, decision D3)
CHUNK_SIZE = 64 * 1024                # read the upload in 64 KB pieces

app = FastAPI(
    title="Log Threat Analyzer",
    description="Upload a log file, detect suspicious activity, and browse the history of analyses.",
    version="0.2.0",
)


@app.get("/api/health")
def health() -> dict:
    """Checks that the server is up."""
    return {"status": "ok"}


@app.post("/api/analyses", status_code=status.HTTP_201_CREATED, response_model=AnalysisOut)
def create_analysis(
    file: UploadFile = File(..., description="Log file in Common Log Format (Apache / Nginx)"),
    time_window_seconds: int = Form(60, ge=1, le=3600),
    brute_force_threshold: int = Form(5, ge=1),
    scanning_threshold: int = Form(15, ge=1),
) -> AnalysisOut:
    """Upload a log file and analyze it.

    Errors: 400 empty file or not a log file, 413 file too large,
    422 missing file or invalid settings (checked by FastAPI).
    """
    settings = AnalysisSettings(time_window_seconds, brute_force_threshold, scanning_threshold)

    temp_path = _save_upload_to_temp_file(file)
    try:
        result = analyze_file(temp_path, settings)
    except NotALogFileError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    finally:
        os.remove(temp_path)   # never keep a copy of the uploaded log (decision D5)

    return AnalysisOut(
        filename=file.filename or "",
        status="completed",
        settings=SettingsOut(**vars(settings)),
        lines_parsed=result.lines_parsed,
        alert_count=len(result.alerts),
        alerts=[_alert_to_api(alert) for alert in result.alerts],
    )


def _save_upload_to_temp_file(file: UploadFile) -> str:
    """Copy the upload to a temporary file, enforcing the size limit while copying.

    Reading in chunks means a huge upload is rejected as soon as it passes the limit,
    without ever holding the whole file in memory.
    """
    size = 0
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as temp_file:
        try:
            while chunk := file.file.read(CHUNK_SIZE):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
                    )
                temp_file.write(chunk)
            if size == 0:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty")
        except HTTPException:
            temp_file.close()
            os.remove(temp_file.name)
            raise
    return temp_file.name


def _alert_to_api(alert: Dict[str, str]) -> AlertOut:
    """Engine alert -> API alert (names from the data model, time as ISO 8601 UTC)."""
    return AlertOut(
        threat_type=alert["type"],
        ip_address=alert["ip_address"],
        detected_at=alert["timestamp"].replace(" ", "T") + "Z",
        details=alert["details"],
    )
