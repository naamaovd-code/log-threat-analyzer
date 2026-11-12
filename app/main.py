"""Log Threat Analyzer - Web API (FastAPI).

API routes only: receive HTTP requests, validate input, choose status codes, return JSON.
No detection logic and no SQL here (see docs/DESIGN.md, section 2).

Run the server from the project root:
    uvicorn app.main:app --reload --port 8000
Then open http://localhost:8000/docs
"""
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import PROJECT_ROOT, database_config
from app.repository import Repository
from app.schemas import AlertOut, AnalysisOut, RunOut, RunSummaryOut, SettingsOut
from app.service import AnalysisSettings, NotALogFileError, analyze_upload

MAX_UPLOAD_BYTES = 10 * 1024 * 1024        # 10 MB (decision D3)
CHUNK_SIZE = 64 * 1024                     # read the upload in 64 KB pieces
DEFAULT_HISTORY_PERIOD = timedelta(days=2)  # history shows the last 2 days by default (decision D15)
STATIC_DIR = PROJECT_ROOT / "static"       # the browser page: index.html, app.js, style.css

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Log Threat Analyzer",
    description="Upload a log file, detect suspicious activity, and browse the history of analyses.",
    version="0.4.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """The web page (decision D8: plain HTML + JS served by FastAPI)."""
    return FileResponse(STATIC_DIR / "index.html")


def get_repository() -> Repository:
    """Dependency: the repository for the app database.
    Tests replace it with one connected to the test database (app.dependency_overrides)."""
    return Repository(database_config())


@app.exception_handler(Exception)
def unexpected_error(request: Request, error: Exception) -> JSONResponse:
    """Any unexpected error (e.g. the database is down) -> 500 with a JSON body, like all other errors.
    The details go to the server log, not to the client."""
    logger.exception("Unexpected error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---------- health ----------

@app.get("/api/health")
def health() -> dict:
    """Checks that the server is up."""
    return {"status": "ok"}


# ---------- analyses ----------

@app.post("/api/analyses", status_code=status.HTTP_201_CREATED, response_model=AnalysisOut,
          responses={200: {"description": "Same content with the same settings was already analyzed; "
                                          "the existing run is returned (reused = true)"}})
def create_analysis(
    response: Response,
    file: UploadFile = File(..., description="Log file in Common Log Format (Apache / Nginx)"),
    time_window_seconds: int = Form(60, ge=1, le=3600),
    brute_force_threshold: int = Form(5, ge=1),
    scanning_threshold: int = Form(15, ge=1),
    repository: Repository = Depends(get_repository),
) -> AnalysisOut:
    """Upload a log file, analyze it and store the result.

    201: new analysis. 200: already analyzed (reused). 400: empty file or not a log file.
    413: file too large. 422: missing file or invalid settings. 500: analysis or database failed.
    """
    settings = AnalysisSettings(time_window_seconds, brute_force_threshold, scanning_threshold)

    temp_path = _save_upload_to_temp_file(file)
    try:
        outcome = analyze_upload(temp_path, file.filename or "", settings, repository)
    except NotALogFileError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    finally:
        os.remove(temp_path)   # never keep a copy of the uploaded log (decision D5)

    if outcome.reused:
        response.status_code = status.HTTP_200_OK

    run = repository.get_run(outcome.run_id)
    alerts = repository.get_alerts(outcome.run_id)
    return AnalysisOut(**_run_fields(run), reused=outcome.reused, alerts=[AlertOut(**a) for a in alerts])


@app.get("/api/analyses", response_model=List[RunSummaryOut])
def list_analyses(
    from_: Optional[datetime] = Query(
        None, alias="from",
        description="Runs created at or after this moment. ISO 8601 with time zone, e.g. 2026-11-12T00:00:00+02:00. "
                    "Default: 2 days before `to` (or before now)."),
    to: Optional[datetime] = Query(
        None, description="Runs created before this moment (exclusive). ISO 8601 with time zone. Default: no limit."),
    repository: Repository = Depends(get_repository),
) -> List[RunSummaryOut]:
    """History of runs by analysis date (decision D12), newest first. An empty list is not an error."""
    for name, value in (("from", from_), ("to", to)):
        if value is not None and value.tzinfo is None:
            raise HTTPException(status_code=422, detail=f"'{name}' must include a time zone, e.g. +02:00 or Z")

    if from_ is None:
        from_ = (to or datetime.now(timezone.utc)) - DEFAULT_HISTORY_PERIOD
    if to is not None and from_ > to:
        raise HTTPException(status_code=422, detail="'from' must not be after 'to'")

    return [RunSummaryOut(**_summary_fields(run)) for run in repository.list_runs(from_, to)]


@app.get("/api/analyses/{run_id}", response_model=RunOut)
def get_analysis(run_id: int, repository: Repository = Depends(get_repository)) -> RunOut:
    """One run, without its alerts."""
    return RunOut(**_run_fields(_existing_run(repository, run_id)))


@app.get("/api/analyses/{run_id}/alerts", response_model=List[AlertOut])
def get_analysis_alerts(
    run_id: int,
    threat_type: Optional[str] = Query(None, description="Only this type, e.g. 'Brute Force' or 'Scanning'"),
    repository: Repository = Depends(get_repository),
) -> List[AlertOut]:
    """Alerts of one run in time order. An empty list means the run had no alerts."""
    _existing_run(repository, run_id)
    return [AlertOut(**a) for a in repository.get_alerts(run_id, threat_type)]


# ---------- helpers ----------

def _existing_run(repository: Repository, run_id: int) -> Dict:
    run = repository.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Analysis {run_id} not found")
    return run


def _summary_fields(run: Dict) -> Dict:
    return {key: run[key] for key in ("id", "filename", "created_at", "status", "lines_parsed", "alert_count")}


def _run_fields(run: Dict) -> Dict:
    return {
        **_summary_fields(run),
        "settings": SettingsOut(**vars(run["settings"])),
        "error_message": run["error_message"],
    }


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
