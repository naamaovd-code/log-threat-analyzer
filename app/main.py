"""Log Threat Analyzer - Web API (FastAPI).

API routes only: receive HTTP requests, validate input, choose status codes, return JSON.
No detection logic and no SQL here (see docs/DESIGN.md, section 2).

Run the server from the project root:
    uvicorn app.main:app --reload --port 8000
Then open http://localhost:8000/docs
"""
from fastapi import FastAPI

app = FastAPI(
    title="Log Threat Analyzer",
    description="Upload a log file, detect suspicious activity, and browse the history of analyses.",
    version="0.1.0",
)


@app.get("/api/health")
def health() -> dict:
    """Checks that the server is up."""
    return {"status": "ok"}
