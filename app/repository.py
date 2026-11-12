"""Repository - ALL the SQL of the application lives here (docs/DESIGN.md, sections 2 and 4).

Knows nothing about HTTP and nothing about how threats are detected.
Every connection uses the UTC time zone, so DATETIME columns (including
CURRENT_TIMESTAMP) are always UTC. Datetimes returned from here are
time zone-aware UTC values.

Queries use placeholders (%s) and never build SQL from user input with string
formatting - this is what prevents SQL injection.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

import mysql.connector

from app.config import DatabaseConfig
from app.service import AnalysisSettings
from engine import ALERT_TIME_FORMAT

MAX_ERROR_MESSAGE_LENGTH = 500   # analysis_runs.error_message is VARCHAR(500)

RUN_COLUMNS = """
    r.id, r.filename, r.file_hash, r.created_at, r.status, r.error_message, r.lines_parsed,
    r.time_window_seconds, r.brute_force_threshold, r.scanning_threshold
"""


class Repository:
    def __init__(self, config: DatabaseConfig) -> None:
        self.config = config

    # ---------- writing ----------

    def create_run(self, filename: str, file_hash: str, settings: AnalysisSettings) -> int:
        """Insert a new run with status 'pending'. Returns its id."""
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO analysis_runs
                    (filename, file_hash, time_window_seconds, brute_force_threshold, scanning_threshold)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (filename, file_hash, settings.time_window_seconds,
                 settings.brute_force_threshold, settings.scanning_threshold),
            )
            return cursor.lastrowid

    def save_alerts(self, run_id: int, alerts: List[Dict[str, str]]) -> None:
        """Insert the engine's alerts for a run (mapping in docs/DESIGN.md, section 4)."""
        if not alerts:
            return
        rows = [
            (run_id, alert["type"], alert["ip_address"],
             datetime.strptime(alert["timestamp"], ALERT_TIME_FORMAT), alert["details"])
            for alert in alerts
        ]
        with self._cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO alerts (analysis_run_id, threat_type, ip_address, detected_at, details)
                VALUES (%s, %s, %s, %s, %s)
                """,
                rows,
            )

    def complete_run(self, run_id: int, lines_parsed: int) -> None:
        with self._cursor() as cursor:
            cursor.execute(
                "UPDATE analysis_runs SET status = 'completed', lines_parsed = %s WHERE id = %s",
                (lines_parsed, run_id),
            )

    def fail_run(self, run_id: int, error_message: str, lines_parsed: Optional[int] = None) -> None:
        """Mark a run as failed and delete any alerts already saved for it, in one transaction:
        a partial result must never look like a complete one (docs/DESIGN.md, failure path)."""
        with self._cursor() as cursor:
            cursor.execute("DELETE FROM alerts WHERE analysis_run_id = %s", (run_id,))
            cursor.execute(
                """
                UPDATE analysis_runs
                SET status = 'failed', error_message = %s, lines_parsed = %s
                WHERE id = %s
                """,
                (error_message[:MAX_ERROR_MESSAGE_LENGTH], lines_parsed, run_id),
            )

    # ---------- reading ----------

    def find_completed_run(self, file_hash: str, settings: AnalysisSettings) -> Optional[int]:
        """The newest completed run of the same content with the same settings (decision D11)."""
        with self._cursor() as cursor:
            cursor.execute(
                """
                SELECT id FROM analysis_runs
                WHERE file_hash = %s
                  AND time_window_seconds = %s
                  AND brute_force_threshold = %s
                  AND scanning_threshold = %s
                  AND status = 'completed'
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (file_hash, settings.time_window_seconds,
                 settings.brute_force_threshold, settings.scanning_threshold),
            )
            row = cursor.fetchone()
            return row["id"] if row else None

    def get_run(self, run_id: int) -> Optional[Dict]:
        """One run with its number of alerts, or None if it does not exist."""
        with self._cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {RUN_COLUMNS}, COUNT(a.id) AS alert_count
                FROM analysis_runs r
                LEFT JOIN alerts a ON a.analysis_run_id = r.id
                WHERE r.id = %s
                GROUP BY r.id
                """,
                (run_id,),
            )
            row = cursor.fetchone()
            return self._run_from_row(row) if row else None

    def list_runs(self, created_from: Optional[datetime] = None,
                  created_to: Optional[datetime] = None) -> List[Dict]:
        """Runs created in [created_from, created_to) - by analysis date (decision D12) - newest first.

        Both limits are optional and must be time zone-aware; they are converted to UTC.
        """
        conditions, params = [], []
        if created_from is not None:
            conditions.append("r.created_at >= %s")
            params.append(_to_utc_naive(created_from))
        if created_to is not None:
            conditions.append("r.created_at < %s")
            params.append(_to_utc_naive(created_to))
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        with self._cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {RUN_COLUMNS}, COUNT(a.id) AS alert_count
                FROM analysis_runs r
                LEFT JOIN alerts a ON a.analysis_run_id = r.id
                {where}
                GROUP BY r.id
                ORDER BY r.created_at DESC, r.id DESC
                """,
                params,
            )
            return [self._run_from_row(row) for row in cursor.fetchall()]

    def get_alerts(self, run_id: int, threat_type: Optional[str] = None) -> List[Dict]:
        """Alerts of one run in time order, optionally only one threat type."""
        sql = """
            SELECT threat_type, ip_address, detected_at, details
            FROM alerts
            WHERE analysis_run_id = %s
        """
        params = [run_id]
        if threat_type is not None:
            sql += " AND threat_type = %s"
            params.append(threat_type)
        sql += " ORDER BY detected_at, id"

        with self._cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall()
        for row in rows:
            row["detected_at"] = row["detected_at"].replace(tzinfo=timezone.utc)
        return rows

    # ---------- helpers ----------

    @contextmanager
    def _cursor(self) -> Iterator:
        """Open a connection, give a cursor, commit on success, roll back on error, always close."""
        connection = mysql.connector.connect(
            host=self.config.host,
            port=self.config.port,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            time_zone="+00:00",
        )
        try:
            cursor = connection.cursor(dictionary=True)
            yield cursor
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _run_from_row(row: Dict) -> Dict:
        return {
            "id": row["id"],
            "filename": row["filename"],
            "file_hash": row["file_hash"],
            "created_at": row["created_at"].replace(tzinfo=timezone.utc),
            "status": row["status"],
            "error_message": row["error_message"],
            "lines_parsed": row["lines_parsed"],
            "settings": AnalysisSettings(
                time_window_seconds=row["time_window_seconds"],
                brute_force_threshold=row["brute_force_threshold"],
                scanning_threshold=row["scanning_threshold"],
            ),
            "alert_count": row["alert_count"],
        }


def _to_utc_naive(moment: datetime) -> datetime:
    """Aware datetime -> naive UTC datetime, the way it is stored in MySQL."""
    if moment.tzinfo is None:
        raise ValueError("Datetime must include a time zone")
    return moment.astimezone(timezone.utc).replace(tzinfo=None)
