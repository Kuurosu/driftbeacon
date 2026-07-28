"""Persistent storage for the DriftBeacon public web MVP."""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .models import ComparisonSummary, Finding, ScanResult
from .storage import StorageError

WEB_REPORT_FORMAT_VERSION = "web-report-v1"
WEB_SCHEMA_VERSION = 4

ScanStatus = Literal[
    "queued",
    "cloning",
    "analysing",
    "generating_report",
    "completed",
    "failed",
    "expired",
]

_SCAN_ID_RE = re.compile(r"^[a-f0-9]{12,64}$")
_IN_PROGRESS_STATUSES = ("queued", "cloning", "analysing", "generating_report")


@dataclass(slots=True)
class WebScanState:
    """Serializable status for one public web scan."""

    scan_id: str
    repository_url: str
    status: ScanStatus
    message: str
    progress: int
    created_at: datetime
    updated_at: datetime
    client_id: str = "anonymous"
    repository_owner: str = ""
    repository_name: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    expires_at: datetime | None = None
    error_code: str | None = None
    safe_error_message: str | None = None
    report_reference: str | None = None
    report_format_version: str = WEB_REPORT_FORMAT_VERSION
    repository: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    overall_health: int | None = None
    overall_grade: str | None = None
    production_health: int | None = None
    production_grade: str | None = None
    coverage_status: str | None = None
    baseline_type: str | None = None
    worker_id: str | None = None
    claimed_at: datetime | None = None
    heartbeat_at: datetime | None = None
    attempt_count: int = 0

    @property
    def done(self) -> bool:
        return self.status in {"completed", "failed", "expired"}

    @property
    def repository_label(self) -> str:
        if self.repository:
            return self.repository
        if self.repository_owner and self.repository_name:
            return f"{self.repository_owner}/{self.repository_name}"
        return self.repository_url

    def to_dict(self) -> dict[str, Any]:
        completed = self.status == "completed" and self.report_reference is not None
        return {
            "scan_id": self.scan_id,
            "repository_url": self.repository_url,
            "repository_owner": self.repository_owner,
            "repository_name": self.repository_name,
            "repository": self.repository_label,
            "status": self.status,
            "message": self.message,
            "progress": self.progress,
            "created_at": self.created_at.isoformat(),
            "started_at": _format_datetime(self.started_at),
            "completed_at": _format_datetime(self.completed_at),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": _format_datetime(self.expires_at),
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "overall_health": self.overall_health,
            "overall_grade": self.overall_grade,
            "production_health": self.production_health,
            "production_grade": self.production_grade,
            "coverage_status": self.coverage_status,
            "baseline_type": self.baseline_type,
            "report_url": f"/scans/{self.scan_id}" if completed else None,
            "markdown_url": f"/scans/{self.scan_id}/report.md" if completed else None,
            "json_url": f"/scans/{self.scan_id}/report.json" if completed else None,
            "comparison_url": (
                f"/scans/{self.scan_id}/comparison-summary.json" if completed else None
            ),
            "error_code": self.error_code,
            "error": self.safe_error_message,
        }


@dataclass(frozen=True, slots=True)
class SubmissionLimitResult:
    """Result of recording one beta submission attempt."""

    allowed: bool
    reason: str | None
    accepted_today: int
    rejected_today: int


@dataclass(frozen=True, slots=True)
class FeedbackRecord:
    """Local beta feedback submission."""

    feedback_id: str
    created_at: datetime
    scan_id: str | None
    source_hash: str
    helpfulness: str
    changed_priority: str
    private_monitoring_interest: bool
    comment: str
    email: str | None
    consent_to_contact: bool
    difficult_to_understand: str = ""


@dataclass(frozen=True, slots=True)
class StoredReport:
    """A stored report and its public download formats."""

    report_json: dict[str, Any]
    markdown: str

    @property
    def scan(self) -> ScanResult:
        raw = self.report_json.get("scan")
        if not isinstance(raw, dict):
            raise StorageError("stored report scan payload is invalid")
        return ScanResult.from_dict(raw)

    @property
    def comparison(self) -> ComparisonSummary:
        raw = self.report_json.get("comparison")
        if not isinstance(raw, dict):
            raise StorageError("stored report comparison payload is invalid")
        return comparison_from_dict(raw)


class SQLiteScanStore:
    """SQLite-backed scan metadata store."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.expanduser()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.database_path.exists() and self.database_path.is_symlink():
            raise StorageError("web database path must not be a symlink")
        if self.database_path.parent.is_symlink():
            raise StorageError("web database directory must not be a symlink")
        self._initialise()

    def create_scan(self, state: WebScanState) -> None:
        validate_scan_id(state.scan_id)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                  scan_id, repository_url, repository_owner, repository_name, status,
                  message, progress, created_at, started_at, completed_at, updated_at,
                  expires_at, error_code, safe_error_message, report_reference,
                  report_format_version, repository, branch, commit_sha, overall_health,
                  overall_grade, production_health, production_grade, coverage_status,
                  baseline_type, worker_id, claimed_at, heartbeat_at, attempt_count
                ) VALUES (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                  ?, ?, ?, ?
                )
                """,
                _state_values(state),
            )

    def claim_next_queued_scan(
        self,
        *,
        worker_id: str,
        now: datetime | None = None,
    ) -> WebScanState | None:
        timestamp = now or datetime.now(UTC)
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT scan_id
                    FROM scans
                    WHERE status = 'queued'
                    ORDER BY created_at ASC
                    LIMIT 1
                    """
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                scan_id = str(row["scan_id"])
                cursor = connection.execute(
                    """
                    UPDATE scans
                    SET status = 'cloning',
                        message = 'Cloning public GitHub repository.',
                        progress = 15,
                        started_at = COALESCE(started_at, ?),
                        updated_at = ?,
                        worker_id = ?,
                        claimed_at = ?,
                        heartbeat_at = ?,
                        attempt_count = attempt_count + 1
                    WHERE scan_id = ?
                      AND status = 'queued'
                    """,
                    (
                        _format_datetime(timestamp),
                        _format_datetime(timestamp),
                        worker_id,
                        _format_datetime(timestamp),
                        _format_datetime(timestamp),
                        scan_id,
                    ),
                )
                connection.execute("COMMIT")
            except sqlite3.Error:
                connection.execute("ROLLBACK")
                raise
        if not cursor.rowcount:
            return None
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> WebScanState | None:
        if not valid_scan_id(scan_id):
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return _state_from_row(row) if row is not None else None

    def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        message: str,
        progress: int,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        expires_at: datetime | None = None,
        error_code: str | None = None,
        safe_error_message: str | None = None,
    ) -> None:
        validate_scan_id(scan_id)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE scans
                SET status = ?,
                    message = ?,
                    progress = ?,
                    started_at = COALESCE(?, started_at),
                    completed_at = COALESCE(?, completed_at),
                    updated_at = ?,
                    expires_at = COALESCE(?, expires_at),
                    error_code = COALESCE(?, error_code),
                    safe_error_message = COALESCE(?, safe_error_message),
                    heartbeat_at = CASE
                      WHEN ? IN ('cloning', 'analysing', 'generating_report')
                      THEN ?
                      ELSE heartbeat_at
                    END
                WHERE scan_id = ?
                """,
                (
                    status,
                    message,
                    max(0, min(100, progress)),
                    _format_datetime(started_at),
                    _format_datetime(completed_at),
                    _format_datetime(now),
                    _format_datetime(expires_at),
                    error_code,
                    safe_error_message,
                    status,
                    _format_datetime(now),
                    scan_id,
                ),
            )

    def heartbeat(
        self,
        scan_id: str,
        *,
        worker_id: str,
        now: datetime | None = None,
    ) -> None:
        validate_scan_id(scan_id)
        timestamp = now or datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE scans
                SET heartbeat_at = ?,
                    updated_at = ?
                WHERE scan_id = ?
                  AND worker_id = ?
                  AND status IN ('cloning', 'analysing', 'generating_report')
                """,
                (
                    _format_datetime(timestamp),
                    _format_datetime(timestamp),
                    scan_id,
                    worker_id,
                ),
            )

    def save_report(
        self,
        scan_id: str,
        *,
        repository: str,
        branch: str,
        commit_sha: str,
        report_reference: str,
        report_format_version: str,
        completed_at: datetime,
        expires_at: datetime,
        overall_health: int | None,
        overall_grade: str | None,
        production_health: int | None,
        production_grade: str | None,
        coverage_status: str | None,
        baseline_type: str | None,
    ) -> None:
        validate_scan_id(scan_id)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE scans
                SET status = 'completed',
                    message = 'Report ready.',
                    progress = 100,
                    completed_at = ?,
                    updated_at = ?,
                    expires_at = ?,
                    report_reference = ?,
                    report_format_version = ?,
                    repository = ?,
                    branch = ?,
                    commit_sha = ?,
                    overall_health = ?,
                    overall_grade = ?,
                    production_health = ?,
                    production_grade = ?,
                    coverage_status = ?,
                    baseline_type = ?,
                    heartbeat_at = ?,
                    worker_id = worker_id
                WHERE scan_id = ?
                """,
                (
                    _format_datetime(completed_at),
                    _format_datetime(completed_at),
                    _format_datetime(expires_at),
                    report_reference,
                    report_format_version,
                    repository,
                    branch,
                    commit_sha,
                    overall_health,
                    overall_grade,
                    production_health,
                    production_grade,
                    coverage_status,
                    baseline_type,
                    _format_datetime(completed_at),
                    scan_id,
                ),
            )

    def list_expired_scans(self, now: datetime) -> list[WebScanState]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM scans
                WHERE expires_at IS NOT NULL
                  AND expires_at <= ?
                  AND status != 'expired'
                ORDER BY expires_at ASC
                """,
                (_format_datetime(now),),
            ).fetchall()
        return [_state_from_row(row) for row in rows]

    def mark_expired(self, scan_id: str, *, now: datetime | None = None) -> None:
        validate_scan_id(scan_id)
        timestamp = now or datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE scans
                SET status = 'expired',
                    message = 'This public report has expired.',
                    progress = 100,
                    updated_at = ?,
                    report_reference = NULL,
                    error_code = NULL,
                    safe_error_message = NULL
                WHERE scan_id = ?
                """,
                (_format_datetime(timestamp), scan_id),
            )

    def delete_scan(self, scan_id: str) -> None:
        validate_scan_id(scan_id)
        with self._connect() as connection:
            connection.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))

    def count_queued_scans(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM scans WHERE status = 'queued'"
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def count_running_scans(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM scans
                WHERE status IN ('cloning', 'analysing', 'generating_report')
                """
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def count_recent_failed_scans(self, *, since: datetime) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM scans
                WHERE status = 'failed'
                  AND completed_at >= ?
                """,
                (_format_datetime(since),),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def count_completed_scans_on(self, date_bucket: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM scans
                WHERE status = 'completed'
                  AND substr(completed_at, 1, 10) = ?
                """,
                (date_bucket,),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def count_failed_scans_on(self, date_bucket: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM scans
                WHERE status = 'failed'
                  AND substr(completed_at, 1, 10) = ?
                """,
                (date_bucket,),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def record_submission_attempt(
        self,
        *,
        source_hash: str,
        date_bucket: str,
        max_source_accepts: int,
        max_total_accepts: int,
    ) -> SubmissionLimitResult:
        """Atomically enforce and record single-instance beta daily scan limits."""

        now = _format_datetime(datetime.now(UTC))
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                source_row = connection.execute(
                    """
                    SELECT accepted_scan_count, rejected_scan_count
                    FROM beta_usage_counters
                    WHERE source_hash = ?
                      AND date_bucket = ?
                    """,
                    (source_hash, date_bucket),
                ).fetchone()
                source_accepted = (
                    int(source_row["accepted_scan_count"]) if source_row is not None else 0
                )
                total_row = connection.execute(
                    """
                    SELECT COALESCE(SUM(accepted_scan_count), 0) AS accepted,
                           COALESCE(SUM(rejected_scan_count), 0) AS rejected
                    FROM beta_usage_counters
                    WHERE date_bucket = ?
                    """,
                    (date_bucket,),
                ).fetchone()
                total_accepted = int(total_row["accepted"]) if total_row is not None else 0
                total_rejected = int(total_row["rejected"]) if total_row is not None else 0
                reason: str | None = None
                if source_accepted >= max_source_accepts:
                    reason = "source_daily_limit"
                elif total_accepted >= max_total_accepts:
                    reason = "global_daily_limit"
                allowed = reason is None
                accepted_increment = 1 if allowed else 0
                rejected_increment = 0 if allowed else 1
                connection.execute(
                    """
                    INSERT INTO beta_usage_counters (
                      source_hash, date_bucket, accepted_scan_count,
                      rejected_scan_count, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(source_hash, date_bucket) DO UPDATE SET
                      accepted_scan_count = accepted_scan_count + excluded.accepted_scan_count,
                      rejected_scan_count = rejected_scan_count + excluded.rejected_scan_count,
                      updated_at = excluded.updated_at
                    """,
                    (
                        source_hash,
                        date_bucket,
                        accepted_increment,
                        rejected_increment,
                        now,
                    ),
                )
                connection.execute("COMMIT")
            except sqlite3.Error:
                connection.execute("ROLLBACK")
                raise
        return SubmissionLimitResult(
            allowed=allowed,
            reason=reason,
            accepted_today=total_accepted + accepted_increment,
            rejected_today=total_rejected + rejected_increment,
        )

    def record_rejected_submission(self, *, source_hash: str, date_bucket: str) -> None:
        now = _format_datetime(datetime.now(UTC))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO beta_usage_counters (
                  source_hash, date_bucket, accepted_scan_count,
                  rejected_scan_count, updated_at
                ) VALUES (?, ?, 0, 1, ?)
                ON CONFLICT(source_hash, date_bucket) DO UPDATE SET
                  rejected_scan_count = rejected_scan_count + 1,
                  updated_at = excluded.updated_at
                """,
                (source_hash, date_bucket, now),
            )

    def daily_submission_counts(self, date_bucket: str) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(accepted_scan_count), 0) AS accepted,
                       COALESCE(SUM(rejected_scan_count), 0) AS rejected
                FROM beta_usage_counters
                WHERE date_bucket = ?
                """,
                (date_bucket,),
            ).fetchone()
        return {
            "accepted": int(row["accepted"]) if row is not None else 0,
            "rejected": int(row["rejected"]) if row is not None else 0,
        }

    def source_daily_usage(self, *, source_hash: str, date_bucket: str) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT accepted_scan_count, rejected_scan_count
                FROM beta_usage_counters
                WHERE source_hash = ?
                  AND date_bucket = ?
                """,
                (source_hash, date_bucket),
            ).fetchone()
        return {
            "accepted": int(row["accepted_scan_count"]) if row is not None else 0,
            "rejected": int(row["rejected_scan_count"]) if row is not None else 0,
        }

    def save_feedback(self, feedback: FeedbackRecord) -> None:
        validate_feedback_id(feedback.feedback_id)
        if feedback.scan_id is not None:
            validate_scan_id(feedback.scan_id)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO beta_feedback (
                  feedback_id, scan_id, created_at, source_hash, helpfulness,
                  changed_priority, private_monitoring_interest, comment,
                  difficult_to_understand, email, consent_to_contact
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feedback.feedback_id,
                    feedback.scan_id,
                    _format_datetime(feedback.created_at),
                    feedback.source_hash,
                    feedback.helpfulness,
                    feedback.changed_priority,
                    1 if feedback.private_monitoring_interest else 0,
                    feedback.comment,
                    feedback.difficult_to_understand,
                    feedback.email,
                    1 if feedback.consent_to_contact else 0,
                ),
            )

    def count_feedback_on(self, date_bucket: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM beta_feedback
                WHERE substr(created_at, 1, 10) = ?
                """,
                (date_bucket,),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def count_feedback_from_source_on(self, *, source_hash: str, date_bucket: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM beta_feedback
                WHERE source_hash = ?
                  AND substr(created_at, 1, 10) = ?
                """,
                (source_hash, date_bucket),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def count_private_monitoring_interest_on(self, date_bucket: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM beta_feedback
                WHERE private_monitoring_interest = 1
                  AND substr(created_at, 1, 10) = ?
                """,
                (date_bucket,),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def list_feedback(self, *, limit: int = 50) -> list[FeedbackRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM beta_feedback
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [_feedback_from_row(row) for row in rows]

    def record_analytics_event(
        self,
        event_name: str,
        *,
        source_hash: str | None = None,
        scan_id: str | None = None,
        properties: dict[str, Any] | None = None,
        created_at: datetime | None = None,
    ) -> None:
        if scan_id is not None:
            validate_scan_id(scan_id)
        timestamp = created_at or datetime.now(UTC)
        safe_properties = {
            str(key): value
            for key, value in (properties or {}).items()
            if isinstance(value, (str, int, float, bool)) or value is None
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO beta_analytics_events (
                  event_id, event_name, created_at, source_hash, scan_id, properties_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    event_name,
                    _format_datetime(timestamp),
                    source_hash,
                    scan_id,
                    json.dumps(safe_properties, sort_keys=True),
                ),
            )

    def event_counts_on(self, date_bucket: str) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_name, COUNT(*) AS count
                FROM beta_analytics_events
                WHERE substr(created_at, 1, 10) = ?
                GROUP BY event_name
                ORDER BY event_name
                """,
                (date_bucket,),
            ).fetchall()
        return {str(row["event_name"]): int(row["count"]) for row in rows}

    def worker_last_activity(self) -> datetime | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT MAX(COALESCE(heartbeat_at, updated_at)) AS activity
                FROM scans
                WHERE worker_id IS NOT NULL
                """
            ).fetchone()
        return _parse_datetime(row["activity"]) if row is not None else None

    def oldest_retained_report(self) -> datetime | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT MIN(completed_at) AS completed_at
                FROM scans
                WHERE status = 'completed'
                  AND report_reference IS NOT NULL
                """
            ).fetchone()
        return _parse_datetime(row["completed_at"]) if row is not None else None

    def recent_scans(self, *, limit: int = 20) -> list[WebScanState]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [_state_from_row(row) for row in rows]

    def failed_scans(self, *, limit: int = 20) -> list[WebScanState]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM scans
                WHERE status = 'failed'
                ORDER BY completed_at DESC, updated_at DESC
                LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [_state_from_row(row) for row in rows]

    def mark_interrupted_scans(
        self,
        *,
        now: datetime,
        expires_at: datetime,
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    message = 'The scan was interrupted before completion.',
                    progress = 100,
                    completed_at = COALESCE(completed_at, ?),
                    updated_at = ?,
                    expires_at = COALESCE(expires_at, ?),
                    error_code = 'scan_interrupted',
                    safe_error_message = 'The scan was interrupted before completion.'
                WHERE status IN ('cloning', 'analysing', 'generating_report')
                """,
                (
                    _format_datetime(now),
                    _format_datetime(now),
                    _format_datetime(expires_at),
                ),
            )
        return int(cursor.rowcount or 0)

    def mark_stale_claimed_scans_failed(
        self,
        *,
        stale_before: datetime,
        now: datetime,
        expires_at: datetime,
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    message = 'The scan was interrupted before completion.',
                    progress = 100,
                    completed_at = COALESCE(completed_at, ?),
                    updated_at = ?,
                    expires_at = COALESCE(expires_at, ?),
                    error_code = 'scan_interrupted',
                    safe_error_message = 'The scan was interrupted before completion.'
                WHERE status IN ('cloning', 'analysing', 'generating_report')
                  AND COALESCE(heartbeat_at, claimed_at, updated_at) <= ?
                """,
                (
                    _format_datetime(now),
                    _format_datetime(now),
                    _format_datetime(expires_at),
                    _format_datetime(stale_before),
                ),
            )
        return int(cursor.rowcount or 0)

    def check_ready(self) -> bool:
        with self._connect() as connection:
            version = connection.execute(
                "SELECT version FROM web_schema_version WHERE id = 1"
            ).fetchone()
            connection.execute("SELECT COUNT(*) FROM scans").fetchone()
        return version is not None and int(version["version"]) == WEB_SCHEMA_VERSION

    def _initialise(self) -> None:
        with self._connect(initialising=True) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS web_schema_version (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  version INTEGER NOT NULL
                )
                """
            )
            row = connection.execute(
                "SELECT version FROM web_schema_version WHERE id = 1"
            ).fetchone()
            if row is not None:
                version = int(row["version"])
                if version == 1:
                    self._migrate_v1_to_v2(connection)
                    version = 2
                if version == 2:
                    self._migrate_v2_to_v3(connection)
                    version = 3
                if version == 3:
                    self._migrate_v3_to_v4(connection)
                    version = 4
                if version == WEB_SCHEMA_VERSION:
                    connection.execute(
                        "UPDATE web_schema_version SET version = ? WHERE id = 1",
                        (WEB_SCHEMA_VERSION,),
                    )
                else:
                    raise StorageError(
                        f"unsupported DriftBeacon web database schema version: {version}"
                    )
            else:
                self._create_scans_table(connection)
                self._create_beta_tables(connection)
                connection.execute(
                    "INSERT INTO web_schema_version (id, version) VALUES (1, ?)",
                    (WEB_SCHEMA_VERSION,),
                )
            self._create_scans_table(connection)
            self._create_beta_tables(connection)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_expires_at_idx ON scans(expires_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_claim_idx ON scans(status, claimed_at)"
            )

    def _create_scans_table(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
              scan_id TEXT PRIMARY KEY,
              repository_url TEXT NOT NULL,
              repository_owner TEXT NOT NULL,
              repository_name TEXT NOT NULL,
              status TEXT NOT NULL,
              message TEXT NOT NULL,
              progress INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              started_at TEXT,
              completed_at TEXT,
              updated_at TEXT NOT NULL,
              expires_at TEXT,
              error_code TEXT,
              safe_error_message TEXT,
              report_reference TEXT,
              report_format_version TEXT NOT NULL,
              repository TEXT,
              branch TEXT,
              commit_sha TEXT,
              overall_health INTEGER,
              overall_grade TEXT,
              production_health INTEGER,
              production_grade TEXT,
              coverage_status TEXT,
              baseline_type TEXT,
              worker_id TEXT,
              claimed_at TEXT,
              heartbeat_at TEXT,
              attempt_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

    def _migrate_v1_to_v2(self, connection: sqlite3.Connection) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(scans)").fetchall()
        }
        additions = {
            "worker_id": "ALTER TABLE scans ADD COLUMN worker_id TEXT",
            "claimed_at": "ALTER TABLE scans ADD COLUMN claimed_at TEXT",
            "heartbeat_at": "ALTER TABLE scans ADD COLUMN heartbeat_at TEXT",
            "attempt_count": (
                "ALTER TABLE scans ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0"
            ),
        }
        for column, statement in additions.items():
            if column not in columns:
                connection.execute(statement)

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        self._create_beta_tables(connection)

    def _migrate_v3_to_v4(self, connection: sqlite3.Connection) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(beta_feedback)").fetchall()
        }
        if "difficult_to_understand" not in columns:
            connection.execute(
                "ALTER TABLE beta_feedback ADD COLUMN difficult_to_understand "
                "TEXT NOT NULL DEFAULT ''"
            )

    def _create_beta_tables(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS beta_usage_counters (
              source_hash TEXT NOT NULL,
              date_bucket TEXT NOT NULL,
              accepted_scan_count INTEGER NOT NULL DEFAULT 0,
              rejected_scan_count INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (source_hash, date_bucket)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS beta_feedback (
              feedback_id TEXT PRIMARY KEY,
              scan_id TEXT,
              created_at TEXT NOT NULL,
              source_hash TEXT NOT NULL,
              helpfulness TEXT NOT NULL,
              changed_priority TEXT NOT NULL,
              private_monitoring_interest INTEGER NOT NULL DEFAULT 0,
              comment TEXT NOT NULL,
              difficult_to_understand TEXT NOT NULL DEFAULT '',
              email TEXT,
              consent_to_contact INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS beta_analytics_events (
              event_id TEXT PRIMARY KEY,
              event_name TEXT NOT NULL,
              created_at TEXT NOT NULL,
              source_hash TEXT,
              scan_id TEXT,
              properties_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS beta_usage_date_idx
            ON beta_usage_counters(date_bucket)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS beta_feedback_created_idx
            ON beta_feedback(created_at)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS beta_events_created_idx
            ON beta_analytics_events(created_at)
            """
        )

    def _connect(self, *, initialising: bool = False) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=10,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise StorageError("could not open DriftBeacon web database") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        if not initialising:
            connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection


class FileReportStore:
    """Filesystem-backed report store keyed only by generated scan IDs."""

    def __init__(self, report_dir: Path) -> None:
        self.report_dir = report_dir.expanduser()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        if self.report_dir.exists() and self.report_dir.is_symlink():
            raise StorageError("web report directory must not be a symlink")

    def save(
        self,
        scan_id: str,
        *,
        report_json: dict[str, Any],
        markdown: str,
    ) -> str:
        validate_scan_id(scan_id)
        scan_dir = self._scan_dir(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        if scan_dir.is_symlink():
            raise StorageError("web report scan directory must not be a symlink")
        payload = {
            "report_format_version": WEB_REPORT_FORMAT_VERSION,
            **report_json,
        }
        self._write_json(scan_dir / "report.json", payload)
        self._write_text(scan_dir / "report.md", markdown)
        return scan_id

    def load(self, scan_id: str) -> StoredReport | None:
        if not valid_scan_id(scan_id):
            raise StorageError("invalid scan id")
        scan_dir = self._scan_dir(scan_id)
        json_path = scan_dir / "report.json"
        markdown_path = scan_dir / "report.md"
        if not json_path.exists() or not markdown_path.exists():
            return None
        if json_path.is_symlink() or markdown_path.is_symlink():
            raise StorageError("stored report files must not be symlinks")
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise StorageError("stored report JSON must be an object")
        return StoredReport(data, markdown_path.read_text(encoding="utf-8"))

    def delete(self, scan_id: str) -> None:
        if not valid_scan_id(scan_id):
            raise StorageError("invalid scan id")
        scan_dir = self._scan_dir(scan_id)
        if scan_dir.exists():
            if scan_dir.is_symlink():
                raise StorageError("refusing to delete symlinked report directory")
            shutil.rmtree(scan_dir)

    def check_writable(self) -> bool:
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.report_dir,
                prefix=".driftbeacon-health-",
                delete=False,
            ) as handle:
                handle.write("ok")
                temp_path = Path(handle.name)
            temp_path.unlink(missing_ok=True)
        except OSError:
            return False
        return True

    def _scan_dir(self, scan_id: str) -> Path:
        validate_scan_id(scan_id)
        return self.report_dir / scan_id

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        self._write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def _write_text(self, path: Path, text: str) -> None:
        if path.exists() and path.is_symlink():
            raise StorageError("refusing to write through symlinked report file")
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            delete=False,
        ) as handle:
            handle.write(text)
            temp_path = Path(handle.name)
        temp_path.replace(path)


def comparison_from_dict(data: dict[str, Any]) -> ComparisonSummary:
    """Rehydrate a comparison summary from stored web report JSON."""

    return ComparisonSummary(
        has_baseline=bool(data.get("has_baseline", False)),
        new_findings=_finding_list(data.get("new_findings")),
        recurring_findings=_finding_list(data.get("recurring_findings")),
        resolved_findings=_finding_list(data.get("resolved_findings")),
        severity_changes=_severity_changes(data.get("severity_changes")),
        health_score_change=_optional_int(data.get("health_score_change")),
        active_findings_change=_optional_int(data.get("active_findings_change")),
        score_formula_version=_optional_str(data.get("score_formula_version")),
        previous_score_formula_version=_optional_str(
            data.get("previous_score_formula_version")
        ),
        score_formula_changed=bool(data.get("score_formula_changed", False)),
    )


def valid_scan_id(scan_id: str) -> bool:
    return bool(_SCAN_ID_RE.fullmatch(scan_id))


def validate_scan_id(scan_id: str) -> None:
    if not valid_scan_id(scan_id):
        raise StorageError("invalid scan id")


def validate_feedback_id(feedback_id: str) -> None:
    if not valid_scan_id(feedback_id):
        raise StorageError("invalid feedback id")


def _state_values(state: WebScanState) -> tuple[Any, ...]:
    return (
        state.scan_id,
        state.repository_url,
        state.repository_owner,
        state.repository_name,
        state.status,
        state.message,
        state.progress,
        _format_datetime(state.created_at),
        _format_datetime(state.started_at),
        _format_datetime(state.completed_at),
        _format_datetime(state.updated_at),
        _format_datetime(state.expires_at),
        state.error_code,
        state.safe_error_message,
        state.report_reference,
        state.report_format_version,
        state.repository,
        state.branch,
        state.commit_sha,
        state.overall_health,
        state.overall_grade,
        state.production_health,
        state.production_grade,
        state.coverage_status,
        state.baseline_type,
        state.worker_id,
        _format_datetime(state.claimed_at),
        _format_datetime(state.heartbeat_at),
        state.attempt_count,
    )


def _state_from_row(row: sqlite3.Row) -> WebScanState:
    status = str(row["status"])
    if status not in set(_IN_PROGRESS_STATUSES) | {"completed", "failed", "expired"}:
        status = "failed"
    return WebScanState(
        scan_id=str(row["scan_id"]),
        repository_url=str(row["repository_url"]),
        repository_owner=str(row["repository_owner"]),
        repository_name=str(row["repository_name"]),
        status=status,  # type: ignore[arg-type]
        message=str(row["message"]),
        progress=int(row["progress"]),
        created_at=_parse_datetime(row["created_at"]) or datetime.now(UTC),
        started_at=_parse_datetime(row["started_at"]),
        completed_at=_parse_datetime(row["completed_at"]),
        updated_at=_parse_datetime(row["updated_at"]) or datetime.now(UTC),
        expires_at=_parse_datetime(row["expires_at"]),
        error_code=_optional_str(row["error_code"]),
        safe_error_message=_optional_str(row["safe_error_message"]),
        report_reference=_optional_str(row["report_reference"]),
        report_format_version=str(row["report_format_version"]),
        repository=_optional_str(row["repository"]),
        branch=_optional_str(row["branch"]),
        commit_sha=_optional_str(row["commit_sha"]),
        overall_health=_optional_int(row["overall_health"]),
        overall_grade=_optional_str(row["overall_grade"]),
        production_health=_optional_int(row["production_health"]),
        production_grade=_optional_str(row["production_grade"]),
        coverage_status=_optional_str(row["coverage_status"]),
        baseline_type=_optional_str(row["baseline_type"]),
        worker_id=_optional_str(row["worker_id"]),
        claimed_at=_parse_datetime(row["claimed_at"]),
        heartbeat_at=_parse_datetime(row["heartbeat_at"]),
        attempt_count=_optional_int(row["attempt_count"]) or 0,
    )


def _feedback_from_row(row: sqlite3.Row) -> FeedbackRecord:
    return FeedbackRecord(
        feedback_id=str(row["feedback_id"]),
        scan_id=_optional_str(row["scan_id"]),
        created_at=_parse_datetime(row["created_at"]) or datetime.now(UTC),
        source_hash=str(row["source_hash"]),
        helpfulness=str(row["helpfulness"]),
        changed_priority=str(row["changed_priority"]),
        private_monitoring_interest=bool(row["private_monitoring_interest"]),
        comment=str(row["comment"]),
        email=_optional_str(row["email"]),
        consent_to_contact=bool(row["consent_to_contact"]),
        difficult_to_understand=str(row["difficult_to_understand"]),
    )


def _finding_list(raw: object) -> list[Finding]:
    if not isinstance(raw, list):
        return []
    return [Finding.from_dict(item) for item in raw if isinstance(item, dict)]


def _severity_changes(raw: object) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    changes: list[dict[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            changes.append({str(key): str(value) for key, value in item.items()})
    return changes


def _format_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
