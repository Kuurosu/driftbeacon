"""Persistent storage for the DriftBeacon public web MVP."""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .models import ComparisonSummary, Finding, ScanResult
from .storage import StorageError

WEB_REPORT_FORMAT_VERSION = "web-report-v1"
WEB_SCHEMA_VERSION = 1

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
                  baseline_type
                ) VALUES (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                _state_values(state),
            )

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
                    safe_error_message = COALESCE(?, safe_error_message)
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
                    scan_id,
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
                    baseline_type = ?
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
                WHERE status IN ('queued', 'cloning', 'analysing', 'generating_report')
                """,
                (
                    _format_datetime(now),
                    _format_datetime(now),
                    _format_datetime(expires_at),
                ),
            )
        return int(cursor.rowcount or 0)

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
                if version != WEB_SCHEMA_VERSION:
                    raise StorageError(
                        f"unsupported DriftBeacon web database schema version: {version}"
                    )
            else:
                connection.execute(
                    "INSERT INTO web_schema_version (id, version) VALUES (1, ?)",
                    (WEB_SCHEMA_VERSION,),
                )
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
                  baseline_type TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_expires_at_idx ON scans(expires_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status)"
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
