"""Public web scan MVP for DriftBeacon."""

# ruff: noqa: E501

from __future__ import annotations

import html
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse
from wsgiref.simple_server import make_server
from wsgiref.types import StartResponse, WSGIEnvironment

from .analysis import clone_repository, detect_supported_infrastructure_files
from .comparison import compare_scans
from .config import load_config
from .models import ComparisonSummary, Finding, ScanResult
from .prioritise import prioritise_findings
from .redaction import redact_secrets
from .reporting import generate_report, prioritised_finding_details
from .scanners.base import safe_walk
from .storage import StorageError
from .web_storage import (
    WEB_REPORT_FORMAT_VERSION,
    FileReportStore,
    ScanStatus,
    SQLiteScanStore,
    StoredReport,
    WebScanState,
    valid_scan_id,
)

WebErrorCode = Literal[
    "invalid_repository_url",
    "repository_not_found",
    "repository_private",
    "repository_too_large",
    "repository_file_limit_exceeded",
    "clone_timeout",
    "scan_timeout",
    "scanner_failure",
    "capacity_reached",
    "report_generation_failed",
    "scan_interrupted",
]
AnalyticsProperties = dict[str, str | int | float | bool | None]

_GITHUB_OWNER_REPO = re.compile(r"^[A-Za-z0-9_.-]+$")
_LOGGER = logging.getLogger("driftbeacon.web")


@dataclass(frozen=True, slots=True)
class WebConfig:
    """Configuration for the public web scan MVP."""

    output_dir: Path = Path(".driftbeacon")
    database_path: Path = Path(".driftbeacon/web.sqlite3")
    report_dir: Path = Path(".driftbeacon/reports")
    working_dir: Path = Path(".driftbeacon/work")
    max_concurrent_scans: int = 2
    max_queued_scans: int = 10
    max_scan_seconds: int = 300
    scanner_timeout_seconds: int = 300
    clone_timeout_seconds: int = 120
    retention_days: int = 7
    scans_per_hour: int = 10
    max_repository_files: int = 8_000
    max_repository_bytes: int = 150 * 1024 * 1024
    top_findings: int = 3

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> WebConfig:
        source = env or dict(os.environ)
        output_dir = Path(source.get("DRIFTBEACON_WEB_OUTPUT_DIR", ".driftbeacon"))
        max_scan_seconds = _env_int(source, "DRIFTBEACON_WEB_MAX_SCAN_SECONDS", 300)
        return cls(
            output_dir=output_dir,
            database_path=Path(source.get("DRIFTBEACON_WEB_DATABASE", str(output_dir / "web.sqlite3"))),
            report_dir=Path(source.get("DRIFTBEACON_WEB_REPORT_DIR", str(output_dir / "reports"))),
            working_dir=Path(source.get("DRIFTBEACON_WEB_WORK_DIR", str(output_dir / "work"))),
            max_concurrent_scans=_env_int(source, "DRIFTBEACON_WEB_MAX_CONCURRENT_SCANS", 2),
            max_queued_scans=_env_int(source, "DRIFTBEACON_WEB_MAX_QUEUED_SCANS", 10),
            max_scan_seconds=max_scan_seconds,
            scanner_timeout_seconds=_env_int(
                source,
                "DRIFTBEACON_WEB_SCANNER_TIMEOUT",
                max_scan_seconds,
            ),
            clone_timeout_seconds=_env_int(source, "DRIFTBEACON_WEB_CLONE_TIMEOUT", 120),
            retention_days=_env_int(source, "DRIFTBEACON_WEB_RETENTION_DAYS", 7),
            scans_per_hour=_env_int(source, "DRIFTBEACON_WEB_SCANS_PER_HOUR", 10),
            max_repository_files=_env_int(source, "DRIFTBEACON_WEB_MAX_REPOSITORY_FILES", 8_000),
            max_repository_bytes=_env_int(
                source,
                "DRIFTBEACON_WEB_MAX_REPOSITORY_BYTES",
                150 * 1024 * 1024,
            ),
            top_findings=_env_int(source, "DRIFTBEACON_WEB_TOP_FINDINGS", 3),
        ).validate()

    def validate(self) -> WebConfig:
        if self.max_concurrent_scans < 1:
            raise ValueError("web max_concurrent_scans must be at least 1")
        if self.max_queued_scans < 0:
            raise ValueError("web max_queued_scans must be at least 0")
        if (
            self.max_scan_seconds < 1
            or self.scanner_timeout_seconds < 1
            or self.clone_timeout_seconds < 1
        ):
            raise ValueError("web timeouts must be at least 1 second")
        if self.retention_days < 1:
            raise ValueError("web retention_days must be at least 1")
        if self.scans_per_hour < 1:
            raise ValueError("web scans_per_hour must be at least 1")
        if self.max_repository_files < 1:
            raise ValueError("web max_repository_files must be at least 1")
        if self.max_repository_bytes < 1:
            raise ValueError("web max_repository_bytes must be at least 1")
        if self.top_findings < 1:
            raise ValueError("web top_findings must be at least 1")
        if self.output_dir.exists() and self.output_dir.is_symlink():
            raise ValueError("web output_dir must not be a symlink")
        for path_name, path in (
            ("database_path", self.database_path),
            ("report_dir", self.report_dir),
            ("working_dir", self.working_dir),
        ):
            if path.exists() and path.is_symlink():
                raise ValueError(f"web {path_name} must not be a symlink")
        return self


@dataclass(frozen=True, slots=True)
class WebScanArtifacts:
    """Files and metadata produced by one web scan."""

    repository: str
    branch: str
    commit_sha: str
    report_reference: str
    report_format_version: str = WEB_REPORT_FORMAT_VERSION
    overall_health: int | None = None
    overall_grade: str | None = None
    production_health: int | None = None
    production_grade: str | None = None
    coverage_status: str | None = None
    baseline_type: str | None = None


class NoOpAnalytics:
    """No-op analytics boundary for the public MVP."""

    def record(self, event: str, properties: AnalyticsProperties) -> None:
        _ = event, properties


class PublicGitHubRepositoryProvider:
    """Validate and clone public GitHub repositories."""

    def normalise_url(self, repository_url: str) -> str:
        return normalise_public_github_url(repository_url)

    def clone(self, repository_url: str, clone_path: Path, *, timeout_seconds: int) -> None:
        clone_repository(repository_url, clone_path, timeout_seconds=timeout_seconds)


class WebSubmissionError(ValueError):
    """Safe rejection raised before a scan is persisted."""

    def __init__(
        self,
        error_code: WebErrorCode,
        safe_message: str,
        *,
        http_status: str = "400 Bad Request",
    ) -> None:
        super().__init__(safe_message)
        self.error_code = error_code
        self.safe_message = safe_message
        self.http_status = http_status


class WebScanFailure(RuntimeError):
    """Safe terminal failure for a persisted scan."""

    def __init__(
        self,
        error_code: WebErrorCode,
        safe_message: str,
        *,
        detail: str | None = None,
    ) -> None:
        super().__init__(safe_message)
        self.error_code = error_code
        self.safe_message = safe_message
        self.detail = detail


class ScanDeadline:
    """Wall-clock timeout boundary for one web scan."""

    def __init__(self, max_seconds: int) -> None:
        self.deadline_monotonic = time.monotonic() + max_seconds

    def remaining_seconds(self) -> int:
        remaining = int(self.deadline_monotonic - time.monotonic())
        if remaining < 1:
            raise WebScanFailure(
                "scan_timeout",
                "This scan exceeded the public demo time limit.",
            )
        return remaining

    def ensure_remaining(self) -> None:
        self.remaining_seconds()


ScanRunner = Callable[
    [
        str,
        str,
        Path,
        WebConfig,
        PublicGitHubRepositoryProvider,
        FileReportStore,
        Callable[[ScanStatus, str, int], None],
    ],
    WebScanArtifacts,
]


class WebScanService:
    """Background scan coordinator used by the WSGI routes."""

    def __init__(
        self,
        config: WebConfig | None = None,
        *,
        analytics: NoOpAnalytics | None = None,
        provider: PublicGitHubRepositoryProvider | None = None,
        runner: ScanRunner | None = None,
        synchronous: bool = False,
        recover_interrupted: bool = True,
        cleanup_on_start: bool = True,
    ) -> None:
        self.config = (config or WebConfig.from_environment()).validate()
        self.output_dir = self.config.output_dir.expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.output_dir.is_symlink():
            raise ValueError("web output_dir must not be a symlink")
        self.working_dir = self.config.working_dir.expanduser().resolve()
        self.working_dir.mkdir(parents=True, exist_ok=True)
        if self.working_dir.is_symlink():
            raise ValueError("web working_dir must not be a symlink")
        self.store = SQLiteScanStore(self.config.database_path)
        self.report_store = FileReportStore(self.config.report_dir)
        self.analytics = analytics or NoOpAnalytics()
        self.provider = provider or PublicGitHubRepositoryProvider()
        self.runner = runner or run_public_repository_scan
        self.synchronous = synchronous
        self._submissions: dict[str, list[float]] = defaultdict(list)
        self._semaphore = threading.BoundedSemaphore(self.config.max_concurrent_scans)
        if recover_interrupted:
            self.mark_abandoned_scans_interrupted()
        if cleanup_on_start:
            self.cleanup_expired_scans()

    def submit(self, repository_url: str, *, client_id: str = "anonymous") -> WebScanState:
        try:
            normalised_url = self.provider.normalise_url(repository_url)
        except ValueError as exc:
            raise WebSubmissionError("invalid_repository_url", str(exc)) from exc
        self._enforce_rate_limit(client_id)
        self.cleanup_expired_scans()
        if self.store.count_queued_scans() >= self.config.max_queued_scans:
            self.analytics.record("scan_rejected", {"reason": "capacity_reached"})
            raise WebSubmissionError(
                "capacity_reached",
                "The public demo is currently at capacity. Please try again later.",
                http_status="503 Service Unavailable",
            )
        owner, repo = _repository_parts(normalised_url)
        scan_id = uuid.uuid4().hex
        now = datetime.now(UTC)
        state = WebScanState(
            scan_id=scan_id,
            repository_url=normalised_url,
            repository_owner=owner,
            repository_name=repo,
            status="queued",
            message="Queued for analysis.",
            progress=5,
            created_at=now,
            updated_at=now,
            client_id=client_id,
        )
        self.store.create_scan(state)
        _log_scan(scan_id, normalised_url, "queued", "created")
        self.analytics.record("scan_submitted", {"scan_id": scan_id})
        if self.synchronous:
            self._run(scan_id, normalised_url)
        else:
            thread = threading.Thread(
                target=self._run,
                args=(scan_id, normalised_url),
                name=f"driftbeacon-scan-{scan_id}",
                daemon=True,
            )
            thread.start()
        return self.get(scan_id) or state

    def get(self, scan_id: str) -> WebScanState | None:
        if not valid_scan_id(scan_id):
            return None
        return self.store.get_scan(scan_id)

    def cleanup_old_scans(self) -> None:
        self.cleanup_expired_scans()

    def cleanup_expired_scans(self) -> dict[str, int]:
        now = datetime.now(UTC)
        cleaned_reports = 0
        expired_records = 0
        failures = 0
        for state in self.store.list_expired_scans(now):
            try:
                with suppress(StorageError, FileNotFoundError):
                    self.report_store.delete(state.scan_id)
                    cleaned_reports += 1
                self.store.mark_expired(state.scan_id, now=now)
                expired_records += 1
                _log_scan(state.scan_id, state.repository_url, "expired", "cleanup")
            except Exception as exc:
                failures += 1
                _LOGGER.warning(
                    "scan_id=%s repository=%s cleanup=failed error=%s",
                    state.scan_id,
                    state.repository_url,
                    redact_secrets(str(exc)),
                )
        cleaned_workdirs = self._cleanup_abandoned_working_dirs(now)
        return {
            "expired_records": expired_records,
            "cleaned_reports": cleaned_reports,
            "cleaned_workdirs": cleaned_workdirs,
            "failures": failures,
        }

    def mark_abandoned_scans_interrupted(self) -> int:
        now = datetime.now(UTC)
        interrupted = self.store.mark_interrupted_scans(
            now=now,
            expires_at=self._expiry_from(now),
        )
        if interrupted:
            _LOGGER.info("interrupted_scans=%s status=startup_recovered", interrupted)
        return interrupted

    def load_report(self, scan_id: str) -> StoredReport | None:
        state = self.get(scan_id)
        if state is None or state.status != "completed" or state.report_reference is None:
            return None
        return self.report_store.load(scan_id)

    def _run(self, scan_id: str, repository_url: str) -> None:
        started_at = datetime.now(UTC)
        with self._semaphore:
            self._update(
                scan_id,
                "cloning",
                "Cloning public GitHub repository.",
                15,
                started_at=started_at,
            )
            _log_scan(scan_id, repository_url, "started", "worker")
            try:
                self.analytics.record("scan_started", {"scan_id": scan_id})
                artifacts = self.runner(
                    scan_id,
                    repository_url,
                    self.working_dir / scan_id,
                    self.config,
                    self.provider,
                    self.report_store,
                    lambda status, message, progress: self._update(
                        scan_id,
                        status,
                        message,
                        progress,
                    ),
                )
            except WebScanFailure as exc:
                completed_at = datetime.now(UTC)
                self._update(
                    scan_id,
                    "failed",
                    exc.safe_message,
                    100,
                    completed_at=completed_at,
                    expires_at=self._expiry_from(completed_at),
                    error_code=exc.error_code,
                    safe_error_message=exc.safe_message,
                )
                self.analytics.record("scan_failed", {"scan_id": scan_id})
                _log_scan(scan_id, repository_url, "failed", exc.error_code)
                if exc.detail:
                    _LOGGER.info(
                        "scan_id=%s repository=%s detail=%s",
                        scan_id,
                        repository_url,
                        redact_secrets(exc.detail),
                    )
                self._delete_workdir(scan_id)
                return
            except Exception as exc:
                completed_at = datetime.now(UTC)
                safe = "Scan failed. Please try again with a smaller public repository."
                self._update(
                    scan_id,
                    "failed",
                    safe,
                    100,
                    completed_at=completed_at,
                    expires_at=self._expiry_from(completed_at),
                    error_code="scanner_failure",
                    safe_error_message=safe,
                )
                self.analytics.record("scan_failed", {"scan_id": scan_id})
                _LOGGER.exception(
                    "scan_id=%s repository=%s status=failed code=scanner_failure detail=%s",
                    scan_id,
                    repository_url,
                    redact_secrets(str(exc)),
                )
                self._delete_workdir(scan_id)
                return
            completed_at = datetime.now(UTC)
            self.store.save_report(
                scan_id,
                repository=artifacts.repository,
                branch=artifacts.branch,
                commit_sha=artifacts.commit_sha,
                report_reference=artifacts.report_reference,
                report_format_version=artifacts.report_format_version,
                completed_at=completed_at,
                expires_at=self._expiry_from(completed_at),
                overall_health=artifacts.overall_health,
                overall_grade=artifacts.overall_grade,
                production_health=artifacts.production_health,
                production_grade=artifacts.production_grade,
                coverage_status=artifacts.coverage_status,
                baseline_type=artifacts.baseline_type,
            )
            self.analytics.record("scan_completed", {"scan_id": scan_id})
            _log_scan(scan_id, repository_url, "completed", "report_ready")
            self._delete_workdir(scan_id)

    def _update(
        self,
        scan_id: str,
        status: ScanStatus,
        message: str,
        progress: int,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        expires_at: datetime | None = None,
        error_code: WebErrorCode | None = None,
        safe_error_message: str | None = None,
    ) -> None:
        self.store.update_status(
            scan_id,
            status,
            message,
            progress,
            started_at=started_at,
            completed_at=completed_at,
            expires_at=expires_at,
            error_code=error_code,
            safe_error_message=safe_error_message,
        )

    def _enforce_rate_limit(self, client_id: str) -> None:
        now = time.time()
        window_start = now - 3600
        submissions = [
            timestamp for timestamp in self._submissions[client_id] if timestamp >= window_start
        ]
        if len(submissions) >= self.config.scans_per_hour:
            self.analytics.record("scan_rejected", {"reason": "rate_limit"})
            raise WebSubmissionError(
                "capacity_reached",
                "Too many scans from this client. Please try again later.",
                http_status="429 Too Many Requests",
            )
        submissions.append(now)
        self._submissions[client_id] = submissions

    def _expiry_from(self, value: datetime) -> datetime:
        return value + timedelta(days=self.config.retention_days)

    def _cleanup_abandoned_working_dirs(self, now: datetime) -> int:
        cutoff = now.timestamp() - max(self.config.max_scan_seconds, 60)
        cleaned = 0
        for path in self.working_dir.iterdir() if self.working_dir.exists() else []:
            try:
                if not path.is_dir() or path.is_symlink() or path.stat().st_mtime >= cutoff:
                    continue
                shutil.rmtree(path)
                cleaned += 1
            except OSError as exc:
                _LOGGER.warning(
                    "working_dir=%s cleanup=failed error=%s",
                    path.name,
                    redact_secrets(str(exc)),
                )
        return cleaned

    def _delete_workdir(self, scan_id: str) -> None:
        if not valid_scan_id(scan_id):
            return
        path = self.working_dir / scan_id
        if path.exists() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)


class DriftBeaconWebApp:
    """Small WSGI application for the public web MVP."""

    def __init__(self, service: WebScanService | None = None) -> None:
        self.service = service or WebScanService()

    def __call__(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        try:
            if method == "GET" and path == "/":
                self.service.analytics.record("landing_page_viewed", {})
                return self._html(start_response, render_home_page())
            if method == "POST" and path == "/scans":
                return self._submit(environ, start_response)
            if method == "GET" and path.startswith("/api/scans/"):
                return self._api_scan(path, start_response)
            if method == "GET" and path.startswith("/scans/"):
                return self._scan_page(path, start_response)
        except WebSubmissionError as exc:
            return self._html(
                start_response,
                render_home_page(error=exc.safe_message),
                status=exc.http_status,
            )
        except ValueError as exc:
            return self._html(start_response, render_home_page(error=str(exc)), status="400 Bad Request")
        except StorageError:
            _LOGGER.exception("web_storage_error=true path=%s", path)
            return self._html(
                start_response,
                render_error_page("DriftBeacon could not load this report."),
                status="500 Internal Server Error",
            )
        return self._html(start_response, render_not_found_page(), status="404 Not Found")

    def _submit(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        if length > 4096:
            raise ValueError("Submission is too large.")
        body = environ["wsgi.input"].read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        repository_url = (form.get("repository_url") or [""])[0].strip()
        client_id = str(environ.get("REMOTE_ADDR") or "anonymous")
        try:
            state = self.service.submit(repository_url, client_id=client_id)
        except WebSubmissionError as exc:
            self.service.analytics.record("scan_rejected", {"reason": exc.error_code})
            return self._html(
                start_response,
                render_home_page(error=exc.safe_message, repository_url=repository_url),
                status=exc.http_status,
            )
        except ValueError as exc:
            self.service.analytics.record("scan_rejected", {"reason": "validation"})
            return self._html(
                start_response,
                render_home_page(error=str(exc), repository_url=repository_url),
                status="400 Bad Request",
            )
        start_response("303 See Other", [("Location", f"/scans/{state.scan_id}")])
        return [b""]

    def _api_scan(self, path: str, start_response: StartResponse) -> Iterable[bytes]:
        scan_id = path.removeprefix("/api/scans/").strip("/")
        state = self.service.get(scan_id)
        if state is None:
            start_response("404 Not Found", [("Content-Type", "application/json")])
            return [b'{"error":"scan not found"}']
        if state.status == "expired":
            start_response("410 Gone", [("Content-Type", "application/json")])
            return [b'{"error":"scan expired"}']
        payload = json.dumps(state.to_dict(), sort_keys=True).encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
            ],
        )
        return [payload]

    def _scan_page(self, path: str, start_response: StartResponse) -> Iterable[bytes]:
        parts = [part for part in path.split("/") if part]
        if len(parts) < 2:
            return self._html(start_response, render_not_found_page(), status="404 Not Found")
        scan_id = parts[1]
        state = self.service.get(scan_id)
        if state is None:
            return self._html(start_response, render_not_found_page(), status="404 Not Found")
        if state.status == "expired":
            return self._html(
                start_response,
                render_expired_report_page(state),
                status="410 Gone",
            )
        if len(parts) == 3:
            return self._artifact(parts[2], state, start_response)
        if state.status != "completed":
            return self._html(start_response, render_progress_page(state))
        stored = self.service.load_report(scan_id)
        if stored is not None:
            self.service.analytics.record("report_viewed", {"scan_id": scan_id})
            return self._html(
                start_response,
                render_repository_report_page(
                    stored.scan,
                    stored.comparison,
                    state=state,
                ),
            )
        return self._html(
            start_response,
            render_error_page("The scan completed, but the web report could not be loaded."),
            status="500 Internal Server Error",
        )

    def _artifact(
        self,
        artifact: str,
        state: WebScanState,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        if state.status == "expired":
            start_response("410 Gone", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"report expired"]
        if state.status != "completed":
            start_response("409 Conflict", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"report is not ready"]
        stored = self.service.load_report(state.scan_id)
        if stored is None:
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"artifact not found"]
        self.service.analytics.record(
            "report_downloaded",
            {"scan_id": state.scan_id, "artifact": artifact},
        )
        if artifact == "report.md":
            return self._download(
                start_response,
                stored.markdown,
                "text/markdown; charset=utf-8",
                f"driftbeacon-{state.scan_id}-report.md",
            )
        if artifact == "report.json":
            return self._download(
                start_response,
                json.dumps(stored.report_json, indent=2, sort_keys=True) + "\n",
                "application/json; charset=utf-8",
                f"driftbeacon-{state.scan_id}-report.json",
            )
        if artifact == "current-scan.json":
            return self._download(
                start_response,
                json.dumps(stored.report_json.get("scan", {}), indent=2, sort_keys=True)
                + "\n",
                "application/json; charset=utf-8",
                f"driftbeacon-{state.scan_id}-scan.json",
            )
        if artifact == "comparison-summary.json":
            return self._download(
                start_response,
                json.dumps(
                    stored.report_json.get("comparison", {}),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                "application/json; charset=utf-8",
                f"driftbeacon-{state.scan_id}-comparison.json",
            )
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"artifact not found"]

    def _html(
        self,
        start_response: StartResponse,
        body: str,
        *,
        status: str = "200 OK",
    ) -> Iterable[bytes]:
        payload = body.encode("utf-8")
        start_response(
            status,
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(payload))),
                ("Cache-Control", "no-store"),
            ],
        )
        return [payload]

    def _download(
        self,
        start_response: StartResponse,
        text: str,
        content_type: str,
        filename: str,
    ) -> Iterable[bytes]:
        payload = text.encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(payload))),
                ("Content-Disposition", f'attachment; filename="{filename}"'),
                ("Cache-Control", "no-store"),
            ],
        )
        return [payload]


def create_app(service: WebScanService | None = None) -> DriftBeaconWebApp:
    """Create the public web MVP application."""

    return DriftBeaconWebApp(service)


def run_web_server(host: str, port: int, config: WebConfig | None = None) -> None:
    """Run the local public web scan MVP."""

    app = create_app(WebScanService(config))
    with make_server(host, port, app) as server:
        print(f"DriftBeacon web listening on http://{host}:{port}")
        server.serve_forever()


def cleanup_web_storage(config: WebConfig | None = None) -> dict[str, int]:
    """Expire old public web reports and abandoned web working directories."""

    service = WebScanService(
        config,
        recover_interrupted=False,
        cleanup_on_start=False,
    )
    return service.cleanup_expired_scans()


def run_public_repository_scan(
    scan_id: str,
    repository_url: str,
    output_dir: Path,
    config: WebConfig,
    provider: PublicGitHubRepositoryProvider,
    report_store: FileReportStore,
    progress: Callable[[ScanStatus, str, int], None],
) -> WebScanArtifacts:
    """Clone a public repository and run the shared DriftBeacon analysis engine."""

    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise ValueError("scan output directory must not be a symlink")
    deadline = ScanDeadline(config.max_scan_seconds)
    temp_root = Path(tempfile.mkdtemp(prefix="driftbeacon-web-"))
    clone_path = temp_root / "repository"
    try:
        progress("cloning", "Cloning public GitHub repository.", 20)
        try:
            provider.clone(
                repository_url,
                clone_path,
                timeout_seconds=min(
                    config.clone_timeout_seconds,
                    deadline.remaining_seconds(),
                ),
            )
        except ValueError as exc:
            raise _clone_failure(exc) from exc
        deadline.ensure_remaining()
        _enforce_repository_limits(clone_path, config)
        supported = detect_supported_infrastructure_files(clone_path)
        if not supported:
            progress("analysing", "No supported infrastructure files found; recording coverage.", 45)
        else:
            progress("analysing", f"Detected {len(supported)} supported files. Running scanners.", 45)
        scan_config = load_config(
            repository_path=clone_path,
            output_dir=output_dir,
            no_slack=True,
        )
        try:
            scan, _executions = run_scan_with_engine(
                scan_config,
                timeout_seconds=min(
                    config.scanner_timeout_seconds,
                    deadline.remaining_seconds(),
                ),
                deadline_monotonic=deadline.deadline_monotonic,
            )
        except TimeoutError as exc:
            raise WebScanFailure(
                "scan_timeout",
                "This scan exceeded the public demo time limit.",
            ) from exc
        deadline.ensure_remaining()
        comparison = compare_scans(scan, None)
        top_items = prioritise_findings(
            scan.findings,
            limit=config.top_findings,
            production_patterns=scan_config.production_patterns,
        )
        progress("generating_report", "Rendering report.", 85)
        markdown_report = generate_report(
            scan,
            comparison,
            top_items=top_items,
            production_patterns=scan_config.production_patterns,
            top_limit=config.top_findings,
        )
        deadline.ensure_remaining()
        report_reference = report_store.save(
            scan_id,
            report_json={
                "generated_at": datetime.now(UTC).isoformat(),
                "scan": scan.to_dict(),
                "comparison": comparison.to_dict(),
            },
            markdown=markdown_report,
        )
        _write_state_file(
            output_dir,
            {
                "scan_id": scan_id,
                "repository_url": repository_url,
                "repository": scan.repository,
                "branch": scan.branch,
                "commit_sha": scan.commit_sha,
                "report_reference": report_reference,
                "completed_at": datetime.now(UTC).isoformat(),
            },
        )
        return WebScanArtifacts(
            repository=scan.repository,
            branch=scan.branch,
            commit_sha=scan.commit_sha,
            report_reference=report_reference,
            overall_health=scan.health_score,
            overall_grade=_grade_for_score(scan.health_score),
            production_health=_optional_int(scan.summary.get("production_health_score")),
            production_grade=_optional_str(scan.summary.get("production_grade")),
            coverage_status=_optional_str(
                scan.summary.get("production_coverage_state")
                or scan.summary.get("coverage_state")
            ),
            baseline_type=_baseline_text(comparison),
        )
    except WebScanFailure:
        raise
    except StorageError as exc:
        raise WebScanFailure(
            "report_generation_failed",
            "The scan completed, but DriftBeacon could not store the report.",
            detail=str(exc),
        ) from exc
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def run_scan_with_engine(
    scan_config: Any,
    *,
    timeout_seconds: int,
    deadline_monotonic: float | None = None,
) -> tuple[ScanResult, list[Any]]:
    """Isolated import boundary for tests and future worker implementations."""

    from .scan import run_scan

    return run_scan(
        scan_config,
        timeout_seconds=timeout_seconds,
        deadline_monotonic=deadline_monotonic,
    )


def normalise_public_github_url(repository_url: str) -> str:
    """Validate and normalize an HTTPS public GitHub repository URL."""

    raw = repository_url.strip()
    if not raw:
        raise ValueError("Paste a public GitHub repository URL.")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError("Only HTTPS GitHub repository URLs are supported in the public MVP.")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Repository URLs must not include credentials, query strings or fragments.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("Use a repository URL such as https://github.com/owner/repo.")
    owner, repo = parts
    repo = repo.removesuffix(".git")
    if not owner or not repo or not _GITHUB_OWNER_REPO.match(owner) or not _GITHUB_OWNER_REPO.match(repo):
        raise ValueError("GitHub owner and repository names contain unsupported characters.")
    return f"https://github.com/{owner}/{repo}.git"


def render_home_page(*, error: str | None = None, repository_url: str = "") -> str:
    """Render the acquisition homepage."""

    error_html = (
        f'<p class="alert" role="alert">{_escape(error)}</p>'
        if error is not None
        else ""
    )
    return _page(
        "Know exactly what to fix next to reduce production risk",
        f"""
        <main>
          <section class="hero">
            <p class="eyebrow">Production-risk prioritisation for public repositories</p>
            <h1>Know exactly what to fix next to reduce production risk.</h1>
            <p class="lead"><strong>Paste a public GitHub repository</strong> and receive a
            prioritised Production Health report.</p>
            <p class="lead">DriftBeacon analyses infrastructure and dependency findings, removes
            test and example noise, and turns the remaining production risks into a prioritised
            engineering action plan.</p>
            <form class="scan-form" method="post" action="/scans">
              <label for="repository_url">Public GitHub repository URL</label>
              <div class="form-row">
                <input id="repository_url" name="repository_url" type="url"
                  placeholder="https://github.com/owner/repository"
                  value="{_escape(repository_url)}" required>
                <button type="submit">Analyse repository</button>
              </div>
              {error_html}
            </form>
          </section>

          <section class="band">
            <h2>How it works</h2>
            <div class="steps">
              <article><strong>1. Paste a repository</strong><span>No workflow file or install in
              the scanned repository.</span></article>
              <article><strong>2. DriftBeacon analyses it</strong><span>Checkov and Trivy findings
              are normalised, deduplicated and separated by production relevance.</span></article>
              <article><strong>3. Review what to fix first</strong><span>The report leads with
              Production Health and ranked engineering actions.</span></article>
            </div>
          </section>

          <section class="split">
            <div>
              <h2>Different from ordinary scanners</h2>
              <p>Ordinary scanners tell you everything they found. DriftBeacon helps you decide
              what your team should fix next.</p>
            </div>
            <div>
              <h2>Continuous monitoring later</h2>
              <p>Private repository monitoring, scheduled scans, saved history and team workflows
              are planned paid capabilities. Billing is not part of this public MVP.</p>
            </div>
          </section>

          <section class="methodology-note">
            <h2>What Production Health means</h2>
            <p>Production Health is a prioritisation and trend metric based on findings detected by
            completed scanners. It does not prove that a repository or production environment is
            secure.</p>
          </section>
        </main>
        """,
    )


def render_progress_page(state: WebScanState) -> str:
    """Render queued/running/failed scan states."""

    failure = (
        f"<p class=\"alert\" role=\"alert\">{_escape(state.safe_error_message or state.message)}</p>"
        if state.status == "failed"
        else ""
    )
    polling = (
        """
        <script>
          async function pollScan() {
            const response = await fetch(window.location.pathname.replace('/scans/', '/api/scans/'));
            if (!response.ok) return;
            const data = await response.json();
            document.querySelector('[data-status]').textContent = data.status;
            document.querySelector('[data-message]').textContent = data.message;
            document.querySelector('progress').value = data.progress;
            if (data.status === 'completed' || data.status === 'failed' || data.status === 'expired') {
              window.location.reload();
            }
          }
          setInterval(pollScan, 2000);
        </script>
        """
        if state.status not in {"completed", "failed"}
        else ""
    )
    return _page(
        "DriftBeacon scan progress",
        f"""
        <main class="narrow">
          <a class="back-link" href="/">Start another scan</a>
          <section class="panel">
            <p class="eyebrow">Repository analysis</p>
            <h1>{_escape(state.repository_url)}</h1>
            <dl class="status-grid">
              <div><dt>Status</dt><dd data-status>{_escape(state.status)}</dd></div>
              <div><dt>Message</dt><dd data-message>{_escape(state.message)}</dd></div>
            </dl>
            <progress max="100" value="{state.progress}"></progress>
            {failure}
          </section>
        </main>
        {polling}
        """,
    )


def render_repository_report_page(
    scan: ScanResult,
    comparison: ComparisonSummary,
    *,
    state: WebScanState | None = None,
) -> str:
    """Render a web report that emphasizes Production Health and next actions."""

    summary = scan.summary
    top_items = prioritise_findings(_web_priority_candidates(scan.findings), limit=3)
    priority_cards = "\n".join(
        _priority_card(index, item, comparison.has_baseline)
        for index, item in enumerate(top_items, start=1)
    ) or '<p class="empty">No active findings were detected by completed scanners.</p>'
    scanner_status = "\n".join(
        f"<li><strong>{_escape(status.name.capitalize())}:</strong> "
        f"{_escape(status.status.capitalize())} - {_escape(status.message)}</li>"
        for status in scan.scanner_statuses.values()
    ) or "<li>No scanner status was recorded.</li>"
    source_rows = _breakdown_rows(summary.get("finding_source_breakdown"))
    group_rows = _breakdown_rows(summary.get("directory_group_breakdown"))
    production_health = _score_text(summary.get("production_health_score"))
    production_grade = _grade_text(summary.get("production_grade"))
    overall_health = _score_text(scan.health_score)
    overall_grade = _grade_text(_grade_for_score(scan.health_score))
    provisional = " Provisional grade." if summary.get("production_grade_provisional") is True else ""
    retention_notice = _retention_notice(state)
    actions = _report_actions(state)
    return _page(
        f"DriftBeacon report for {scan.repository}",
        f"""
        <main>
          <a class="back-link" href="/">Analyse another repository</a>
          <section class="report-status">
            <h1>{_escape(scan.repository)}</h1>
            {actions}
            {retention_notice}
            <dl class="status-grid">
              <div><dt>Branch</dt><dd>{_escape(scan.branch)}</dd></div>
              <div><dt>Commit</dt><dd>{_escape(scan.commit_sha[:12])}</dd></div>
              <div><dt>Scan date</dt><dd>{_escape(_date_text(scan.completed_at))}</dd></div>
              <div><dt>Baseline</dt><dd>{_escape(_baseline_text(comparison))}</dd></div>
              <div><dt>Scanner coverage</dt><dd>{_escape(_coverage_text(summary))}</dd></div>
            </dl>
          </section>

          <section class="health-focus">
            <div>
              <p class="eyebrow">Primary metric</p>
              <h2>Production Health</h2>
              <p class="score">{_escape(production_health)}</p>
              <p class="grade">Grade {_escape(production_grade)}{_escape(provisional)}</p>
              <p>{_escape(str(summary.get("production_score_reason", "No production score reason recorded.")))}</p>
            </div>
            <aside>
              <h2>Overall Health</h2>
              <p class="support-score">{_escape(overall_health)} / Grade {_escape(overall_grade)}</p>
              <p>Overall Health includes all analysed actionable findings. Production Health is
              shown first because this report is designed to prioritise production risk.</p>
            </aside>
          </section>

          <section class="methodology-note">
            <h2>Methodology</h2>
            <p>Production Health is a prioritisation and trend metric based on findings detected by
            completed scanners. It does not prove that a repository or production environment is
            secure. Path classification is heuristic and should be reviewed.</p>
          </section>

          <section>
            <h2>What to fix next</h2>
            <p class="unavailable">This web report shows production-relevant findings first when
            they exist, then applies DriftBeacon's shared prioritisation and explanation logic.</p>
            <div class="priority-list">{priority_cards}</div>
          </section>

          <section class="impact">
            <h2>Expected impact</h2>
            <p>Current production-relevant actionable findings: <strong>{summary.get("production_actionable_findings", 0)}</strong>.</p>
            <p>Projected risk reduction, estimated effort and projected Production Health are
            unavailable in this MVP because remediation-impact simulation has not been implemented.
            DriftBeacon will only show those values after they are calculated from the real scoring
            model.</p>
          </section>

          <section class="evidence">
            <h2>Supporting evidence</h2>
            <div class="evidence-grid">
              <article>
                <h3>Severity distribution</h3>
                <ul>
                  <li>Critical: {summary.get("production_critical_findings", 0)} production / {_severity_count(scan, "critical")} total</li>
                  <li>High: {summary.get("production_high_findings", 0)} production / {_severity_count(scan, "high")} total</li>
                  <li>Medium: {summary.get("production_medium_findings", 0)} production / {_severity_count(scan, "medium")} total</li>
                  <li>Low: {summary.get("production_low_findings", 0)} production / {_severity_count(scan, "low")} total</li>
                </ul>
              </article>
              <article>
                <h3>Finding sources</h3>
                {_table(source_rows, "Source")}
              </article>
              <article>
                <h3>Directory groups</h3>
                {_table(group_rows, "Directory group")}
              </article>
              <article>
                <h3>Scanner status</h3>
                <ul>{scanner_status}</ul>
              </article>
            </div>
          </section>
        </main>
        """,
    )


def render_expired_report_page(state: WebScanState) -> str:
    return _page(
        "DriftBeacon report expired",
        f"""
        <main class="narrow">
          <a class="back-link" href="/">Start another scan</a>
          <section class="panel">
            <p class="eyebrow">Expired public report</p>
            <h1>{_escape(state.repository_label)}</h1>
            <p>This public report has expired and its stored findings have been removed.</p>
            <p>Run a new scan to generate a fresh report.</p>
          </section>
        </main>
        """,
    )


def render_error_page(message: str) -> str:
    return _page("DriftBeacon error", f"<main class=\"narrow\"><p class=\"alert\">{_escape(message)}</p></main>")


def render_not_found_page() -> str:
    return _page("Not found", '<main class="narrow"><h1>Not found</h1></main>')


def _priority_card(index: int, item: Any, has_baseline: bool) -> str:
    details = prioritised_finding_details(item, has_baseline=has_baseline)
    production_relevance = (
        "Production path" if details["directory_group"] == "production" else details["directory_group"]
    )
    return f"""
    <article class="priority-card">
      <p class="eyebrow">Priority {index}</p>
      <h3>{_escape(details["title"])}</h3>
      <dl>
        <div><dt>Severity</dt><dd>{_escape(details["severity"])}</dd></div>
        <div><dt>Production relevance</dt><dd>{_escape(production_relevance)}</dd></div>
        <div><dt>Location</dt><dd>{_escape(details["location"])}</dd></div>
        <div><dt>Finding source</dt><dd>{_escape(details["finding_source"])}</dd></div>
        <div><dt>Status</dt><dd>{_escape(details["status"])}</dd></div>
        <div><dt>Confidence</dt><dd>Scanner-reported finding</dd></div>
      </dl>
      <p><strong>Why it matters:</strong> {_escape(details["why"])}</p>
      <p><strong>Recommended action:</strong> {_escape(details["action"])}</p>
      <p class="unavailable">Estimated effort, projected risk reduction, projected Production
      Health and related findings resolved are unavailable until impact simulation is implemented.</p>
    </article>
    """


def _report_actions(state: WebScanState | None) -> str:
    if state is None or state.status != "completed":
        return ""
    return f"""
    <div class="report-actions">
      <button type="button" data-copy-report>Copy report link</button>
      <a class="button-link" href="/scans/{state.scan_id}/report.md">Download Markdown</a>
      <a class="button-link secondary" href="/scans/{state.scan_id}/report.json">Download JSON</a>
    </div>
    <script>
      const copyButton = document.querySelector('[data-copy-report]');
      if (copyButton) {{
        copyButton.addEventListener('click', async () => {{
          await navigator.clipboard.writeText(window.location.href);
          copyButton.textContent = 'Copied';
        }});
      }}
    </script>
    """


def _retention_notice(state: WebScanState | None) -> str:
    if state is None or state.expires_at is None:
        return ""
    return (
        '<p class="retention-note">This public report is available until '
        f"{_escape(_date_text(state.expires_at))}. Anyone with this link can view it.</p>"
    )


def _web_priority_candidates(findings: list[Finding]) -> list[Finding]:
    active = [finding for finding in findings if finding.status != "resolved"]
    production = [finding for finding in active if finding.directory_group == "production"]
    return production or active


def _enforce_repository_limits(repository_path: Path, config: WebConfig) -> None:
    files = safe_walk(repository_path)
    if len(files) > config.max_repository_files:
        raise WebScanFailure(
            "repository_file_limit_exceeded",
            "This repository exceeds the file-count limit for the public demo.",
            detail=f"repository file count {len(files)} exceeds {config.max_repository_files}",
        )
    total = 0
    for path in files:
        try:
            total += path.stat().st_size
        except OSError:
            continue
        if total > config.max_repository_bytes:
            limit_mb = round(config.max_repository_bytes / (1024 * 1024))
            raise WebScanFailure(
                "repository_too_large",
                "This repository exceeds the size limit for the public demo.",
                detail=f"repository byte size exceeds {limit_mb} MB",
            )


def _write_state_file(output_dir: Path, data: dict[str, Any]) -> None:
    path = output_dir / "scan-state.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _clone_failure(exc: ValueError) -> WebScanFailure:
    detail = redact_secrets(str(exc))
    lower = detail.lower()
    if "timed out" in lower:
        return WebScanFailure(
            "clone_timeout",
            "Git clone exceeded the public demo time limit.",
            detail=detail,
        )
    if "authentication" in lower or "could not read username" in lower:
        return WebScanFailure(
            "repository_private",
            "This repository could not be cloned. Confirm it is public and exists.",
            detail=detail,
        )
    if "not found" in lower or "repository not found" in lower:
        return WebScanFailure(
            "repository_not_found",
            "This repository could not be found on GitHub.",
            detail=detail,
        )
    return WebScanFailure(
        "repository_not_found",
        "This repository could not be cloned. Confirm it is public and exists.",
        detail=detail,
    )


def _repository_parts(repository_url: str) -> tuple[str, str]:
    parsed = urlparse(repository_url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        return "", ""
    return parts[0], parts[1].removesuffix(".git")


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _log_scan(scan_id: str, repository: str, status: str, detail: str) -> None:
    _LOGGER.info(
        "scan_id=%s repository=%s status=%s detail=%s",
        scan_id,
        repository,
        status,
        detail,
    )


def _breakdown_rows(raw: object) -> list[tuple[str, int, int, int, int, int]]:
    if not isinstance(raw, dict):
        return []
    rows: list[tuple[str, int, int, int, int, int]] = []
    for key, value in sorted(raw.items()):
        if isinstance(value, dict):
            rows.append(
                (
                    str(key).replace("_", " ").title(),
                    _int_value(value.get("critical")),
                    _int_value(value.get("high")),
                    _int_value(value.get("medium")),
                    _int_value(value.get("low")),
                    _int_value(value.get("total_actionable")),
                )
            )
    return rows


def _table(rows: list[tuple[str, int, int, int, int, int]], label: str) -> str:
    if not rows:
        return "<p>No findings recorded.</p>"
    body = "\n".join(
        f"<tr><td>{_escape(name)}</td><td>{critical}</td><td>{high}</td>"
        f"<td>{medium}</td><td>{low}</td><td>{total}</td></tr>"
        for name, critical, high, medium, low, total in rows
    )
    return f"""
    <table>
      <thead><tr><th>{_escape(label)}</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(title)} - DriftBeacon</title>
  <style>{_css()}</style>
</head>
<body>
  <header class="site-header"><a href="/">DriftBeacon</a><span>Production Health reports</span></header>
  {body}
</body>
</html>
"""


def _css() -> str:
    return """
    :root { color-scheme: light; --ink:#17201a; --muted:#5a675f; --line:#d8dfd9;
      --paper:#f8faf7; --panel:#ffffff; --accent:#176b56; --accent-2:#b04428; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color:var(--ink); background:var(--paper); line-height:1.5; }
    .site-header { display:flex; justify-content:space-between; align-items:center; padding:18px clamp(18px,4vw,48px);
      border-bottom:1px solid var(--line); background:#fff; }
    .site-header a { color:var(--ink); text-decoration:none; font-weight:800; }
    .site-header span, .eyebrow, dt { color:var(--muted); font-size:0.86rem; }
    main { max-width:1120px; margin:0 auto; padding:34px clamp(18px,4vw,48px) 64px; }
    .narrow { max-width:760px; }
    .hero { padding:52px 0 38px; max-width:850px; }
    h1 { font-size:clamp(2.2rem,5vw,4.7rem); line-height:1; margin:10px 0 18px; letter-spacing:0; }
    h2 { font-size:1.55rem; margin:0 0 14px; }
    h3 { margin:0 0 12px; font-size:1.08rem; }
    .lead { font-size:1.2rem; max-width:760px; color:#2d3a33; }
    .scan-form { margin-top:28px; }
    label { display:block; font-weight:700; margin-bottom:8px; }
    .form-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:10px; max-width:760px; }
    input { width:100%; min-height:46px; border:1px solid var(--line); border-radius:8px; padding:0 14px; font:inherit; }
    button, .button-link { min-height:46px; border:0; border-radius:8px; padding:0 18px; font-weight:800; color:#fff; background:var(--accent); cursor:pointer; display:inline-flex; align-items:center; text-decoration:none; }
    .button-link.secondary { background:#2d3a33; }
    .report-actions { display:flex; flex-wrap:wrap; gap:10px; margin:16px 0; }
    .retention-note { border:1px solid var(--line); border-radius:8px; padding:12px; background:#fff; color:var(--muted); }
    .band, .split, .methodology-note, .panel, .report-status, .health-focus, .impact, .evidence {
      border-top:1px solid var(--line); padding:28px 0; }
    .steps, .split, .health-focus, .evidence-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:18px; }
    .split, .health-focus { grid-template-columns:1fr 1fr; }
    article, .health-focus aside, .health-focus > div { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; }
    .steps article span { display:block; color:var(--muted); margin-top:6px; }
    .status-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin:18px 0 0; }
    .status-grid div { border:1px solid var(--line); border-radius:8px; padding:12px; background:#fff; }
    dd { margin:4px 0 0; font-weight:750; overflow-wrap:anywhere; }
    progress { width:100%; height:18px; margin-top:18px; }
    .score { font-size:4.2rem; line-height:1; font-weight:900; margin:8px 0; color:var(--accent); }
    .support-score { font-size:1.55rem; font-weight:800; }
    .grade { font-weight:800; color:var(--accent-2); }
    .priority-list { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }
    .priority-card dl { display:grid; gap:8px; margin:12px 0; }
    .priority-card dl div { border-top:1px solid var(--line); padding-top:8px; }
    .unavailable, .empty { color:var(--muted); font-size:0.92rem; }
    .alert { border:1px solid #c65a42; background:#fff0ec; color:#7b2718; border-radius:8px; padding:12px; }
    .back-link { color:var(--accent); font-weight:800; text-decoration:none; }
    table { width:100%; border-collapse:collapse; font-size:0.9rem; }
    th, td { text-align:left; border-bottom:1px solid var(--line); padding:7px 5px; vertical-align:top; }
    @media (max-width:850px) {
      .form-row, .steps, .split, .health-focus, .priority-list, .evidence-grid, .status-grid { grid-template-columns:1fr; }
      h1 { font-size:2.4rem; }
      .score { font-size:3.2rem; }
      .site-header { align-items:flex-start; gap:8px; flex-direction:column; }
    }
    """


def _score_text(score: object) -> str:
    return f"{score}/100" if isinstance(score, int) else "Not scored"


def _grade_text(grade: object) -> str:
    return str(grade or "N/A")


def _grade_for_score(score: int | None) -> str:
    if score is None:
        return "N/A"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _coverage_text(summary: dict[str, Any]) -> str:
    coverage = str(summary.get("production_coverage_state") or summary.get("coverage_state", "unknown"))
    labels = {
        "complete_coverage": "Complete",
        "partial_coverage": "Partial coverage",
        "not_scored_no_supported_files": "Not scored: no supported files",
        "not_scored_all_scanners_failed": "Not scored: scanners failed",
    }
    return labels.get(coverage, coverage)


def _baseline_text(comparison: ComparisonSummary) -> str:
    if not comparison.has_baseline:
        return "Initial baseline"
    if comparison.health_score_change is None:
        return "Comparison available"
    if comparison.health_score_change > 0:
        return f"Overall Health up {comparison.health_score_change} points"
    if comparison.health_score_change < 0:
        return f"Overall Health down {abs(comparison.health_score_change)} points"
    return "Overall Health unchanged"


def _date_text(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "unknown"


def _severity_count(scan: ScanResult, severity: str) -> int:
    return sum(1 for finding in scan.findings if finding.status != "resolved" and finding.severity == severity)


def _int_value(value: object) -> int:
    return value if isinstance(value, int) else 0


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc
