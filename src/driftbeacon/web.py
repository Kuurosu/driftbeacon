"""Public web scan MVP for DriftBeacon."""

# ruff: noqa: E501

from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse
from wsgiref.simple_server import make_server
from wsgiref.types import StartResponse, WSGIEnvironment

from .analysis import clone_repository, detect_supported_infrastructure_files
from .analysis_metrics import (
    classify_path_group,
    directory_group_breakdown,
    finding_source_breakdown,
    production_findings,
)
from .comparison import compare_scans
from .config import load_config
from .models import ComparisonSummary, Finding, ScanResult
from .prioritise import PrioritisedFinding, prioritise_findings
from .redaction import redact_secrets
from .reporting import generate_report, prioritised_finding_details
from .scanners.base import safe_walk
from .scoring import (
    ACTIONABLE_SEVERITIES,
    calculate_health_score,
    deduplicate_findings_by_fingerprint,
    severity_counts,
)
from .storage import StorageError
from .web_storage import (
    WEB_REPORT_FORMAT_VERSION,
    FeedbackRecord,
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


BetaAccessMode = Literal["open", "invite"]


@dataclass(frozen=True, slots=True)
class BetaConfig:
    """Controlled public beta settings for web submissions."""

    enabled: bool = True
    access_mode: BetaAccessMode = "open"
    access_codes: tuple[str, ...] = ()
    accepting_scans: bool = True
    max_scans_per_source_per_day: int = 3
    max_total_scans_per_day: int = 25
    rate_limit_secret: str = "driftbeacon-local-rate-limit"
    trusted_proxy_ips: tuple[str, ...] = ("127.0.0.1", "::1")
    max_feedback_per_source_per_day: int = 5

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> BetaConfig:
        source = env or dict(os.environ)
        raw_mode = source.get("DRIFTBEACON_BETA_ACCESS_MODE", "open").strip().lower()
        access_mode: BetaAccessMode = "invite" if raw_mode == "invite" else "open"
        return cls(
            enabled=_env_bool(source, "DRIFTBEACON_BETA_ENABLED", True),
            access_mode=access_mode,
            access_codes=_env_list(source, "DRIFTBEACON_BETA_ACCESS_CODES"),
            accepting_scans=_env_bool(source, "DRIFTBEACON_BETA_ACCEPTING_SCANS", True),
            max_scans_per_source_per_day=_env_int(
                source,
                "DRIFTBEACON_BETA_MAX_SCANS_PER_IP_PER_DAY",
                3,
            ),
            max_total_scans_per_day=_env_int(
                source,
                "DRIFTBEACON_BETA_MAX_TOTAL_SCANS_PER_DAY",
                25,
            ),
            rate_limit_secret=(
                source.get("DRIFTBEACON_RATE_LIMIT_SECRET", "").strip()
                or "driftbeacon-local-rate-limit"
            ),
            trusted_proxy_ips=_env_list(
                source,
                "DRIFTBEACON_TRUSTED_PROXY_IPS",
                default=("127.0.0.1", "::1"),
            ),
            max_feedback_per_source_per_day=_env_int(
                source,
                "DRIFTBEACON_BETA_MAX_FEEDBACK_PER_IP_PER_DAY",
                5,
            ),
        ).validate()

    def validate(self) -> BetaConfig:
        if self.access_mode not in {"open", "invite"}:
            raise ValueError("beta access_mode must be open or invite")
        if self.max_scans_per_source_per_day < 1:
            raise ValueError("beta max_scans_per_source_per_day must be at least 1")
        if self.max_total_scans_per_day < 1:
            raise ValueError("beta max_total_scans_per_day must be at least 1")
        if self.max_feedback_per_source_per_day < 1:
            raise ValueError("beta max_feedback_per_source_per_day must be at least 1")
        if not self.rate_limit_secret.strip():
            raise ValueError("DRIFTBEACON_RATE_LIMIT_SECRET must not be empty")
        for value in self.trusted_proxy_ips:
            with suppress(ValueError):
                ipaddress.ip_address(value)
                continue
            raise ValueError("trusted proxy IPs must be valid IP addresses")
        return self

    def access_code_is_valid(self, candidate: str) -> bool:
        if self.access_mode == "open":
            return True
        submitted = candidate.strip()
        if not submitted or not self.access_codes:
            return False
        return any(hmac.compare_digest(submitted, code) for code in self.access_codes)


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
    max_repository_files: int = 8_000
    max_repository_bytes: int = 150 * 1024 * 1024
    top_findings: int = 3
    beta: BetaConfig = field(default_factory=BetaConfig)

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> WebConfig:
        source = env or dict(os.environ)
        output_dir = Path(source.get("DRIFTBEACON_WEB_OUTPUT_DIR", ".driftbeacon"))
        max_scan_seconds = _env_int(source, "DRIFTBEACON_WEB_MAX_SCAN_SECONDS", 300)
        return cls(
            output_dir=output_dir,
            database_path=Path(source.get("DRIFTBEACON_WEB_DATABASE", str(output_dir / "web.sqlite3"))),
            report_dir=Path(source.get("DRIFTBEACON_WEB_REPORT_DIR", str(output_dir / "reports"))),
            working_dir=Path(
                source.get(
                    "DRIFTBEACON_SCAN_WORK_DIR",
                    source.get("DRIFTBEACON_WEB_WORK_DIR", str(output_dir / "work")),
                )
            ),
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
            max_repository_files=_env_int(source, "DRIFTBEACON_WEB_MAX_REPOSITORY_FILES", 8_000),
            max_repository_bytes=_env_int(
                source,
                "DRIFTBEACON_WEB_MAX_REPOSITORY_BYTES",
                150 * 1024 * 1024,
            ),
            top_findings=_env_int(source, "DRIFTBEACON_WEB_TOP_FINDINGS", 3),
            beta=BetaConfig.from_environment(source),
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
        if self.max_repository_files < 1:
            raise ValueError("web max_repository_files must be at least 1")
        if self.max_repository_bytes < 1:
            raise ValueError("web max_repository_bytes must be at least 1")
        if self.top_findings < 1:
            raise ValueError("web top_findings must be at least 1")
        self.beta.validate()
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


@dataclass(frozen=True, slots=True)
class ReportFindingOptions:
    """Query options for the web findings explorer."""

    view: str = ""
    severity: str = ""
    production: str = ""
    scanner: str = ""
    category: str = ""
    path_type: str = ""
    status: str = ""
    sort: str = "recommended"
    page: int = 1


@dataclass(frozen=True, slots=True)
class ReportFindingView:
    """Rendered finding row with priority context and a safe anchor."""

    finding: Finding
    priority: PrioritisedFinding
    rank: int
    anchor: str
    duplicate_count: int


@dataclass(frozen=True, slots=True)
class ReportFindingPage:
    """Filtered and paginated finding explorer state."""

    all_findings: list[ReportFindingView]
    filtered_findings: list[ReportFindingView]
    page_findings: list[ReportFindingView]
    options: ReportFindingOptions
    total_count: int
    filtered_count: int
    page_count: int
    total_pages: int
    has_more_than_top_three: bool


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
        recover_interrupted: bool = False,
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
        if recover_interrupted:
            self.mark_abandoned_scans_interrupted()
        if cleanup_on_start:
            self.cleanup_expired_scans()

    def submit(
        self,
        repository_url: str,
        *,
        client_id: str = "anonymous",
        access_code: str = "",
    ) -> WebScanState:
        try:
            normalised_url = self.provider.normalise_url(repository_url)
        except ValueError as exc:
            raise WebSubmissionError("invalid_repository_url", str(exc)) from exc
        source_hash = self.source_hash(client_id)
        self._enforce_beta_access(source_hash, access_code)
        self.cleanup_expired_scans()
        if self.store.count_queued_scans() >= self.config.max_queued_scans:
            self._record_rejected_submission(source_hash)
            self.record_event(
                "scan_rejected",
                source_hash=source_hash,
                properties={"reason": "capacity_reached"},
            )
            raise WebSubmissionError(
                "capacity_reached",
                "The public demo is currently at capacity. Please try again later.",
                http_status="503 Service Unavailable",
            )
        self._enforce_daily_rate_limit(source_hash)
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
            client_id=source_hash,
        )
        self.store.create_scan(state)
        _log_scan(scan_id, normalised_url, "queued", "created")
        self.record_event(
            "scan_submitted",
            source_hash=source_hash,
            scan_id=scan_id,
            properties={"repository": f"{owner}/{repo}"},
        )
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

    def readiness(self) -> bool:
        try:
            return self.store.check_ready() and self.report_store.check_writable()
        except StorageError:
            return False

    def source_hash(self, client_id: str) -> str:
        return hash_submission_source(client_id, self.config.beta.rate_limit_secret)

    def record_event(
        self,
        event: str,
        *,
        source_hash: str | None = None,
        scan_id: str | None = None,
        properties: AnalyticsProperties | None = None,
    ) -> None:
        safe_properties = properties or {}
        with suppress(Exception):
            self.store.record_analytics_event(
                event,
                source_hash=source_hash,
                scan_id=scan_id,
                properties=dict(safe_properties),
            )
        with suppress(Exception):
            self.analytics.record(event, safe_properties)

    def save_feedback(
        self,
        *,
        source_hash: str,
        scan_id: str | None,
        helpfulness: str,
        changed_priority: str,
        difficult_to_understand: str,
        private_monitoring_interest: bool,
        comment: str,
        email: str,
        consent_to_contact: bool,
    ) -> str:
        date_bucket = _date_bucket(datetime.now(UTC))
        if (
            self.store.count_feedback_from_source_on(
                source_hash=source_hash,
                date_bucket=date_bucket,
            )
            >= self.config.beta.max_feedback_per_source_per_day
        ):
            raise WebSubmissionError(
                "capacity_reached",
                "The public beta feedback limit has been reached. Please try again later.",
                http_status="429 Too Many Requests",
            )
        feedback_id = uuid.uuid4().hex
        stored_email = email.strip() if consent_to_contact else ""
        self.store.save_feedback(
            FeedbackRecord(
                feedback_id=feedback_id,
                created_at=datetime.now(UTC),
                scan_id=scan_id,
                source_hash=source_hash,
                helpfulness=helpfulness,
                changed_priority=changed_priority,
                difficult_to_understand=difficult_to_understand,
                private_monitoring_interest=private_monitoring_interest,
                comment=comment,
                email=stored_email or None,
                consent_to_contact=bool(consent_to_contact and stored_email),
            )
        )
        self.record_event(
            "feedback_submitted",
            source_hash=source_hash,
            scan_id=scan_id,
            properties={"helpfulness": helpfulness, "changed_priority": changed_priority},
        )
        if private_monitoring_interest:
            self.record_event(
                "private_monitoring_interest_submitted",
                source_hash=source_hash,
                scan_id=scan_id,
                properties={"consent_to_contact": bool(consent_to_contact and stored_email)},
            )
        return feedback_id

    def _enforce_beta_access(self, source_hash: str, access_code: str) -> None:
        beta = self.config.beta
        if not beta.enabled:
            return
        if not beta.accepting_scans:
            self._record_rejected_submission(source_hash)
            self.record_event(
                "scan_rejected",
                source_hash=source_hash,
                properties={"reason": "submissions_paused"},
            )
            raise WebSubmissionError(
                "capacity_reached",
                "New scans are temporarily paused while we perform maintenance. Existing reports remain available.",
                http_status="503 Service Unavailable",
            )
        if beta.access_mode == "invite" and not beta.access_code_is_valid(access_code):
            self._record_rejected_submission(source_hash)
            self.record_event(
                "scan_rejected",
                source_hash=source_hash,
                properties={"reason": "invalid_beta_access_code"},
            )
            raise WebSubmissionError(
                "capacity_reached",
                "Enter a valid beta access code to start a scan.",
                http_status="403 Forbidden",
            )

    def _enforce_daily_rate_limit(self, source_hash: str) -> None:
        beta = self.config.beta
        if not beta.enabled:
            return
        result = self.store.record_submission_attempt(
            source_hash=source_hash,
            date_bucket=_date_bucket(datetime.now(UTC)),
            max_source_accepts=beta.max_scans_per_source_per_day,
            max_total_accepts=beta.max_total_scans_per_day,
        )
        if not result.allowed:
            self.record_event(
                "scan_rejected",
                source_hash=source_hash,
                properties={"reason": result.reason},
            )
            raise WebSubmissionError(
                "capacity_reached",
                "The public beta scan limit has been reached. Please try again later.",
                http_status="429 Too Many Requests",
            )

    def _record_rejected_submission(self, source_hash: str) -> None:
        with suppress(StorageError):
            self.store.record_rejected_submission(
                source_hash=source_hash,
                date_bucket=_date_bucket(datetime.now(UTC)),
            )

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
            if method == "GET" and path == "/health/live":
                return self._json(start_response, {"status": "alive"})
            if method == "GET" and path == "/health/ready":
                if self.service.readiness():
                    return self._json(start_response, {"status": "ready"})
                return self._json(
                    start_response,
                    {"status": "not_ready"},
                    status="503 Service Unavailable",
                )
            if method == "GET" and path == "/":
                source_hash = self._source_hash(environ)
                self.service.record_event("homepage_viewed", source_hash=source_hash)
                return self._html(start_response, render_home_page(config=self.service.config))
            if method == "GET" and path == "/sample-report":
                source_hash = self._source_hash(environ)
                self.service.record_event("sample_report_viewed", source_hash=source_hash)
                return self._html(
                    start_response,
                    render_sample_report_page(
                        feedback_submitted=_query_flag(environ, "feedback", "thanks"),
                        options=report_finding_options_from_environ(environ),
                    ),
                )
            if method == "GET" and path == "/privacy":
                return self._html(start_response, render_privacy_page())
            if method == "GET" and path == "/acceptable-use":
                return self._html(start_response, render_acceptable_use_page())
            if method == "POST" and path == "/scans":
                return self._submit(environ, start_response)
            if method == "POST" and path == "/feedback":
                return self._submit_feedback(environ, start_response)
            if method == "GET" and path.startswith("/api/scans/"):
                return self._api_scan(path, start_response)
            if method == "GET" and path.startswith("/scans/"):
                return self._scan_page(path, start_response, environ)
        except WebSubmissionError as exc:
            return self._html(
                start_response,
                render_home_page(error=exc.safe_message, config=self.service.config),
                status=exc.http_status,
            )
        except ValueError as exc:
            return self._html(
                start_response,
                render_home_page(error=str(exc), config=self.service.config),
                status="400 Bad Request",
            )
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
        access_code = (form.get("beta_access_code") or [""])[0].strip()
        client_id = client_source_from_environ(environ, self.service.config.beta)
        try:
            state = self.service.submit(
                repository_url,
                client_id=client_id,
                access_code=access_code,
            )
        except WebSubmissionError as exc:
            return self._html(
                start_response,
                render_home_page(
                    error=exc.safe_message,
                    repository_url=repository_url,
                    config=self.service.config,
                ),
                status=exc.http_status,
            )
        except ValueError as exc:
            self.service.record_event(
                "scan_rejected",
                source_hash=self.service.source_hash(client_id),
                properties={"reason": "validation"},
            )
            return self._html(
                start_response,
                render_home_page(
                    error=str(exc),
                    repository_url=repository_url,
                    config=self.service.config,
                ),
                status="400 Bad Request",
            )
        start_response("303 See Other", [("Location", f"/scans/{state.scan_id}")])
        return [b""]

    def _submit_feedback(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        if length > 8192:
            return self._html(
                start_response,
                render_error_page("Feedback is too large."),
                status="400 Bad Request",
            )
        body = environ["wsgi.input"].read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        scan_id = (form.get("scan_id") or [""])[0].strip() or None
        if scan_id is not None and not valid_scan_id(scan_id):
            scan_id = None
        source_hash = self.service.source_hash(
            client_source_from_environ(environ, self.service.config.beta)
        )
        target = f"/scans/{scan_id}" if scan_id else "/sample-report"
        if (form.get("website") or [""])[0].strip():
            return self._redirect(start_response, f"{target}?{urlencode({'feedback': 'thanks'})}")
        try:
            helpfulness = _validated_choice(
                (form.get("helpfulness") or [""])[0],
                {"yes", "partly", "no"},
                "helpfulness",
            )
            changed_priority = _validated_choice(
                (form.get("changed_priority") or [""])[0],
                {"yes", "maybe", "no"},
                "changed priority",
            )
            difficult_to_understand = _validated_choice(
                (form.get("difficult_to_understand") or [""])[0],
                {
                    "",
                    "production_health",
                    "overall_health",
                    "score_difference",
                    "top_priorities",
                    "finding_explanations",
                    "scanner_coverage",
                    "other",
                },
                "report difficulty",
            )
            comment = _validated_text((form.get("comment") or [""])[0], "feedback", 2000)
            email = _validated_text((form.get("email") or [""])[0], "email", 320)
            consent_to_contact = (form.get("consent_to_contact") or [""])[0] == "yes"
            private_monitoring_interest = (
                (form.get("private_monitoring_interest") or [""])[0] == "yes"
            )
            self.service.save_feedback(
                source_hash=source_hash,
                scan_id=scan_id,
                helpfulness=helpfulness,
                changed_priority=changed_priority,
                difficult_to_understand=difficult_to_understand,
                private_monitoring_interest=private_monitoring_interest,
                comment=comment,
                email=email,
                consent_to_contact=consent_to_contact,
            )
        except WebSubmissionError as exc:
            return self._html(
                start_response,
                render_error_page(exc.safe_message),
                status=exc.http_status,
            )
        except ValueError as exc:
            return self._html(
                start_response,
                render_error_page(str(exc)),
                status="400 Bad Request",
            )
        return self._redirect(start_response, f"{target}?{urlencode({'feedback': 'thanks'})}")

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

    def _json(
        self,
        start_response: StartResponse,
        data: dict[str, str],
        *,
        status: str = "200 OK",
    ) -> Iterable[bytes]:
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        start_response(
            status,
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(payload))),
                ("Cache-Control", "no-store"),
            ],
        )
        return [payload]

    def _scan_page(
        self,
        path: str,
        start_response: StartResponse,
        environ: WSGIEnvironment,
    ) -> Iterable[bytes]:
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
            self.service.record_event("report_viewed", scan_id=scan_id)
            return self._html(
                start_response,
                render_repository_report_page(
                    stored.scan,
                    stored.comparison,
                    state=state,
                    feedback_submitted=_query_flag(environ, "feedback", "thanks"),
                    options=report_finding_options_from_environ(environ),
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
        self.service.record_event(
            "report_downloaded",
            scan_id=state.scan_id,
            properties={"artifact": artifact},
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

    def _redirect(self, start_response: StartResponse, location: str) -> Iterable[bytes]:
        start_response("303 See Other", [("Location", location)])
        return [b""]

    def _source_hash(self, environ: WSGIEnvironment) -> str:
        return self.service.source_hash(
            client_source_from_environ(environ, self.service.config.beta)
        )

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


def render_home_page(
    *,
    error: str | None = None,
    repository_url: str = "",
    config: WebConfig | None = None,
) -> str:
    """Render the acquisition homepage."""

    web_config = config or WebConfig()
    beta = web_config.beta
    error_html = (
        f'<div class="alert" role="alert"><h2>Submission problem</h2><p>{_escape(error)}</p></div>'
        if error is not None
        else ""
    )
    paused = beta.enabled and not beta.accepting_scans
    pause_html = (
        """
        <div class="notice" role="status">
          <strong>New scans are temporarily paused while we perform maintenance.</strong>
          Existing reports remain available.
        </div>
        """
        if paused
        else ""
    )
    access_field = (
        """
        <label for="beta_access_code">Beta access code</label>
        <input id="beta_access_code" name="beta_access_code" type="password"
          autocomplete="off" inputmode="text" placeholder="Access code" required>
        """
        if beta.enabled and beta.access_mode == "invite"
        else ""
    )
    disabled = " disabled" if paused else ""
    limit_text = _format_bytes(web_config.max_repository_bytes)
    return _page(
        "Know exactly what to fix next to reduce production risk",
        f"""
        <main>
          <section class="hero">
            <p class="eyebrow">Controlled public beta</p>
            <h1>Know exactly what to fix next to reduce production risk.</h1>
            <p class="lead">Paste a public GitHub repository. DriftBeacon analyses infrastructure
            and dependency findings, removes non-production noise, and shows what your team should
            address first.</p>
            <p><a class="text-link" href="/sample-report">View an example report</a></p>
            {pause_html}
            <form class="scan-form" method="post" action="/scans">
              <label for="repository_url">Public GitHub repository URL</label>
              <div class="form-row">
                <input id="repository_url" name="repository_url" type="url"
                  placeholder="https://github.com/owner/repository"
                  value="{_escape(repository_url)}" required{disabled}>
                <button type="submit"{disabled}>Analyse repository</button>
              </div>
              <div class="access-row">{access_field}</div>
              {error_html}
            </form>
          </section>

          <section class="band">
            <h2>How it works</h2>
            <div class="steps">
              <article><strong>1. Submit a public repository</strong><span>No workflow file or
              install in the scanned repository.</span></article>
              <article><strong>2. DriftBeacon runs static analysis</strong><span>Infrastructure
              and dependency findings are normalised, deduplicated and grouped by production
              relevance.</span></article>
              <article><strong>3. Review what to fix next</strong><span>The report leads with
              Production Health and ranked engineering actions.</span></article>
            </div>
          </section>

          <section class="band">
            <h2>Public beta limits</h2>
            <ul class="plain-list">
              <li>Public GitHub repositories only.</li>
              <li>Maximum repository size applies; current limit is {_escape(limit_text)}.</li>
              <li>Scans may take several minutes and queued scans wait for the worker.</li>
              <li>Reports are retained for {_escape(web_config.retention_days)} days.</li>
              <li>Usage is limited during the beta.</li>
            </ul>
          </section>

          <section class="split">
            <article>
              <h2>What this beta does</h2>
              <p>Ordinary scanners tell you everything they found. DriftBeacon helps you decide
              what your team should fix next by putting production-relevant risk first.</p>
            </article>
            <article>
              <h2>Current scope</h2>
              <p>The beta supports public GitHub repositories, performs static analysis, does not
              execute the submitted application and may not identify every vulnerability.</p>
            </article>
            <article>
              <h2>Methodology</h2>
              <p>DriftBeacon uses Checkov and Trivy scanner output as inputs, then applies its own
              normalisation, production classification, scoring and prioritisation.</p>
            </article>
          </section>

          <section class="methodology-note">
            <h2>Important limitations</h2>
            <p>Production Health is a prioritisation and trend metric. It does not prove that a
            repository or production environment is secure. Reports are temporary and visible to
            anyone with the link.</p>
          </section>
        </main>
        """,
    )


def render_progress_page(state: WebScanState) -> str:
    """Render queued/running/failed scan states."""

    safe_failure = _safe_failure_message(state)
    failure = (
        f"""
        <div class="alert" role="alert">
          <h2>Scan could not complete</h2>
          <p>{_escape(safe_failure)}</p>
          <p>Try a smaller public GitHub repository, review the beta limits, or view the example
          report to see the expected output.</p>
        </div>
        """
        if state.status == "failed"
        else ""
    )
    polling = (
        """
        <script>
          const stageLabels = {
            queued: 'Queued',
            cloning: 'Cloning repository',
            analysing: 'Checking repository limits and analysing findings',
            generating_report: 'Preparing prioritised report',
            completed: 'Completed',
            failed: 'Failed safely',
            expired: 'Expired'
          };
          const stepOrder = ['queued', 'cloning', 'analysing', 'generating_report', 'completed'];
          function updateProgressSteps(status) {
            const currentIndex = stepOrder.includes(status) ? stepOrder.indexOf(status) : 0;
            document.querySelectorAll('[data-step-key]').forEach((step) => {
              const stepIndex = stepOrder.indexOf(step.dataset.stepKey);
              let state = stepIndex < currentIndex ? 'complete' : stepIndex === currentIndex ? 'current' : 'waiting';
              if (status === 'failed' && stepIndex === currentIndex) state = 'failed';
              step.className = state;
              const label = step.querySelector('small');
              if (label) label.textContent = state;
            });
          }
          async function pollScan() {
            const response = await fetch(window.location.pathname.replace('/scans/', '/api/scans/'));
            if (!response.ok) return;
            const data = await response.json();
            document.querySelector('[data-status]').textContent = stageLabels[data.status] || data.status;
            document.querySelector('[data-message]').textContent = data.message;
            updateProgressSteps(data.status);
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
            <h1>{_escape(state.repository_label)}</h1>
            <dl class="status-grid">
              <div><dt>Status</dt><dd data-status>{_escape(state.status)}</dd></div>
              <div><dt>Current stage</dt><dd data-message>{_escape(_stage_label(state))}</dd></div>
              <div><dt>Elapsed</dt><dd>{_escape(_elapsed_text(state.created_at))}</dd></div>
            </dl>
            <ol class="step-list" aria-label="Scan progress">
              {_progress_steps(state.status)}
            </ol>
            <p class="unavailable">This page updates automatically. You can also
            <a class="text-link" href="/scans/{state.scan_id}">refresh manually</a>.</p>
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
    feedback_submitted: bool = False,
    sample: bool = False,
    options: ReportFindingOptions | None = None,
) -> str:
    """Render a web report that emphasizes Production Health and next actions."""

    summary = scan.summary
    report_path = "/sample-report" if sample else f"/scans/{state.scan_id}" if state else ""
    report_options = options or ReportFindingOptions()
    expanded_findings = report_options.view == "all"
    finding_page = build_report_finding_page(
        scan,
        report_options,
        page_size=50 if expanded_findings else 10,
    )
    finding_notice = _finding_state_notice(scan)
    priority_cards = "\n".join(
        _priority_card(index, view, comparison.has_baseline, report_path=report_path)
        for index, view in enumerate(finding_page.all_findings[:3], start=1)
    ) or f'<p class="empty">{_escape(_empty_findings_text(scan))}</p>'
    production_health = _score_text(summary.get("production_health_score"))
    production_grade = _grade_text(summary.get("production_grade"))
    overall_health = _score_text(scan.health_score)
    overall_grade = _grade_text(_grade_for_score(scan.health_score))
    provisional = " Provisional grade." if summary.get("production_grade_provisional") is True else ""
    retention_notice = _retention_notice(state)
    actions = _report_actions(state)
    sample_notice = (
        """
        <div class="notice" role="status">
          <strong>Example report.</strong> This page uses generated fixture data and does not
          describe a real organisation.
        </div>
        """
        if sample
        else ""
    )
    scan_id = state.scan_id if state is not None else None
    top_summary = _top_priority_summary(finding_page, report_path)
    divergence = _score_divergence_callout(scan)
    glossary = _report_glossary()
    initial_tab = "findings" if expanded_findings else "overview"
    return _page(
        f"DriftBeacon report for {scan.repository}",
        f"""
        <main class="report-main" data-initial-tab="{_escape(initial_tab)}">
          <a class="back-link" href="/">Analyse another repository</a>
          <section class="report-status">
            {sample_notice}
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

          <nav class="report-tabs" role="tablist" aria-label="Report sections">
            <button type="button" role="tab" data-report-tab="overview" aria-controls="tab-overview">Overview</button>
            <button type="button" role="tab" data-report-tab="priorities" aria-controls="tab-priorities">Priorities</button>
            <button type="button" role="tab" data-report-tab="findings" aria-controls="tab-findings">Findings</button>
            <button type="button" role="tab" data-report-tab="coverage" aria-controls="tab-coverage">Coverage</button>
            <button type="button" role="tab" data-report-tab="feedback" aria-controls="tab-feedback">Feedback</button>
          </nav>

          <section id="tab-overview" class="tab-panel" data-tab-panel="overview" role="tabpanel">
            <section class="report-section health-focus" aria-labelledby="production-health-heading">
              <div class="score-card score-card-primary">
                <p class="eyebrow">Primary metric</p>
                <h2 id="production-health-heading">Production Health {_help_bubble("Production Health", "A 0 to 100 prioritisation score calculated from deduplicated active actionable findings in paths DriftBeacon classifies as production-relevant. It does not prove the deployed environment is secure.")}</h2>
                <p class="score">{_escape(production_health)}</p>
                <p class="grade">Grade {_escape(production_grade)}{_escape(provisional)}</p>
                <p>Production Health focuses on findings that DriftBeacon classifies as production-relevant or likely production-related from repository paths.</p>
                <p>A high Production Health score means those production-relevant areas have relatively few or lower-impact included findings. It does not mean the entire repository is healthy or secure.</p>
                <p>{_escape(str(summary.get("production_score_reason", "No production score reason recorded.")))}</p>
                {_score_breakdown("Production-relevant included findings", _production_severity_counts(scan))}
                {_score_calculation_disclosure("production")}
                {finding_notice}
              </div>
              <aside class="score-card">
                <h2>Overall Health {_help_bubble("Overall Health", "A 0 to 100 score calculated from included deduplicated active actionable findings across the scanned repository, including non-production areas where detected.")}</h2>
                <p class="support-score">{_escape(overall_health)} / Grade {_escape(overall_grade)}</p>
                <p>Overall Health reflects included findings across the scanned repository, including development, example, test, generated and non-production areas where detected.</p>
                <p>A low Overall Health score can be caused by many findings outside the areas DriftBeacon considers production-relevant.</p>
                {_score_breakdown("All included findings", _severity_counts_for_report(scan.findings))}
                {_score_calculation_disclosure("overall")}
              </aside>
            </section>

            {divergence}

            <section class="report-section impact">
              <h2>What to do with this report</h2>
              <p>Current production-relevant actionable findings: <strong>{summary.get("production_actionable_findings", 0)}</strong>.</p>
              <p>Start with the top priorities, inspect the full finding detail, confirm whether each affected path is actually used for production, and then apply the recommended remediation in your normal engineering workflow.</p>
              <p>Projected risk reduction, estimated effort and projected Production Health are
              unavailable in this MVP because remediation-impact simulation has not been implemented.
              DriftBeacon will only show those values after they are calculated from the real scoring
              model.</p>
            </section>
          </section>

          <section id="tab-priorities" class="tab-panel" data-tab-panel="priorities" role="tabpanel">
            <section class="report-section" aria-labelledby="top-priorities-heading">
              <h2 id="top-priorities-heading">Top priorities {_help_bubble("Top priorities", "The three findings DriftBeacon recommends investigating first based on severity, production relevance and deterministic prioritisation rules.")}</h2>
              <p>These are the three issues DriftBeacon recommends investigating first based on production relevance, severity and the deterministic priority rules.</p>
              <p class="count-note">{top_summary}</p>
              <div class="priority-list">{priority_cards}</div>
            </section>
          </section>

          <section id="tab-findings" class="tab-panel" data-tab-panel="findings" role="tabpanel">
            {_all_findings_section(finding_page, report_path)}
          </section>

          <section id="tab-coverage" class="tab-panel" data-tab-panel="coverage" role="tabpanel">
            {_scanner_coverage_section(scan)}
            {glossary}
          </section>

          <section id="tab-feedback" class="tab-panel" data-tab-panel="feedback" role="tabpanel">
            <section class="methodology-note">
              <h2>Private monitoring interest</h2>
              <p>Want continuous monitoring for private repositories?</p>
              <p>DriftBeacon plans to support private GitHub repositories, scan history, Production
              Health trends and Slack alerts.</p>
              <p><a class="button-link" href="#feedback" data-interest-link>Register interest</a></p>
            </section>

            {_feedback_form(scan_id=scan_id, submitted=feedback_submitted, sample=sample)}
          </section>

          <script>
            const reportMain = document.querySelector('[data-initial-tab]');
            const tabButtons = Array.from(document.querySelectorAll('[data-report-tab]'));
            const tabPanels = Array.from(document.querySelectorAll('[data-tab-panel]'));
            function setReportTab(tabName) {{
              tabButtons.forEach((button) => {{
                const active = button.dataset.reportTab === tabName;
                button.classList.toggle('is-active', active);
                button.setAttribute('aria-selected', active ? 'true' : 'false');
              }});
              tabPanels.forEach((panel) => {{
                const active = panel.dataset.tabPanel === tabName;
                panel.classList.toggle('is-active', active);
                panel.toggleAttribute('hidden', !active);
              }});
            }}
            tabButtons.forEach((button) => {{
              button.addEventListener('click', () => {{
                setReportTab(button.dataset.reportTab);
                history.replaceState(null, '', '#' + button.dataset.reportTab);
              }});
            }});
            const hashTab = window.location.hash.replace('#', '');
            const startingTab = ['overview', 'priorities', 'findings', 'coverage', 'feedback'].includes(hashTab)
              ? hashTab
              : reportMain.dataset.initialTab || 'overview';
            setReportTab(startingTab);
            if (window.location.hash.startsWith('#finding-') || window.location.hash === '#all-findings') {{
              setReportTab('findings');
            }}
            const interestLink = document.querySelector('[data-interest-link]');
            if (interestLink) {{
              interestLink.addEventListener('click', () => {{
                const interestBox = document.getElementById('private_monitoring_interest');
                if (interestBox) interestBox.checked = true;
                setReportTab('feedback');
              }});
            }}
          </script>
        </main>
        """,
    )


def render_sample_report_page(
    *,
    feedback_submitted: bool = False,
    options: ReportFindingOptions | None = None,
) -> str:
    """Render a static example report without creating a scan record."""

    scan, comparison = sample_report_data()
    return render_repository_report_page(
        scan,
        comparison,
        feedback_submitted=feedback_submitted,
        sample=True,
        options=options,
    )


def sample_report_data() -> tuple[ScanResult, ComparisonSummary]:
    """Generated fixture data for the public beta sample report."""

    completed_at = "2026-07-24T09:01:12+00:00"
    findings: list[dict[str, object]] = [
        {
            "id": "sample-public-s3",
            "scanner": "checkov",
            "rule_id": "CKV_AWS_20",
            "title": "S3 bucket allows public read access",
            "description": "Generated fixture showing public object access in production infrastructure.",
            "severity": "high",
            "category": "storage",
            "file_path": "terraform/production/s3.tf",
            "line_start": 7,
            "resource": "aws_s3_bucket.demo",
            "status": "new",
            "first_seen": "2026-07-24T09:00:00+00:00",
            "last_seen": completed_at,
            "fingerprint": "sample-public-s3",
            "remediation": "Disable public ACLs and enable S3 Block Public Access.",
            "finding_family": "checkov_configuration",
            "directory_group": "production",
        },
        {
            "id": "sample-privileged-pod",
            "scanner": "checkov",
            "rule_id": "CKV_K8S_16",
            "title": "Container runs as privileged",
            "description": "Generated fixture showing a privileged Kubernetes workload in a production path.",
            "severity": "critical",
            "category": "container",
            "file_path": "k8s/production/deployment.yaml",
            "line_start": 22,
            "resource": "Deployment/demo",
            "status": "new",
            "first_seen": "2026-07-24T09:00:00+00:00",
            "last_seen": completed_at,
            "fingerprint": "sample-privileged-pod",
            "remediation": "Disable privileged mode and run with the least required capabilities.",
            "finding_family": "checkov_configuration",
            "directory_group": "production",
        },
    ]
    for index in range(1, 56):
        findings.append(
            {
                "id": f"sample-example-open-sg-{index}",
                "scanner": "checkov",
                "rule_id": "CKV_AWS_260",
                "title": "Example security group allows public ingress",
                "description": "Generated fixture showing a non-production security group open to the internet.",
                "severity": "high",
                "category": "network",
                "file_path": f"examples/demo-infrastructure/team-{index}/security-group.tf",
                "line_start": 14,
                "resource": f"aws_security_group.example_{index}",
                "status": "new",
                "first_seen": "2026-07-24T09:00:00+00:00",
                "last_seen": completed_at,
                "fingerprint": f"sample-example-open-sg-{index}",
                "remediation": "Restrict ingress to the smallest required CIDR range before using this pattern.",
                "finding_family": "checkov_configuration",
                "directory_group": "examples",
            }
        )
    for index in range(1, 8):
        findings.append(
            {
                "id": f"sample-example-vuln-{index}",
                "scanner": "trivy",
                "rule_id": f"CVE-2099-{index:04d}",
                "title": "Generated example dependency vulnerability",
                "description": "Generated fixture showing dependency risk outside production paths.",
                "severity": "medium",
                "category": "vulnerability",
                "file_path": f"examples/services/service-{index}/package-lock.json",
                "line_start": 1,
                "resource": f"demo-package-{index}",
                "status": "new",
                "first_seen": "2026-07-24T09:00:00+00:00",
                "last_seen": completed_at,
                "fingerprint": f"sample-example-vuln-{index}",
                "remediation": "Update the dependency before this example pattern is copied into production code.",
                "finding_family": "trivy_vulnerability",
                "directory_group": "examples",
            }
        )
    supported_files = {
        str(finding.get("file_path"))
        for finding in findings
        if isinstance(finding.get("file_path"), str)
    }
    scan = ScanResult.from_dict(
        {
            "repository": "example/public-infra-demo",
            "branch": "main",
            "commit_sha": "example000000",
            "started_at": "2026-07-24T09:00:00+00:00",
            "completed_at": completed_at,
            "scanner_statuses": {
                "checkov": {
                    "name": "checkov",
                    "status": "success",
                    "message": "Loaded generated Terraform and Kubernetes fixture findings.",
                    "duration_seconds": 18.4,
                },
                "trivy": {
                    "name": "trivy",
                    "status": "success",
                    "message": "Loaded generated container and dependency fixture findings.",
                    "duration_seconds": 21.9,
                },
            },
            "findings": findings,
            "health_score": None,
            "summary": {},
        }
    )
    production_only = production_findings(scan.findings)
    production_counts = severity_counts(production_only)
    production_actionable = _production_score_findings(scan)
    production_score = calculate_health_score(production_only)
    scan.health_score = calculate_health_score(scan.findings)
    scan.summary = {
        "coverage_state": "complete_coverage",
        "production_coverage_state": "complete_coverage",
        "score_reason": "Overall Health calculated from generated scanner fixture findings.",
        "production_health_score": production_score,
        "production_grade": _grade_for_score(production_score),
        "production_grade_provisional": False,
        "production_score_reason": (
            "Production Health is calculated from the two generated findings in production paths."
        ),
        "production_actionable_findings": len(production_actionable),
        "production_critical_findings": production_counts["critical"],
        "production_high_findings": production_counts["high"],
        "production_medium_findings": production_counts["medium"],
        "production_low_findings": production_counts["low"],
        "supported_files_scanned": len(supported_files),
        "affected_supported_files": len(supported_files),
        "finding_source_breakdown": finding_source_breakdown(scan.findings),
        "directory_group_breakdown": directory_group_breakdown(scan.findings),
    }
    comparison = compare_scans(scan, None)
    return scan, comparison


def render_privacy_page() -> str:
    return _page(
        "Beta data and privacy information",
        """
        <main class="narrow">
          <a class="back-link" href="/">Back to DriftBeacon</a>
          <section class="panel">
            <p class="eyebrow">Controlled beta</p>
            <h1>Beta data and privacy information</h1>
            <p>This is practical information for testers, not a professionally reviewed legal
            privacy policy.</p>
            <ul class="plain-list">
              <li>Submitted public GitHub repository URLs are stored with scan metadata.</li>
              <li>Public repository source is cloned temporarily for scanning and deleted after
              the worker finishes.</li>
              <li>Report contents and scan metadata are retained for the configured retention
              period.</li>
              <li>Report links are public to anyone who has the URL.</li>
              <li>Feedback is stored locally to improve the beta. Email is optional and is only
              retained when contact consent is provided.</li>
              <li>Server logs may contain request metadata but DriftBeacon does not intentionally
              store raw IP addresses in beta usage counters.</li>
              <li>Private repository scanning is not supported in this beta.</li>
              <li>DriftBeacon does not sell beta feedback or scan data.</li>
              <li>Contact Rob to request deletion of beta feedback or report data where
              applicable.</li>
            </ul>
          </section>
        </main>
        """,
    )


def render_acceptable_use_page() -> str:
    return _page(
        "Beta acceptable use",
        """
        <main class="narrow">
          <a class="back-link" href="/">Back to DriftBeacon</a>
          <section class="panel">
            <p class="eyebrow">Controlled beta</p>
            <h1>Beta acceptable use</h1>
            <p>These beta terms are intentionally concise and should be professionally reviewed
            before any commercial launch.</p>
            <ul class="plain-list">
              <li>Only submit repositories you are permitted to analyse.</li>
              <li>Do not deliberately abuse the service or attempt to bypass beta limits.</li>
              <li>Do not submit malicious payloads, excessive automated submissions, private
              credentials or tokens.</li>
              <li>Do not treat a DriftBeacon report as a guarantee of security.</li>
              <li>Automated findings can contain false positives and false negatives.</li>
              <li>DriftBeacon is not a substitute for professional security review.</li>
              <li>Availability is not guaranteed during beta testing.</li>
            </ul>
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


def report_finding_options_from_environ(environ: WSGIEnvironment) -> ReportFindingOptions:
    values = parse_qs(str(environ.get("QUERY_STRING") or ""), keep_blank_values=True)
    return ReportFindingOptions(
        view=_query_choice(values, "view", {"", "all"}),
        severity=_query_choice(values, "severity", {"", *ACTIONABLE_SEVERITIES}),
        production=_query_choice(values, "production", {"", "production", "other"}),
        scanner=_query_text(values, "scanner"),
        category=_query_text(values, "category"),
        path_type=_query_text(values, "path_type"),
        status=_query_choice(values, "status", {"", "new", "recurring", "resolved"}),
        sort=_query_choice(values, "sort", {"recommended", "severity", "production", "path"})
        or "recommended",
        page=max(1, _query_int(values, "page", 1)),
    )


def build_report_finding_page(
    scan: ScanResult,
    options: ReportFindingOptions,
    *,
    page_size: int = 50,
) -> ReportFindingPage:
    raw_active_actionable = [
        finding
        for finding in deduplicate_findings_by_fingerprint(scan.findings)
        if finding.status != "resolved" and finding.severity in ACTIONABLE_SEVERITIES
    ]
    duplicate_counts = _duplicate_counts(scan.findings)
    prioritised = prioritise_findings(raw_active_actionable, limit=max(1, len(raw_active_actionable)))
    views = [
        ReportFindingView(
            finding=item.finding,
            priority=item,
            rank=index,
            anchor=_finding_anchor(item.finding),
            duplicate_count=duplicate_counts.get(item.finding.fingerprint, 1),
        )
        for index, item in enumerate(prioritised, start=1)
    ]
    filtered = _filter_finding_views(views, options)
    sorted_views = _sort_finding_views(filtered, options.sort)
    total_pages = max(1, (len(sorted_views) + page_size - 1) // page_size)
    page = min(max(1, options.page), total_pages)
    start = (page - 1) * page_size
    page_options = ReportFindingOptions(
        view=options.view,
        severity=options.severity,
        production=options.production,
        scanner=options.scanner,
        category=options.category,
        path_type=options.path_type,
        status=options.status,
        sort=options.sort,
        page=page,
    )
    return ReportFindingPage(
        all_findings=views,
        filtered_findings=sorted_views,
        page_findings=sorted_views[start : start + page_size],
        options=page_options,
        total_count=len(views),
        filtered_count=len(sorted_views),
        page_count=page,
        total_pages=total_pages,
        has_more_than_top_three=len(views) > 3,
    )


def _priority_card(
    index: int,
    view: ReportFindingView,
    has_baseline: bool,
    *,
    report_path: str,
) -> str:
    details = prioritised_finding_details(view.priority, has_baseline=has_baseline)
    production_relevance = (
        "Production path" if details["directory_group"] == "production" else details["directory_group"]
    )
    finding_url = _finding_url(report_path, view.anchor)
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
        <div><dt>Priority position</dt><dd>{_escape(view.rank)} of {_escape("all deduplicated active actionable findings")}</dd></div>
      </dl>
      <p><strong>Why this is prioritised:</strong> {_escape(details["why"])}</p>
      <p><strong>Recommended action:</strong> {_escape(details["action"])}</p>
      <p><a class="text-link" href="{_escape(finding_url)}">View full finding</a></p>
      <p class="unavailable">Estimated effort, projected risk reduction, projected Production
      Health and related findings resolved are unavailable until impact simulation is implemented.</p>
    </article>
    """


def _all_findings_section(page: ReportFindingPage, report_path: str) -> str:
    if page.total_count == 0:
        return """
        <section id="all-findings" class="report-section">
          <h2>All findings</h2>
          <p class="empty">No deduplicated active actionable findings were available to explore.</p>
        </section>
        """
    rows = "\n".join(
        _finding_detail(view, page.options.sort == "recommended")
        for view in page.page_findings
    )
    expanded = page.options.view == "all"
    intro = (
        f"Showing {page.filtered_count} filtered results from {page.total_count} deduplicated active actionable findings."
        if page.filtered_count != page.total_count
        else f"Showing {page.total_count} deduplicated active actionable findings."
    )
    full_url = _findings_page_url(report_path, page.options, 1, force_expanded=True)
    explorer_note = (
        '<p class="count-note">Expanded findings explorer. Use filters and page numbers to move through the full deduplicated finding set.</p>'
        if expanded
        else (
            '<p class="count-note">Compact preview: this report page shows shorter finding pages. '
            f'<a class="text-link" href="{_escape(full_url)}" target="_blank" rel="noopener">Open the full findings explorer</a> in a new tab for the longer list.</p>'
        )
    )
    section_class = "report-section all-findings expanded-findings" if expanded else "report-section all-findings compact-findings"
    return f"""
    <section id="all-findings" class="{section_class}">
      <h2>All findings {_help_bubble("Actionable findings", "Deduplicated active findings with critical, high, medium or low severity. Info and unknown-severity findings remain available in data exports but do not reduce the health score.")}</h2>
      <p class="count-note">{_escape(intro)} This count excludes resolved findings and info or unknown severity findings. Duplicate fingerprints are shown once.</p>
      {explorer_note}
      {_finding_filter_form(page, report_path)}
      <div class="finding-results" aria-live="polite">
        <p class="count-note">Page {page.page_count} of {page.total_pages}. Default order matches DriftBeacon's deterministic prioritisation logic.</p>
        {rows or '<p class="empty">No findings match the selected filters.</p>'}
      </div>
      {_pagination(page, report_path)}
      <script>
        function openTargetFinding() {{
          if (!window.location.hash) return;
          const target = document.querySelector(window.location.hash);
          if (target && target.tagName.toLowerCase() === 'details') {{
            target.open = true;
            target.classList.add('targeted');
          }}
        }}
        window.addEventListener('hashchange', openTargetFinding);
        openTargetFinding();
      </script>
    </section>
    """


def _finding_detail(view: ReportFindingView, recommended_sort: bool) -> str:
    finding = view.finding
    details = prioritised_finding_details(view.priority, has_baseline=False)
    location = _finding_location(finding)
    priority_text = (
        f"Priority {view.rank}"
        if recommended_sort
        else f"Priority rank {view.rank} in recommended order"
    )
    duplicate_note = (
        f"<li>Related duplicate findings: {view.duplicate_count} normalised findings shared this fingerprint.</li>"
        if view.duplicate_count > 1
        else "<li>Related duplicate findings: none collapsed for this fingerprint.</li>"
    )
    remediation = finding.remediation or "Review the scanner rule, confirm whether the affected configuration is used, and reduce the risky configuration where applicable."
    return f"""
    <details id="{_escape(view.anchor)}" class="finding-detail">
      <summary>
        <span class="finding-title">{_escape(finding.title)}</span>
        <span class="badge severity-{_escape(finding.severity)}">{_escape(finding.severity.capitalize())}</span>
        <span class="badge">{_escape(_production_relevance_label(finding))}</span>
        <span class="finding-path">{_escape(location)}</span>
      </summary>
      <div class="finding-body">
        <dl class="finding-meta">
          <div><dt>Priority position</dt><dd>{_escape(priority_text)}</dd></div>
          <div><dt>Scanner source</dt><dd>{_escape(finding.scanner)}</dd></div>
          <div><dt>Scanner identifier</dt><dd>{_escape(finding.rule_id)}</dd></div>
          <div><dt>Category</dt><dd>{_escape(finding.category)}</dd></div>
          <div><dt>Status</dt><dd>{_escape(finding.status)}</dd></div>
          <div><dt>Path type</dt><dd>{_escape(_path_type(finding))}</dd></div>
        </dl>
        <h3>What was found</h3>
        <p>{_escape(finding.description or finding.title)}</p>
        <h3>Why DriftBeacon prioritised it</h3>
        <ul class="plain-list">
          <li>Severity: {_escape(finding.severity.capitalize())}</li>
          <li>Production relevance: {_escape(_production_relevance_label(finding))}</li>
          <li>Found in: {_escape(location)}</li>
          <li>Scanner evidence: {_escape(finding.title)}</li>
          <li>Priority rule explanation: {_escape(view.priority.reason)}</li>
        </ul>
        <h3>Why this matters</h3>
        <p>{_escape(details["why"])}</p>
        <h3>Recommended action</h3>
        <p>{_escape(remediation)}</p>
        <details class="technical-details">
          <summary>Technical details</summary>
          <ul class="plain-list">
            <li>Affected file: {_escape(finding.file_path or "not reported")}</li>
            <li>Line: {_escape(finding.line_start if finding.line_start is not None else "not reported")}</li>
            <li>Resource: {_escape(finding.resource or "not reported")}</li>
            <li>Fingerprint: {_escape(finding.fingerprint)}</li>
            {duplicate_note}
          </ul>
        </details>
        <p class="unavailable">Limitations: DriftBeacon uses static scanner output and path classification. Confirm whether this configuration is actually deployed before treating it as production risk.</p>
      </div>
    </details>
    """


def _help_bubble(label: str, text: str) -> str:
    safe_label = _escape(label)
    return f"""
    <span class="help-popover">
      <button type="button" class="help-trigger" aria-label="{safe_label}: explanation">?</button>
      <span class="help-bubble" role="tooltip"><strong>{safe_label}</strong>{_escape(text)}</span>
    </span>
    """


def _score_breakdown(title: str, counts: Mapping[str, int]) -> str:
    return f"""
    <div class="score-breakdown" aria-label="{_escape(title)}">
      <h3>{_escape(title)}</h3>
      <ul>
        <li><strong>{_escape(counts.get("critical", 0))}</strong><span>Critical</span></li>
        <li><strong>{_escape(counts.get("high", 0))}</strong><span>High</span></li>
        <li><strong>{_escape(counts.get("medium", 0))}</strong><span>Medium</span></li>
        <li><strong>{_escape(counts.get("low", 0))}</strong><span>Low</span></li>
      </ul>
    </div>
    """


def _score_calculation_disclosure(score_type: str) -> str:
    included = (
        "deduplicated active critical, high, medium and low findings in paths classified as production"
        if score_type == "production"
        else "deduplicated active critical, high, medium and low findings included in scoring across the scanned repository"
    )
    return f"""
    <details class="explanation">
      <summary>How this score is calculated</summary>
      <p>The score uses {included}. Critical findings weigh more than high, medium and low findings. Informational and unknown-severity findings do not reduce the score. Duplicate fingerprints are counted once. Scanner coverage affects whether the grade is marked provisional.</p>
      <p>The score is a prioritisation signal, not a guarantee that the repository or production environment is secure.</p>
    </details>
    """


def _score_divergence_callout(scan: ScanResult, *, threshold: int = 20) -> str:
    production_score = _optional_int(scan.summary.get("production_health_score"))
    overall_score = scan.health_score
    if production_score is None or overall_score is None:
        return ""
    difference = abs(production_score - overall_score)
    if difference < threshold:
        return ""
    production_count = len(_production_score_findings(scan))
    overall_count = len(_overall_score_findings(scan))
    other_count = max(0, overall_count - production_count)
    if production_score > overall_score:
        explanation = (
            f"Production Health is {production_score}/100 because the files classified as production-relevant contain {production_count} included actionable findings. "
            f"Overall Health is {overall_score}/100 because the wider repository contains {other_count} included actionable findings outside those production-relevant paths."
        )
    else:
        explanation = (
            f"Production Health is {production_score}/100 while Overall Health is {overall_score}/100 because production-relevant paths contain a higher concentration or severity of included findings than the wider repository."
        )
    return f"""
    <section class="report-section divergence-callout" aria-labelledby="score-divergence-heading">
      <h2 id="score-divergence-heading">Why are these scores so different?</h2>
      <p>{_escape(explanation)}</p>
      <dl class="compact-stats">
        <div><dt>Production-relevant included findings</dt><dd>{production_count}</dd></div>
        <div><dt>Other included findings</dt><dd>{other_count}</dd></div>
        <div><dt>Score difference</dt><dd>{difference} points</dd></div>
      </dl>
      <p>This does not mean the additional findings should be ignored. It means DriftBeacon is separating likely production risk from broader repository hygiene.</p>
    </section>
    """


def _scanner_coverage_section(scan: ScanResult) -> str:
    scanner_rows = "\n".join(
        f"<li><strong>{_escape(status.name.capitalize())}:</strong> {_escape(status.status.replace('_', ' ').capitalize())}. {_escape(status.message)}</li>"
        for status in scan.scanner_statuses.values()
    ) or "<li>No scanner status was recorded.</li>"
    summary = scan.summary
    supported_files = summary.get("supported_files_scanned")
    coverage = _coverage_text(summary)
    source_rows = _breakdown_rows(summary.get("finding_source_breakdown"))
    group_rows = _breakdown_rows(summary.get("directory_group_breakdown"))
    supported_text = (
        f"{supported_files} supported files were scanned."
        if isinstance(supported_files, int)
        else "Supported-file count was not recorded for this report."
    )
    return f"""
    <section class="report-section evidence" aria-labelledby="scanner-coverage-heading">
      <h2 id="scanner-coverage-heading">Scanner coverage {_help_bubble("Scanner coverage", "Shows which configured scanners completed for supported file types. Partial or failed coverage means findings and scores may be incomplete.")}</h2>
      <p>{_escape(coverage)} for supported file types. {_escape(supported_text)} DriftBeacon performs static analysis only and does not execute the submitted application.</p>
      <div class="evidence-grid">
        <article>
          <h3>Scanner status</h3>
          <ul>{scanner_rows}</ul>
        </article>
        <article>
          <h3>Finding source breakdown</h3>
          {_table(source_rows, "Source")}
        </article>
        <article>
          <h3>Path classification breakdown</h3>
          {_table(group_rows, "Path type")}
        </article>
      </div>
    </section>
    """


def _report_glossary() -> str:
    definitions = [
        ("definition-production-health", "Production Health", "A 0 to 100 prioritisation score calculated from deduplicated active actionable findings in paths DriftBeacon classifies as production-relevant or likely production-related."),
        ("definition-overall-health", "Overall Health", "A 0 to 100 score calculated from included deduplicated active actionable findings across the scanned repository."),
        ("definition-top-priorities", "Top priorities", "The highest-ranked findings according to DriftBeacon's deterministic prioritisation rules. The ranking considers severity, lifecycle status, production-like paths, category, blast-radius indicators, recurrence and whether remediation guidance exists."),
        ("definition-actionable-findings", "Actionable findings", "Deduplicated active findings with critical, high, medium or low severity. Info and unknown-severity findings are retained for auditability but are not included in health scoring."),
        ("definition-production-relevance", "Production relevance", "A static path classification signal. It means the finding appears in a path that looks production-related; it does not prove the resource is deployed."),
        ("definition-scanner-coverage", "Scanner coverage", "Which configured scanners completed for supported file types. Partial or failed coverage means findings and scores may be incomplete."),
        ("definition-severity", "Severity", "The severity reported or normalised from scanner output. Critical findings reduce health more than high, medium and low findings."),
        ("definition-limitations", "Limitations", "DriftBeacon uses static analysis and scanner output. Reports can contain false positives and false negatives and are not a substitute for security review."),
    ]
    body = "\n".join(
        f"""
        <details id="{anchor}" class="glossary-item">
          <summary>{_escape(term)}</summary>
          <p>{_escape(text)}</p>
        </details>
        """
        for anchor, term, text in definitions
    )
    return f"""
    <section class="report-section glossary" aria-labelledby="report-glossary-heading">
      <h2 id="report-glossary-heading">How to read this report</h2>
      <p>Use these definitions when interpreting scores, priorities and scanner coverage.</p>
      {body}
    </section>
    """


def _query_choice(values: dict[str, list[str]], key: str, allowed: set[str]) -> str:
    candidate = (values.get(key) or [""])[0].strip().lower()
    return candidate if candidate in allowed else ""


def _query_text(values: dict[str, list[str]], key: str) -> str:
    candidate = (values.get(key) or [""])[0].strip().lower()
    if len(candidate) > 80:
        return ""
    if not re.fullmatch(r"[a-z0-9_.:-]*", candidate):
        return ""
    return candidate


def _query_int(values: dict[str, list[str]], key: str, default: int) -> int:
    candidate = (values.get(key) or [""])[0].strip()
    if not candidate:
        return default
    with suppress(ValueError):
        return int(candidate)
    return default


def _duplicate_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.fingerprint] = counts.get(finding.fingerprint, 0) + 1
    return counts


def _finding_anchor(finding: Finding) -> str:
    seed = finding.fingerprint or f"{finding.id}:{finding.rule_id}:{finding.file_path}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"finding-{digest}"


def _filter_finding_views(
    views: list[ReportFindingView],
    options: ReportFindingOptions,
) -> list[ReportFindingView]:
    filtered: list[ReportFindingView] = []
    for view in views:
        finding = view.finding
        path_type = _path_type(finding).lower()
        if options.severity and finding.severity != options.severity:
            continue
        if options.production == "production" and path_type != "production":
            continue
        if options.production == "other" and path_type == "production":
            continue
        if options.scanner and finding.scanner.lower() != options.scanner:
            continue
        if options.category and finding.category.lower() != options.category:
            continue
        if options.path_type and path_type != options.path_type:
            continue
        if options.status and finding.status != options.status:
            continue
        filtered.append(view)
    return filtered


def _sort_finding_views(
    views: list[ReportFindingView],
    sort: str,
) -> list[ReportFindingView]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if sort == "severity":
        return sorted(
            views,
            key=lambda view: (
                severity_order.get(view.finding.severity, 99),
                view.rank,
                _finding_location(view.finding).lower(),
            ),
        )
    if sort == "production":
        return sorted(
            views,
            key=lambda view: (
                0 if _path_type(view.finding) == "production" else 1,
                severity_order.get(view.finding.severity, 99),
                view.rank,
            ),
        )
    if sort == "path":
        return sorted(
            views,
            key=lambda view: (_finding_location(view.finding).lower(), view.rank),
        )
    return list(views)


def _finding_url(report_path: str, anchor: str) -> str:
    query = urlencode({"view": "all", "sort": "recommended", "page": "1"})
    base = report_path or ""
    return f"{base}?{query}#{anchor}"


def _finding_location(finding: Finding) -> str:
    location = finding.file_path or "path not reported"
    if finding.line_start is not None:
        return f"{location}:{finding.line_start}"
    return location


def _production_relevance_label(finding: Finding) -> str:
    path_type = _path_type(finding)
    if path_type == "production":
        return "Production path"
    if path_type == "unknown":
        return "Unknown path type"
    return f"Non-production path ({path_type.replace('_', ' ')})"


def _path_type(finding: Finding) -> str:
    return finding.directory_group or classify_path_group(finding.file_path)


def _top_priority_summary(page: ReportFindingPage, report_path: str) -> str:
    if page.total_count == 0:
        return "No active actionable findings are available to prioritise."
    if page.has_more_than_top_three:
        full_url = _findings_page_url(report_path, page.options, 1, force_expanded=True)
        return (
            f"Top priorities show 3 of {page.total_count}. "
            f'<a class="text-link" href="{_escape(full_url)}" target="_blank" rel="noopener">View all {page.total_count} '
            "deduplicated active actionable findings</a> in a separate tab."
        )
    return f"All {page.total_count} deduplicated active actionable findings are shown here."


def _finding_filter_form(page: ReportFindingPage, report_path: str) -> str:
    options = page.options
    scanner_values = sorted({view.finding.scanner.lower() for view in page.all_findings})
    category_values = sorted({view.finding.category.lower() for view in page.all_findings})
    path_values = sorted({_path_type(view.finding).lower() for view in page.all_findings})
    action = f"{report_path}#all-findings" if report_path else "#all-findings"
    view_input = '<input type="hidden" name="view" value="all">' if options.view == "all" else ""
    clear_target = _findings_page_url(report_path, options, 1, clear_filters=True)
    return f"""
    <form class="finding-filters" method="get" action="{_escape(action)}" aria-label="Filter findings">
      {view_input}
      <label for="filter-severity">Severity
        <select id="filter-severity" name="severity">
          {_select_options((("", "All severities"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")), options.severity)}
        </select>
      </label>
      <label for="filter-production">Production relevance
        <select id="filter-production" name="production">
          {_select_options((("", "All paths"), ("production", "Production paths"), ("other", "Non-production and unknown paths")), options.production)}
        </select>
      </label>
      <label for="filter-scanner">Scanner
        <select id="filter-scanner" name="scanner">
          {_select_options((("", "All scanners"), *[(value, value) for value in scanner_values]), options.scanner)}
        </select>
      </label>
      <label for="filter-category">Category
        <select id="filter-category" name="category">
          {_select_options((("", "All categories"), *[(value, value.replace("_", " ").title()) for value in category_values]), options.category)}
        </select>
      </label>
      <label for="filter-path-type">Path type
        <select id="filter-path-type" name="path_type">
          {_select_options((("", "All path types"), *[(value, value.replace("_", " ").title()) for value in path_values]), options.path_type)}
        </select>
      </label>
      <label for="filter-status">Status
        <select id="filter-status" name="status">
          {_select_options((("", "All statuses"), ("new", "New"), ("recurring", "Recurring"), ("resolved", "Resolved")), options.status)}
        </select>
      </label>
      <label for="filter-sort">Sort
        <select id="filter-sort" name="sort">
          {_select_options((("recommended", "Recommended"), ("severity", "Severity"), ("production", "Production first"), ("path", "Path")), options.sort)}
        </select>
      </label>
      <div class="filter-actions">
        <button type="submit">Apply filters</button>
        <a class="button-link secondary" href="{_escape(clear_target)}">Clear</a>
      </div>
    </form>
    """


def _select_options(values: tuple[tuple[str, str], ...], selected: str) -> str:
    return "\n".join(
        f'<option value="{_escape(value)}"{" selected" if value == selected else ""}>{_escape(label)}</option>'
        for value, label in values
    )


def _pagination(page: ReportFindingPage, report_path: str) -> str:
    if page.total_pages <= 1:
        return ""
    page_links = "\n".join(
        _pagination_link(page, report_path, page_number)
        for page_number in _pagination_page_numbers(page.page_count, page.total_pages)
    )
    previous_link = (
        f'<a class="button-link secondary" href="{_escape(_findings_page_url(report_path, page.options, page.page_count - 1))}">Previous</a>'
        if page.page_count > 1
        else '<span class="pagination-disabled">Previous</span>'
    )
    next_link = (
        f'<a class="button-link secondary" href="{_escape(_findings_page_url(report_path, page.options, page.page_count + 1))}">Next</a>'
        if page.page_count < page.total_pages
        else '<span class="pagination-disabled">Next</span>'
    )
    return f"""
    <nav class="pagination" aria-label="Finding pages">
      {previous_link}
      <span>Page {page.page_count} of {page.total_pages}</span>
      <span class="page-links">{page_links}</span>
      {next_link}
    </nav>
    """


def _pagination_link(page: ReportFindingPage, report_path: str, page_number: int | None) -> str:
    if page_number is None:
        return '<span class="page-ellipsis" aria-hidden="true">...</span>'
    if page_number == page.page_count:
        return f'<span class="page-current" aria-current="page">{page_number}</span>'
    return (
        f'<a class="page-number" href="{_escape(_findings_page_url(report_path, page.options, page_number))}">'
        f"{page_number}</a>"
    )


def _pagination_page_numbers(current: int, total: int) -> list[int | None]:
    if total <= 9:
        return list(range(1, total + 1))
    numbers: list[int | None] = [1]
    start = max(2, current - 2)
    end = min(total - 1, current + 2)
    if start > 2:
        numbers.append(None)
    numbers.extend(range(start, end + 1))
    if end < total - 1:
        numbers.append(None)
    numbers.append(total)
    return numbers


def _findings_page_url(
    report_path: str,
    options: ReportFindingOptions,
    page_number: int,
    *,
    force_expanded: bool = False,
    clear_filters: bool = False,
) -> str:
    query: dict[str, str] = {}
    view = "all" if force_expanded else options.view
    if view:
        query["view"] = view
    if options.severity and not clear_filters:
        query["severity"] = options.severity
    if options.production and not clear_filters:
        query["production"] = options.production
    if options.scanner and not clear_filters:
        query["scanner"] = options.scanner
    if options.category and not clear_filters:
        query["category"] = options.category
    if options.path_type and not clear_filters:
        query["path_type"] = options.path_type
    if options.status and not clear_filters:
        query["status"] = options.status
    if options.sort and options.sort != "recommended" and not clear_filters:
        query["sort"] = options.sort
    if page_number > 1:
        query["page"] = str(page_number)
    base = report_path or ""
    encoded = urlencode(query)
    return f"{base}?{encoded}#all-findings" if encoded else f"{base}#all-findings"


def _production_severity_counts(scan: ScanResult) -> dict[str, int]:
    return _severity_counts_for_report(production_findings(scan.findings))


def _severity_counts_for_report(findings: list[Finding]) -> dict[str, int]:
    counts = severity_counts(findings)
    return {
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
    }


def _production_score_findings(scan: ScanResult) -> list[Finding]:
    return [
        finding
        for finding in deduplicate_findings_by_fingerprint(production_findings(scan.findings))
        if finding.status != "resolved"
        and finding.severity in ACTIONABLE_SEVERITIES
        and not finding.excluded_from_score
    ]


def _overall_score_findings(scan: ScanResult) -> list[Finding]:
    return [
        finding
        for finding in deduplicate_findings_by_fingerprint(scan.findings)
        if finding.status != "resolved"
        and finding.severity in ACTIONABLE_SEVERITIES
        and not finding.excluded_from_score
    ]


def _report_actions(state: WebScanState | None) -> str:
    if state is None or state.status != "completed":
        return ""
    return f"""
    <div class="report-actions">
      <button type="button" data-copy-report>Copy report link</button>
      <span class="copy-status" aria-live="polite" data-copy-status></span>
      <a class="button-link" href="/scans/{state.scan_id}/report.md">Download Markdown</a>
      <a class="button-link secondary" href="/scans/{state.scan_id}/report.json">Download JSON</a>
    </div>
    <script>
      const copyButton = document.querySelector('[data-copy-report]');
      const copyStatus = document.querySelector('[data-copy-status]');
      if (copyButton) {{
        copyButton.addEventListener('click', async () => {{
          await navigator.clipboard.writeText(window.location.href);
          copyButton.textContent = 'Copied';
          if (copyStatus) copyStatus.textContent = 'Report link copied.';
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


def _feedback_form(
    *,
    scan_id: str | None,
    submitted: bool,
    sample: bool,
) -> str:
    thanks = (
        '<div class="notice" role="status"><strong>Thanks.</strong> Your beta feedback was recorded.</div>'
        if submitted
        else ""
    )
    scan_input = (
        f'<input type="hidden" name="scan_id" value="{_escape(scan_id)}">'
        if scan_id is not None
        else ""
    )
    context = (
        "This feedback is for the example report."
        if sample
        else "This feedback is linked to this scan report."
    )
    return f"""
    <section id="feedback" class="feedback-section">
      <h2>Did this report help you decide what to fix?</h2>
      <p class="unavailable">{_escape(context)}</p>
      {thanks}
      <form method="post" action="/feedback" class="feedback-form">
        {scan_input}
        <div class="honeypot" aria-hidden="true">
          <label for="website">Website</label>
          <input id="website" name="website" type="text" tabindex="-1" autocomplete="off">
        </div>
        <fieldset>
          <legend>Was the report helpful?</legend>
          <label><input type="radio" name="helpfulness" value="yes" required> Yes</label>
          <label><input type="radio" name="helpfulness" value="partly"> Partly</label>
          <label><input type="radio" name="helpfulness" value="no"> No</label>
        </fieldset>
        <fieldset>
          <legend>Would this change what you worked on?</legend>
          <label><input type="radio" name="changed_priority" value="yes" required> Yes</label>
          <label><input type="radio" name="changed_priority" value="maybe"> Maybe</label>
          <label><input type="radio" name="changed_priority" value="no"> No</label>
        </fieldset>
        <label for="difficult_to_understand">What was hardest to understand?</label>
        <select id="difficult_to_understand" name="difficult_to_understand">
          <option value="">Nothing specific</option>
          <option value="production_health">Production Health</option>
          <option value="overall_health">Overall Health</option>
          <option value="score_difference">Why the scores differed</option>
          <option value="top_priorities">Top priorities</option>
          <option value="finding_explanations">Finding explanations</option>
          <option value="scanner_coverage">Scanner coverage</option>
          <option value="other">Something else</option>
        </select>
        <label for="comment">What was useful, confusing or missing?</label>
        <textarea id="comment" name="comment" maxlength="2000" rows="4"></textarea>
        <label class="check-row">
          <input id="private_monitoring_interest" type="checkbox" name="private_monitoring_interest" value="yes">
          I am interested in continuous monitoring for private repositories.
        </label>
        <label for="email">Email address, optional</label>
        <input id="email" name="email" type="email" maxlength="320" autocomplete="email">
        <label class="check-row">
          <input type="checkbox" name="consent_to_contact" value="yes">
          DriftBeacon may contact me about this beta.
        </label>
        <p class="unavailable">Feedback is stored to help improve the DriftBeacon beta. Your email
        is optional and will only be used to contact you about DriftBeacon if you provide consent.
        See <a class="text-link" href="/privacy">beta data and privacy information</a>.</p>
        <button type="submit">Send feedback</button>
      </form>
    </section>
    """


def _finding_state_notice(scan: ScanResult) -> str:
    summary = scan.summary
    coverage = str(summary.get("production_coverage_state") or summary.get("coverage_state", ""))
    if coverage == "not_scored_no_supported_files":
        return (
            '<div class="notice" role="status"><strong>No eligible scan targets were found.</strong> '
            "DriftBeacon did not find supported infrastructure or dependency files in this "
            "repository, so a meaningful Production Health score could not be calculated.</div>"
        )
    if coverage == "not_scored_all_scanners_failed":
        return (
            '<div class="alert" role="alert"><strong>Scanner coverage failed.</strong> '
            "A meaningful Production Health score could not be calculated because all applicable "
            "scanners failed.</div>"
        )
    if coverage == "partial_coverage":
        return (
            '<div class="notice" role="status"><strong>Partial scanner coverage.</strong> '
            "The score is provisional because at least one applicable scanner did not complete.</div>"
        )
    if scan.health_score is not None and not _web_priority_candidates(scan.findings):
        return (
            '<div class="notice" role="status"><strong>No active findings were detected.</strong> '
            "This means completed scanners did not report actionable findings in the analysed "
            "targets; it does not prove the repository is secure.</div>"
        )
    return ""


def _empty_findings_text(scan: ScanResult) -> str:
    coverage = str(
        scan.summary.get("production_coverage_state") or scan.summary.get("coverage_state", "")
    )
    if coverage == "not_scored_no_supported_files":
        return "No eligible scan targets were found."
    if coverage == "not_scored_all_scanners_failed":
        return "No prioritised findings are available because scanner coverage failed."
    if scan.health_score is None:
        return "No prioritised findings are available because this repository was not scored."
    return "No active findings were detected by completed scanners."


def _stage_label(state: WebScanState) -> str:
    labels = {
        "queued": "Queued",
        "cloning": "Cloning repository and checking repository limits",
        "analysing": "Analysing infrastructure and dependencies",
        "generating_report": "Preparing prioritised report",
        "completed": "Completed",
        "failed": "Failed safely",
        "expired": "Expired",
    }
    return labels.get(state.status, state.message)


def _progress_steps(status: str) -> str:
    steps = [
        ("queued", "Queued"),
        ("cloning", "Cloning repository"),
        ("analysing", "Checking repository limits and analysing findings"),
        ("generating_report", "Preparing prioritised report"),
        ("completed", "Completed"),
    ]
    order = {key: index for index, (key, _label) in enumerate(steps)}
    current = order.get(status, len(steps) - 1 if status == "completed" else 0)
    items = []
    for index, (key, label) in enumerate(steps):
        state = "complete" if index < current else "current" if index == current else "waiting"
        if status == "failed" and index == current:
            state = "failed"
        items.append(
            f'<li class="{state}" data-step-key="{_escape(key)}">'
            f"<span>{_escape(label)}</span><small>{_escape(state)}</small></li>"
        )
    return "\n".join(items)


def _safe_failure_message(state: WebScanState) -> str:
    messages = {
        "repository_not_found": "This repository could not be cloned. Confirm it is public and exists.",
        "repository_private": "This repository could not be cloned. Confirm it is public and exists.",
        "repository_too_large": "This repository exceeds the size limit for the public beta.",
        "repository_file_limit_exceeded": "This repository exceeds the file-count limit for the public beta.",
        "clone_timeout": "Git clone exceeded the public beta time limit.",
        "scan_timeout": "This scan exceeded the public beta time limit.",
        "scanner_failure": "Scan failed. Please try again with a smaller public repository.",
        "report_generation_failed": "The scan completed, but DriftBeacon could not store the report.",
        "scan_interrupted": "The scan was interrupted before completion.",
    }
    if state.error_code in messages:
        return messages[state.error_code]
    if state.status == "failed":
        return "Scan failed. Please try again with a smaller public repository."
    return state.safe_error_message or state.message


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
    description = "DriftBeacon prioritises public repository findings by Production Health."
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{_escape(description)}">
  <meta property="og:title" content="{_escape(title)} - DriftBeacon">
  <meta property="og:description" content="{_escape(description)}">
  <title>{_escape(title)} - DriftBeacon</title>
  <script>
    (function() {{
      try {{
        const stored = localStorage.getItem('driftbeacon-theme');
        const theme = stored || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
        document.documentElement.dataset.theme = theme;
      }} catch (_error) {{
        document.documentElement.dataset.theme = 'light';
      }}
    }})();
  </script>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23176b56'/%3E%3Cpath d='M8 21h16l-8-12z' fill='white'/%3E%3C/svg%3E">
  <style>{_css()}</style>
</head>
<body>
  <header class="site-header">
    <a href="/">DriftBeacon</a>
    <div class="header-actions">
      <span>Production Health reports</span>
      <button type="button" class="theme-toggle" data-theme-toggle aria-label="Switch colour theme">
        <span data-theme-label>Theme</span>
      </button>
    </div>
  </header>
  {body}
  <footer class="site-footer">
    <a href="/sample-report">Example report</a>
    <a href="/privacy">Beta data and privacy</a>
    <a href="/acceptable-use">Acceptable use</a>
  </footer>
  <script>
    (function() {{
      const button = document.querySelector('[data-theme-toggle]');
      const label = document.querySelector('[data-theme-label]');
      function applyTheme(theme) {{
        document.documentElement.dataset.theme = theme;
        if (label) label.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
        if (button) button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      }}
      applyTheme(document.documentElement.dataset.theme || 'light');
      if (button) {{
        button.addEventListener('click', () => {{
          const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
          try {{ localStorage.setItem('driftbeacon-theme', next); }} catch (_error) {{}}
          applyTheme(next);
        }});
      }}
    }})();
  </script>
</body>
</html>
"""


def _css() -> str:
    return """
    :root { color-scheme: light; --ink:#17201a; --muted:#5a675f; --line:#d8dfd9;
      --paper:#f8faf7; --panel:#ffffff; --accent:#176b56; --accent-2:#b04428;
      --soft:#edf4ef; --warning:#fff7eb; --warning-line:#f1c77c; --focus:#f1b24a; }
    :root[data-theme="dark"] { color-scheme: dark; --ink:#edf4ef; --muted:#a9b8ad; --line:#334239;
      --paper:#111713; --panel:#19221d; --accent:#78d1b7; --accent-2:#f1a17d;
      --soft:#223229; --warning:#2d2618; --warning-line:#7b6330; --focus:#f3c465; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color:var(--ink); background:var(--paper); line-height:1.5; }
    .site-header { display:flex; justify-content:space-between; align-items:center; padding:18px clamp(18px,4vw,48px);
      border-bottom:1px solid var(--line); background:var(--panel); gap:16px; }
    .site-header a, .text-link { color:var(--accent); text-decoration-thickness:2px; text-underline-offset:3px; font-weight:800; }
    .site-header a { color:var(--ink); text-decoration:none; }
    .site-header span, .eyebrow, dt { color:var(--muted); font-size:0.86rem; }
    .header-actions { display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:flex-end; }
    main { max-width:1120px; margin:0 auto; padding:34px clamp(18px,4vw,48px) 64px; }
    .narrow { max-width:760px; }
    .hero { padding:52px 0 38px; max-width:850px; }
    h1 { font-size:clamp(2.2rem,5vw,4.7rem); line-height:1; margin:10px 0 18px; letter-spacing:0; }
    h2 { font-size:1.55rem; margin:0 0 14px; }
    h3 { margin:0 0 12px; font-size:1.08rem; }
    p, li, th, td, summary, h1, h2, h3 { overflow-wrap:anywhere; }
    .lead { font-size:1.2rem; max-width:760px; color:#2d3a33; }
    .scan-form { margin-top:28px; }
    label, legend { display:block; font-weight:700; margin-bottom:8px; }
    .form-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:10px; max-width:760px; }
    .access-row { margin-top:14px; max-width:360px; }
    input, textarea, select { width:100%; min-height:46px; border:1px solid var(--line); border-radius:8px; padding:0 14px; font:inherit; background:var(--panel); color:var(--ink); }
    textarea { padding:12px 14px; resize:vertical; }
    button, .button-link { min-height:46px; border:0; border-radius:8px; padding:0 18px; font-weight:800; color:#fff; background:var(--accent); cursor:pointer; display:inline-flex; align-items:center; text-decoration:none; }
    button:disabled, input:disabled { opacity:0.62; cursor:not-allowed; }
    button:focus-visible, input:focus-visible, textarea:focus-visible, a:focus-visible {
      outline:3px solid var(--focus); outline-offset:3px;
    }
    .button-link.secondary { background:#2d3a33; color:#fff; }
    .theme-toggle { min-height:34px; padding:0 12px; background:transparent; color:var(--ink); border:1px solid var(--line); }
    .report-actions { display:flex; flex-wrap:wrap; gap:10px; margin:16px 0; }
    .retention-note, .notice { border:1px solid var(--line); border-radius:8px; padding:12px; background:var(--panel); color:var(--muted); }
    .band, .split, .methodology-note, .panel, .report-status, .report-section, .health-focus, .impact, .evidence, .feedback-section {
      border-top:1px solid var(--line); padding:28px 0; }
    .steps, .split, .health-focus, .evidence-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:18px; }
    .split, .health-focus { grid-template-columns:1fr 1fr; }
    article, .health-focus aside, .health-focus > div { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; min-width:0; }
    .steps article span { display:block; color:var(--muted); margin-top:6px; }
    .status-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin:18px 0 0; }
    .status-grid div { border:1px solid var(--line); border-radius:8px; padding:12px; background:var(--panel); }
    dd { margin:4px 0 0; font-weight:750; overflow-wrap:anywhere; }
    .step-list { list-style:none; padding:0; margin:22px 0; display:grid; gap:8px; }
    .step-list li { display:flex; justify-content:space-between; gap:12px; border:1px solid var(--line); border-radius:8px; padding:10px 12px; background:var(--panel); }
    .step-list .complete { border-color:#86b8a5; }
    .step-list .current { border-color:var(--accent); box-shadow:0 0 0 2px rgba(23,107,86,.12); }
    .step-list .failed { border-color:#c65a42; }
    .score { font-size:4.2rem; line-height:1; font-weight:900; margin:8px 0; color:var(--accent); }
    .support-score { font-size:1.55rem; font-weight:800; }
    .grade { font-weight:800; color:var(--accent-2); }
    .report-tabs { position:sticky; top:0; z-index:2; display:flex; flex-wrap:wrap; gap:8px; padding:12px 0; background:var(--paper); border-bottom:1px solid var(--line); }
    .report-tabs button { min-height:38px; background:transparent; color:var(--ink); border:1px solid var(--line); }
    .report-tabs button.is-active { color:#fff; background:var(--accent); border-color:var(--accent); }
    .tab-panel[hidden] { display:none; }
    .tab-panel.is-active { display:block; }
    .help-popover { position:relative; display:inline-flex; vertical-align:middle; }
    .help-trigger { min-height:1.45rem; width:1.45rem; padding:0; align-items:center; justify-content:center;
      border-radius:50%; border:1px solid var(--line); background:var(--panel); color:var(--accent); font-size:0.86rem; }
    .help-bubble { display:none; position:absolute; left:50%; bottom:calc(100% + 8px); transform:translateX(-50%);
      width:min(320px, calc(100vw - 42px)); z-index:5; padding:12px; border:1px solid var(--line);
      border-radius:8px; background:var(--panel); color:var(--ink); box-shadow:0 12px 30px rgba(0,0,0,.18);
      font-size:0.9rem; font-weight:500; line-height:1.45; }
    .help-bubble strong { display:block; margin-bottom:4px; }
    .help-popover:hover .help-bubble, .help-popover:focus-within .help-bubble { display:block; }
    .score-breakdown { margin:16px 0; border-top:1px solid var(--line); padding-top:14px; }
    .score-breakdown ul { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:8px; list-style:none; padding:0; margin:0; }
    .score-breakdown li { border:1px solid var(--line); border-radius:8px; padding:10px; background:var(--soft); }
    .score-breakdown strong { display:block; font-size:1.25rem; }
    details.explanation, .technical-details, .glossary-item { border:1px solid var(--line); border-radius:8px; padding:12px; background:var(--panel); margin-top:10px; }
    details > summary { cursor:pointer; font-weight:800; }
    .divergence-callout { background:var(--warning); border:1px solid var(--warning-line); border-radius:8px; padding:18px; margin:22px 0; }
    .compact-stats { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin:12px 0 0; }
    .compact-stats div { border:1px solid var(--warning-line); border-radius:8px; padding:10px; background:var(--panel); }
    .priority-list { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }
    .priority-card dl { display:grid; gap:8px; margin:12px 0; }
    .priority-card dl div { border-top:1px solid var(--line); padding-top:8px; }
    .count-note { color:var(--muted); }
    .finding-filters { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:18px 0; align-items:end; }
    .finding-filters label { margin:0; min-width:0; }
    .filter-actions { display:flex; gap:10px; flex-wrap:wrap; }
    .finding-results { display:grid; gap:10px; }
    .compact-findings .finding-results { max-width:920px; }
    .expanded-findings .finding-results { gap:12px; }
    .finding-detail { background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .finding-detail:target, .finding-detail.targeted { border-color:var(--accent); box-shadow:0 0 0 3px rgba(23,107,86,.14); }
    .finding-detail summary { display:grid; grid-template-columns:minmax(0,1fr) auto auto minmax(160px,.8fr); gap:10px; align-items:center; padding:14px; }
    .finding-detail summary::-webkit-details-marker { display:none; }
    .finding-title { font-weight:850; min-width:0; }
    .finding-path { color:var(--muted); font-size:0.9rem; overflow-wrap:anywhere; word-break:break-word; min-width:0; }
    .finding-body { border-top:1px solid var(--line); padding:16px; }
    .finding-meta { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin:0 0 16px; }
    .finding-meta div { border:1px solid var(--line); border-radius:8px; padding:10px; background:var(--soft); min-width:0; }
    .badge { display:inline-flex; align-items:center; min-height:28px; border:1px solid var(--line); border-radius:999px; padding:2px 9px; font-size:0.82rem; font-weight:800; white-space:normal; }
    .severity-critical { background:#fff0ec; color:#7b2718; border-color:#e5a08d; }
    .severity-high { background:#fff7eb; color:#7a4a00; border-color:#f1c77c; }
    .severity-medium { background:#eef6ff; color:#1a4f7a; border-color:#a5c7e6; }
    .severity-low { background:#edf8f2; color:#176b56; border-color:#9dc9b9; }
    :root[data-theme="dark"] .severity-critical { background:#3a1712; color:#ffb8aa; border-color:#8a3d2e; }
    :root[data-theme="dark"] .severity-high { background:#35250d; color:#ffd48a; border-color:#8a6422; }
    :root[data-theme="dark"] .severity-medium { background:#14283a; color:#9ed0ff; border-color:#315f89; }
    :root[data-theme="dark"] .severity-low { background:#123427; color:#9be4cb; border-color:#33765e; }
    .pagination { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:16px; }
    .pagination-disabled { min-height:46px; display:inline-flex; align-items:center; border:1px solid var(--line); border-radius:8px; padding:0 18px; color:var(--muted); background:var(--panel); }
    .page-links { display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
    .page-number, .page-current, .page-ellipsis { min-width:34px; min-height:34px; border:1px solid var(--line); border-radius:8px;
      display:inline-flex; align-items:center; justify-content:center; padding:0 8px; text-decoration:none; font-weight:800; }
    .page-number { color:var(--accent); background:var(--panel); }
    .page-current { color:#fff; background:var(--accent); border-color:var(--accent); }
    .page-ellipsis { color:var(--muted); }
    .glossary { display:grid; gap:10px; }
    .unavailable, .empty { color:var(--muted); font-size:0.92rem; }
    .alert { border:1px solid #c65a42; background:#fff0ec; color:#7b2718; border-radius:8px; padding:12px; }
    .alert h2 { font-size:1rem; margin:0 0 6px; }
    .back-link { color:var(--accent); font-weight:800; text-decoration:none; }
    .plain-list { padding-left:1.1rem; }
    .feedback-form { display:grid; gap:16px; max-width:760px; }
    fieldset { border:1px solid var(--line); border-radius:8px; padding:14px; display:flex; flex-wrap:wrap; gap:12px; }
    fieldset label, .check-row { display:flex; gap:8px; align-items:center; font-weight:600; margin:0; }
    fieldset input, .check-row input { width:auto; min-height:0; }
    .honeypot { position:absolute; left:-10000px; width:1px; height:1px; overflow:hidden; }
    table { width:100%; border-collapse:collapse; font-size:0.9rem; display:block; overflow-x:auto; }
    th, td { text-align:left; border-bottom:1px solid var(--line); padding:7px 5px; vertical-align:top; }
    .site-footer { border-top:1px solid var(--line); padding:20px clamp(18px,4vw,48px); display:flex; flex-wrap:wrap; gap:14px; background:var(--panel); }
    .site-footer a { color:var(--accent); font-weight:700; }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior:auto !important; transition:none !important; animation:none !important; }
    }
    @media (max-width:850px) {
      .form-row, .steps, .split, .health-focus, .priority-list, .evidence-grid, .status-grid,
      .score-breakdown ul, .compact-stats, .finding-filters, .finding-meta, .finding-detail summary { grid-template-columns:1fr; }
      h1 { font-size:2.4rem; }
      .score { font-size:3.2rem; }
      .site-header { align-items:flex-start; gap:8px; flex-direction:column; }
      .header-actions { justify-content:flex-start; }
      .report-tabs { position:static; }
      .help-bubble { left:auto; right:0; transform:none; }
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


def _date_bucket(value: datetime) -> str:
    return value.astimezone(UTC).date().isoformat()


def _elapsed_text(started_at: datetime) -> str:
    elapsed = max(0, int((datetime.now(UTC) - started_at.astimezone(UTC)).total_seconds()))
    if elapsed < 60:
        return f"{elapsed} seconds"
    minutes, seconds = divmod(elapsed, 60)
    if minutes < 60:
        return f"{minutes} minutes {seconds} seconds"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} hours {minutes} minutes"


def _format_bytes(value: int) -> str:
    if value >= 1024 * 1024:
        return f"{round(value / (1024 * 1024))} MB"
    if value >= 1024:
        return f"{round(value / 1024)} KB"
    return f"{value} bytes"


def _validated_choice(value: str, allowed: set[str], label: str) -> str:
    candidate = value.strip().lower()
    if candidate not in allowed:
        raise ValueError(f"Choose a valid {label} option.")
    return candidate


def _validated_text(value: str, label: str, max_length: int) -> str:
    text = value.strip()
    if len(text) > max_length:
        raise ValueError(f"{label.capitalize()} is too long.")
    return text


def _query_flag(environ: WSGIEnvironment, key: str, expected: str) -> bool:
    values = parse_qs(str(environ.get("QUERY_STRING") or ""), keep_blank_values=True)
    return (values.get(key) or [""])[0] == expected


def hash_submission_source(source: str, secret: str) -> str:
    normalised = source.strip().lower() or "anonymous"
    return hmac.new(secret.encode("utf-8"), normalised.encode("utf-8"), hashlib.sha256).hexdigest()


def client_source_from_environ(environ: WSGIEnvironment, beta: BetaConfig) -> str:
    remote = _normalise_ip(str(environ.get("REMOTE_ADDR") or ""))
    if remote and remote in beta.trusted_proxy_ips:
        forwarded = str(environ.get("HTTP_X_FORWARDED_FOR") or "")
        candidate = forwarded.split(",", 1)[0].strip()
        normalised = _normalise_ip(candidate)
        if normalised:
            return normalised
    return remote or "anonymous"


def _normalise_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc


def _env_bool(env: dict[str, str], key: str, default: bool) -> bool:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    normalised = value.strip().lower()
    if normalised in {"1", "true", "yes", "on"}:
        return True
    if normalised in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{key} must be a boolean")


def _env_list(
    env: dict[str, str],
    key: str,
    *,
    default: tuple[str, ...] = (),
) -> tuple[str, ...]:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    return tuple(part.strip() for part in re.split(r"[,\n]", value) if part.strip())
