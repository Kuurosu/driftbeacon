"""Persistent scan worker for the DriftBeacon public web MVP."""

from __future__ import annotations

import logging
import os
import shutil
import socket
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .redaction import redact_secrets
from .web import (
    PublicGitHubRepositoryProvider,
    ScanRunner,
    WebConfig,
    WebScanFailure,
    run_public_repository_scan,
)
from .web_storage import FileReportStore, SQLiteScanStore, WebScanState, valid_scan_id

_LOGGER = logging.getLogger("driftbeacon.worker")


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    """Configuration for the persistent scan worker."""

    worker_id: str
    poll_interval_seconds: float = 2.0
    stale_seconds: int = 600

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> WorkerConfig:
        source = env or dict(os.environ)
        worker_id = source.get("DRIFTBEACON_WORKER_ID") or _default_worker_id()
        return cls(
            worker_id=worker_id,
            poll_interval_seconds=_env_float(
                source,
                "DRIFTBEACON_WORKER_POLL_SECONDS",
                2.0,
            ),
            stale_seconds=_env_int(source, "DRIFTBEACON_WORKER_STALE_SECONDS", 600),
        ).validate()

    def validate(self) -> WorkerConfig:
        if not self.worker_id.strip():
            raise ValueError("worker_id must not be empty")
        if self.poll_interval_seconds <= 0:
            raise ValueError("worker poll interval must be greater than zero")
        if self.stale_seconds < 60:
            raise ValueError("worker stale seconds must be at least 60")
        return self


class WebScanWorker:
    """Claims queued web scans and executes scanner work outside the web process."""

    def __init__(
        self,
        web_config: WebConfig | None = None,
        worker_config: WorkerConfig | None = None,
        *,
        provider: PublicGitHubRepositoryProvider | None = None,
        runner: ScanRunner | None = None,
    ) -> None:
        self.web_config = (web_config or WebConfig.from_environment()).validate()
        self.worker_config = (worker_config or WorkerConfig.from_environment()).validate()
        self.working_dir = self.web_config.working_dir.expanduser().resolve()
        self.working_dir.mkdir(parents=True, exist_ok=True)
        if self.working_dir.exists() and self.working_dir.is_symlink():
            raise ValueError("worker working_dir must not be a symlink")
        self.store = SQLiteScanStore(self.web_config.database_path)
        self.report_store = FileReportStore(self.web_config.report_dir)
        self.provider = provider or PublicGitHubRepositoryProvider()
        self.runner = runner or run_public_repository_scan

    def process_once(self) -> bool:
        """Claim and process at most one queued scan."""

        self.fail_stale_claims()
        state = self.store.claim_next_queued_scan(
            worker_id=self.worker_config.worker_id,
            now=datetime.now(UTC),
        )
        if state is None:
            return False
        self._process_claimed_scan(state)
        return True

    def run_forever(self) -> None:
        """Poll SQLite for queued scans until interrupted."""

        _LOGGER.info("service=worker worker_id=%s status=started", self.worker_config.worker_id)
        while True:
            processed = self.process_once()
            if not processed:
                time.sleep(self.worker_config.poll_interval_seconds)

    def fail_stale_claims(self) -> int:
        now = datetime.now(UTC)
        failed = self.store.mark_stale_claimed_scans_failed(
            stale_before=now - timedelta(seconds=self.worker_config.stale_seconds),
            now=now,
            expires_at=self._expiry_from(now),
        )
        if failed:
            _LOGGER.warning(
                "service=worker worker_id=%s stale_claims_failed=%s",
                self.worker_config.worker_id,
                failed,
            )
        return failed

    def _process_claimed_scan(self, state: WebScanState) -> None:
        scan_id = state.scan_id
        started = time.monotonic()
        _LOGGER.info(
            "service=worker worker_id=%s scan_id=%s repository=%s status=claimed attempt=%s",
            self.worker_config.worker_id,
            scan_id,
            state.repository_url,
            state.attempt_count,
        )
        self._record_event("scan_started", scan_id=scan_id)
        try:
            artifacts = self.runner(
                scan_id,
                state.repository_url,
                self.working_dir / scan_id,
                self.web_config,
                self.provider,
                self.report_store,
                lambda status, message, progress: self._progress(
                    scan_id,
                    status,
                    message,
                    progress,
                ),
            )
        except WebScanFailure as exc:
            completed_at = datetime.now(UTC)
            self.store.update_status(
                scan_id,
                "failed",
                exc.safe_message,
                100,
                completed_at=completed_at,
                expires_at=self._expiry_from(completed_at),
                error_code=exc.error_code,
                safe_error_message=exc.safe_message,
            )
            _LOGGER.warning(
                "service=worker worker_id=%s scan_id=%s status=failed code=%s duration=%.2f",
                self.worker_config.worker_id,
                scan_id,
                exc.error_code,
                time.monotonic() - started,
            )
            self._record_event(
                "scan_failed",
                scan_id=scan_id,
                properties={"error_code": exc.error_code},
            )
            if exc.detail:
                _LOGGER.info(
                    "service=worker worker_id=%s scan_id=%s detail=%s",
                    self.worker_config.worker_id,
                    scan_id,
                    redact_secrets(exc.detail),
                )
        except Exception as exc:
            completed_at = datetime.now(UTC)
            safe = "Scan failed. Please try again with a smaller public repository."
            self.store.update_status(
                scan_id,
                "failed",
                safe,
                100,
                completed_at=completed_at,
                expires_at=self._expiry_from(completed_at),
                error_code="scanner_failure",
                safe_error_message=safe,
            )
            _LOGGER.exception(
                "service=worker worker_id=%s scan_id=%s status=failed "
                "code=scanner_failure detail=%s",
                self.worker_config.worker_id,
                scan_id,
                redact_secrets(str(exc)),
            )
            self._record_event(
                "scan_failed",
                scan_id=scan_id,
                properties={"error_code": "scanner_failure"},
            )
        else:
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
            _LOGGER.info(
                "service=worker worker_id=%s scan_id=%s status=completed duration=%.2f",
                self.worker_config.worker_id,
                scan_id,
                time.monotonic() - started,
            )
            self._record_event(
                "scan_completed",
                scan_id=scan_id,
                properties={"repository": artifacts.repository},
            )
        finally:
            self._delete_workdir(scan_id)

    def _progress(self, scan_id: str, status: str, message: str, progress: int) -> None:
        self.store.update_status(
            scan_id,
            status,  # type: ignore[arg-type]
            message,
            progress,
        )
        self.store.heartbeat(scan_id, worker_id=self.worker_config.worker_id)
        _LOGGER.info(
            "service=worker worker_id=%s scan_id=%s status=%s progress=%s",
            self.worker_config.worker_id,
            scan_id,
            status,
            progress,
        )

    def _record_event(
        self,
        event_name: str,
        *,
        scan_id: str,
        properties: dict[str, str | int | float | bool | None] | None = None,
    ) -> None:
        with suppress(Exception):
            self.store.record_analytics_event(
                event_name,
                scan_id=scan_id,
                properties=properties or {},
            )

    def _expiry_from(self, value: datetime) -> datetime:
        return value + timedelta(days=self.web_config.retention_days)

    def _delete_workdir(self, scan_id: str) -> None:
        if not valid_scan_id(scan_id):
            return
        path = self.working_dir / scan_id
        if path.exists() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)


def _default_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc


def _env_float(env: dict[str, str], key: str, default: float) -> float:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be a number") from exc
