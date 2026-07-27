from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_web import _request

from driftbeacon.models import ComparisonSummary, ScanResult
from driftbeacon.storage import StorageError
from driftbeacon.web import DriftBeaconWebApp, WebConfig, WebScanService
from driftbeacon.web_storage import FileReportStore, SQLiteScanStore, WebScanState


def _state(scan_id: str, tmp_path: Path, *, status: str = "queued") -> WebScanState:
    now = datetime.now(UTC)
    return WebScanState(
        scan_id=scan_id,
        repository_url="https://github.com/owner/repo.git",
        repository_owner="owner",
        repository_name="repo",
        status=status,  # type: ignore[arg-type]
        message="Queued for analysis.",
        progress=5,
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(days=7),
        report_reference=scan_id if status == "completed" else None,
        repository="owner/repo" if status == "completed" else None,
        branch="main" if status == "completed" else None,
        commit_sha="abc123" if status == "completed" else None,
    )


def _report_json() -> dict[str, object]:
    scan = ScanResult.from_dict(
        {
            "repository": "owner/repo",
            "branch": "main",
            "commit_sha": "abc123",
            "started_at": "2026-07-24T09:00:00+00:00",
            "completed_at": "2026-07-24T09:00:01+00:00",
            "scanner_statuses": {},
            "findings": [],
            "health_score": 100,
            "summary": {},
        }
    )
    comparison = ComparisonSummary(
        has_baseline=False,
        new_findings=[],
        recurring_findings=[],
        resolved_findings=[],
        severity_changes=[],
        health_score_change=None,
        active_findings_change=None,
    )
    return {
        "generated_at": "2026-07-24T09:00:01+00:00",
        "scan": scan.to_dict(),
        "comparison": comparison.to_dict(),
    }


def test_sqlite_scan_state_survives_new_store_instance(tmp_path: Path) -> None:
    database = tmp_path / "web.sqlite3"
    store = SQLiteScanStore(database)
    store.create_scan(_state("abcdef123456", tmp_path))
    store.update_status("abcdef123456", "analysing", "Running scanners.", 45)

    reloaded = SQLiteScanStore(database)
    state = reloaded.get_scan("abcdef123456")

    assert state is not None
    assert state.status == "analysing"
    assert state.repository_owner == "owner"


def test_sqlite_schema_initialises_and_rejects_unsupported_version(tmp_path: Path) -> None:
    database = tmp_path / "web.sqlite3"
    SQLiteScanStore(database)
    assert database.exists()

    bad_database = tmp_path / "bad.sqlite3"
    with sqlite3.connect(bad_database) as connection:
        connection.execute(
            "CREATE TABLE web_schema_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO web_schema_version (id, version) VALUES (1, 99)")

    with pytest.raises(StorageError, match="unsupported DriftBeacon web database schema version"):
        SQLiteScanStore(bad_database)


def test_sqlite_insert_uses_parameters_for_repository_url(tmp_path: Path) -> None:
    store = SQLiteScanStore(tmp_path / "web.sqlite3")
    state = _state("abcdef123456", tmp_path)
    state.repository_url = "https://github.com/owner/repo.git'); DROP TABLE scans;--"

    store.create_scan(state)

    assert store.get_scan("abcdef123456") is not None
    store.create_scan(_state("abcdef123457", tmp_path))
    assert store.get_scan("abcdef123457") is not None


def test_report_store_round_trips_deletes_and_rejects_path_traversal(tmp_path: Path) -> None:
    reports = FileReportStore(tmp_path / "reports")
    reports.save(
        "abcdef123456",
        report_json=_report_json(),
        markdown="# DriftBeacon Report\n",
    )

    loaded = reports.load("abcdef123456")
    assert loaded is not None
    assert loaded.scan.repository == "owner/repo"
    assert loaded.markdown.startswith("# DriftBeacon")

    with pytest.raises(StorageError, match="invalid scan id"):
        reports.load("../abcdef123456")

    reports.delete("abcdef123456")
    assert reports.load("abcdef123456") is None


def test_abandoned_scans_become_interrupted_failures_at_startup(tmp_path: Path) -> None:
    config = _web_config(tmp_path)
    store = SQLiteScanStore(config.database_path)
    store.create_scan(_state("abcdef123456", tmp_path, status="analysing"))

    service = WebScanService(config, recover_interrupted=True)
    state = service.get("abcdef123456")

    assert state is not None
    assert state.status == "failed"
    assert state.error_code == "scan_interrupted"


def test_expired_report_cleanup_tombstones_metadata_and_removes_report(
    tmp_path: Path,
) -> None:
    service = WebScanService(_web_config(tmp_path), recover_interrupted=False)
    expired = _state("abcdef123456", tmp_path, status="completed")
    expired.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    service.store.create_scan(expired)
    service.report_store.save(
        "abcdef123456",
        report_json=_report_json(),
        markdown="# DriftBeacon Report\n",
    )

    result = service.cleanup_expired_scans()

    assert result["expired_records"] == 1
    assert service.report_store.load("abcdef123456") is None
    state = service.get("abcdef123456")
    assert state is not None
    assert state.status == "expired"

    app = DriftBeaconWebApp(service)
    status, _headers, body = _request(app, "GET", "/scans/abcdef123456")
    assert status.startswith("410")
    assert "stored findings have been removed" in body

    second = service.cleanup_expired_scans()
    assert second["expired_records"] == 0


def test_cleanup_removes_abandoned_working_directories(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path), recover_interrupted=False)
    old_workdir = service.working_dir / "abcdef123456"
    old_workdir.mkdir(parents=True)
    old_timestamp = datetime.now(UTC).timestamp() - 120
    os.utime(old_workdir, (old_timestamp, old_timestamp))

    result = service.cleanup_expired_scans()

    assert result["cleaned_workdirs"] == 1
    assert not old_workdir.exists()


def _web_config(tmp_path: Path) -> WebConfig:
    root = tmp_path / "web"
    return WebConfig(
        output_dir=root,
        database_path=root / "web.sqlite3",
        report_dir=root / "reports",
        working_dir=root / "work",
        max_concurrent_scans=1,
        max_queued_scans=1,
        max_scan_seconds=10,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        retention_days=7,
        scans_per_hour=3,
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
    )
