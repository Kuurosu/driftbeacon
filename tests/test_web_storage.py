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
from driftbeacon.web_storage import (
    FeedbackRecord,
    FileReportStore,
    SQLiteScanStore,
    WebScanState,
)


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


def test_worker_claims_one_queued_scan_atomically(tmp_path: Path) -> None:
    database = tmp_path / "web.sqlite3"
    store = SQLiteScanStore(database)
    store.create_scan(_state("abcdef123456", tmp_path))

    claimed = store.claim_next_queued_scan(
        worker_id="worker-one",
        now=datetime.now(UTC),
    )
    second_claim = store.claim_next_queued_scan(
        worker_id="worker-two",
        now=datetime.now(UTC),
    )

    assert claimed is not None
    assert claimed.scan_id == "abcdef123456"
    assert claimed.status == "cloning"
    assert claimed.worker_id == "worker-one"
    assert claimed.attempt_count == 1
    assert second_claim is None


def test_completed_and_failed_scans_are_not_reclaimed(tmp_path: Path) -> None:
    store = SQLiteScanStore(tmp_path / "web.sqlite3")
    store.create_scan(_state("abcdef123456", tmp_path, status="completed"))
    store.create_scan(_state("abcdef123457", tmp_path, status="failed"))

    assert store.claim_next_queued_scan(worker_id="worker", now=datetime.now(UTC)) is None


def test_claim_state_survives_store_recreation(tmp_path: Path) -> None:
    database = tmp_path / "web.sqlite3"
    store = SQLiteScanStore(database)
    store.create_scan(_state("abcdef123456", tmp_path))
    store.claim_next_queued_scan(worker_id="worker-one", now=datetime.now(UTC))

    reloaded = SQLiteScanStore(database)
    state = reloaded.get_scan("abcdef123456")

    assert state is not None
    assert state.status == "cloning"
    assert state.worker_id == "worker-one"
    assert state.claimed_at is not None


def test_stale_worker_claims_become_safe_failures(tmp_path: Path) -> None:
    store = SQLiteScanStore(tmp_path / "web.sqlite3")
    store.create_scan(_state("abcdef123456", tmp_path))
    old = datetime.now(UTC) - timedelta(minutes=15)
    store.claim_next_queued_scan(worker_id="worker-one", now=old)

    failed = store.mark_stale_claimed_scans_failed(
        stale_before=datetime.now(UTC) - timedelta(minutes=10),
        now=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    state = store.get_scan("abcdef123456")

    assert failed == 1
    assert state is not None
    assert state.status == "failed"
    assert state.error_code == "scan_interrupted"


def test_queued_scans_survive_web_service_recreation(tmp_path: Path) -> None:
    config = _web_config(tmp_path)
    service = WebScanService(config)
    submitted = service.submit("https://github.com/owner/repo")

    restarted = WebScanService(config)
    state = restarted.get(submitted.scan_id)

    assert state is not None
    assert state.status == "queued"


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


def test_sqlite_v1_schema_migrates_to_worker_queue_columns(tmp_path: Path) -> None:
    database = tmp_path / "v1.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE web_schema_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO web_schema_version (id, version) VALUES (1, 1)")
        connection.execute(
            """
            CREATE TABLE scans (
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

    store = SQLiteScanStore(database)
    store.create_scan(_state("abcdef123456", tmp_path))
    claimed = store.claim_next_queued_scan(worker_id="worker", now=datetime.now(UTC))

    assert store.check_ready() is True
    assert claimed is not None
    assert claimed.worker_id == "worker"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'beta_usage_counters'"
        ).fetchone()


def test_sqlite_v2_schema_migrates_to_beta_tables(tmp_path: Path) -> None:
    database = tmp_path / "v2.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE web_schema_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO web_schema_version (id, version) VALUES (1, 2)")
        connection.execute(
            """
            CREATE TABLE scans (
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

    store = SQLiteScanStore(database)

    assert store.check_ready() is True
    decision = store.record_submission_attempt(
        source_hash="abc",
        date_bucket="2026-07-24",
        max_source_accepts=1,
        max_total_accepts=1,
    )
    assert decision.allowed is True


def test_sqlite_insert_uses_parameters_for_repository_url(tmp_path: Path) -> None:
    store = SQLiteScanStore(tmp_path / "web.sqlite3")
    state = _state("abcdef123456", tmp_path)
    state.repository_url = "https://github.com/owner/repo.git'); DROP TABLE scans;--"

    store.create_scan(state)

    assert store.get_scan("abcdef123456") is not None
    store.create_scan(_state("abcdef123457", tmp_path))
    assert store.get_scan("abcdef123457") is not None


def test_sqlite_beta_usage_counters_enforce_source_and_global_limits(
    tmp_path: Path,
) -> None:
    store = SQLiteScanStore(tmp_path / "web.sqlite3")

    first = store.record_submission_attempt(
        source_hash="source-a",
        date_bucket="2026-07-24",
        max_source_accepts=1,
        max_total_accepts=2,
    )
    second = store.record_submission_attempt(
        source_hash="source-a",
        date_bucket="2026-07-24",
        max_source_accepts=1,
        max_total_accepts=2,
    )
    third = store.record_submission_attempt(
        source_hash="source-b",
        date_bucket="2026-07-24",
        max_source_accepts=2,
        max_total_accepts=1,
    )

    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == "source_daily_limit"
    assert third.allowed is False
    assert third.reason == "global_daily_limit"
    assert store.daily_submission_counts("2026-07-24") == {"accepted": 1, "rejected": 2}


def test_sqlite_feedback_and_analytics_are_local_only_records(tmp_path: Path) -> None:
    store = SQLiteScanStore(tmp_path / "web.sqlite3")
    now = datetime.now(UTC)
    feedback = FeedbackRecord(
        feedback_id="abcdef123456",
        created_at=now,
        scan_id=None,
        source_hash="hash-only",
        helpfulness="yes",
        changed_priority="maybe",
        private_monitoring_interest=True,
        comment="<b>helpful</b>",
        email="tester@example.com",
        consent_to_contact=True,
    )

    store.save_feedback(feedback)
    store.record_analytics_event(
        "feedback_submitted",
        source_hash="hash-only",
        properties={"helpfulness": "yes"},
        created_at=now,
    )

    rows = store.list_feedback()
    assert len(rows) == 1
    assert rows[0].comment == "<b>helpful</b>"
    assert rows[0].email == "tester@example.com"
    assert store.count_private_monitoring_interest_on(now.date().isoformat()) == 1
    assert store.event_counts_on(now.date().isoformat()) == {"feedback_submitted": 1}


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
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
    )
