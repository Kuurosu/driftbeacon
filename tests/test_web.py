from __future__ import annotations

import io
import json
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlencode
from wsgiref.util import setup_testing_defaults

import pytest

from driftbeacon.analysis_metrics import enrich_findings_for_analysis
from driftbeacon.comparison import compare_scans
from driftbeacon.models import ComparisonSummary, ScanResult
from driftbeacon.web import (
    DriftBeaconWebApp,
    FileReportStore,
    PublicGitHubRepositoryProvider,
    WebConfig,
    WebScanArtifacts,
    WebScanFailure,
    WebScanService,
    WebScanState,
    _enforce_repository_limits,
    normalise_public_github_url,
    render_home_page,
    render_progress_page,
    render_repository_report_page,
    run_public_repository_scan,
)


def _request(
    app: DriftBeaconWebApp,
    method: str,
    path: str,
    *,
    body: str = "",
    remote_addr: str = "127.0.0.1",
) -> tuple[str, dict[str, str], str]:
    captured: dict[str, object] = {}

    def start_response(
        status: str,
        headers: list[tuple[str, str]],
        exc_info: object = None,
    ) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)
        captured["exc_info"] = exc_info

    environ: dict[str, object] = {}
    setup_testing_defaults(environ)
    environ.update(
        {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "REMOTE_ADDR": remote_addr,
            "wsgi.input": io.BytesIO(body.encode("utf-8")),
            "CONTENT_LENGTH": str(len(body.encode("utf-8"))),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
        }
    )
    chunks = app(environ, start_response)
    payload = b"".join(_as_bytes(chunks)).decode("utf-8")
    return str(captured["status"]), captured["headers"], payload  # type: ignore[return-value]


def _as_bytes(chunks: Iterable[bytes]) -> Iterable[bytes]:
    return chunks


def _fake_runner(
    scan_id: str,
    repository_url: str,
    output_dir: Path,
    _config: WebConfig,
    _provider: PublicGitHubRepositoryProvider,
    report_store: FileReportStore,
    progress: object,
) -> WebScanArtifacts:
    output_dir.mkdir(parents=True, exist_ok=True)
    progress("cloning", "Cloning public GitHub repository.", 20)  # type: ignore[operator]
    progress("analysing", "Running scanners.", 50)  # type: ignore[operator]
    progress("generating_report", "Rendering report.", 90)  # type: ignore[operator]
    scan = ScanResult.from_dict(
        {
            "repository": "owner/repo",
            "branch": "main",
            "commit_sha": "abc123456789",
            "started_at": "2026-07-24T09:00:00+00:00",
            "completed_at": "2026-07-24T09:00:01+00:00",
            "scanner_statuses": {},
            "findings": [],
            "health_score": 100,
            "summary": {
                "production_health_score": 100,
                "production_grade": "A",
                "production_score_reason": "No production findings were detected.",
                "production_actionable_findings": 0,
                "production_coverage_state": "complete_coverage",
            },
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
    report_reference = report_store.save(
        scan_id,
        report_json={
            "generated_at": "2026-07-24T09:00:01+00:00",
            "scan": scan.to_dict(),
            "comparison": comparison.to_dict(),
        },
        markdown="# DriftBeacon Report\n",
    )
    return WebScanArtifacts(
        repository="owner/repo",
        branch="main",
        commit_sha="abc123456789",
        report_reference=report_reference,
        overall_health=100,
        overall_grade="A",
        production_health=100,
        production_grade="A",
        coverage_status="complete_coverage",
        baseline_type="Initial baseline",
    )


def _web_config(tmp_path: Path) -> WebConfig:
    return WebConfig(
        output_dir=tmp_path / "web",
        database_path=tmp_path / "web" / "web.sqlite3",
        report_dir=tmp_path / "web" / "reports",
        working_dir=tmp_path / "web" / "work",
        max_concurrent_scans=1,
        max_queued_scans=2,
        max_scan_seconds=10,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        retention_days=7,
        scans_per_hour=3,
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
    )


def test_homepage_uses_production_risk_positioning() -> None:
    html = render_home_page()

    assert "Know exactly what to fix next to reduce production risk" in html
    assert "Paste a public GitHub repository" in html
    assert "Ordinary scanners tell you everything they found" in html
    assert "guarantee security" not in html.lower()
    assert "guarantees security" not in html.lower()


def test_public_github_url_validation_is_strict() -> None:
    assert normalise_public_github_url("https://github.com/Kuurosu/driftbeacon") == (
        "https://github.com/Kuurosu/driftbeacon.git"
    )
    assert normalise_public_github_url("https://github.com/Kuurosu/driftbeacon.git") == (
        "https://github.com/Kuurosu/driftbeacon.git"
    )

    for url in (
        "http://github.com/Kuurosu/driftbeacon",
        "https://example.com/Kuurosu/driftbeacon",
        "https://user:token@github.com/Kuurosu/driftbeacon",
        "https://github.com/Kuurosu/driftbeacon?token=abc",
        "git@github.com:Kuurosu/driftbeacon.git",
    ):
        with pytest.raises(ValueError):
            normalise_public_github_url(url)


def test_web_routes_submit_scan_and_render_status(tmp_path: Path) -> None:
    service = WebScanService(
        _web_config(tmp_path),
        runner=_fake_runner,
        synchronous=True,
    )
    app = DriftBeaconWebApp(service)

    status, _headers, body = _request(app, "GET", "/")
    assert status.startswith("200")
    assert "Production Health" in body

    form = urlencode({"repository_url": "https://github.com/owner/repo"})
    status, headers, _body = _request(app, "POST", "/scans", body=form)

    assert status.startswith("303")
    location = headers["Location"]
    assert location.startswith("/scans/")

    status, _headers, body = _request(app, "GET", location)
    assert status.startswith("200")
    assert "owner/repo" in body
    assert "What to fix next" in body

    scan_id = location.rsplit("/", 1)[-1]
    status, _headers, body = _request(app, "GET", f"/api/scans/{scan_id}")
    data = json.loads(body)
    assert status.startswith("200")
    assert data["status"] == "completed"
    assert data["repository"] == "owner/repo"

    status, _headers, body = _request(app, "GET", f"/scans/{scan_id}/report.md")
    assert status.startswith("200")
    assert "# DriftBeacon Report" in body

    status, _headers, body = _request(app, "GET", f"/scans/{scan_id}/report.json")
    assert status.startswith("200")
    assert json.loads(body)["scan"]["repository"] == "owner/repo"

    restarted = DriftBeaconWebApp(
        WebScanService(_web_config(tmp_path), runner=_fake_runner, synchronous=True)
    )
    status, _headers, body = _request(restarted, "GET", location)
    assert status.startswith("200")
    assert "owner/repo" in body
    assert "Anyone with this link can view it" in body


def test_web_rejects_invalid_repository_without_starting_scan(tmp_path: Path) -> None:
    service = WebScanService(
        _web_config(tmp_path),
        runner=_fake_runner,
        synchronous=True,
    )
    app = DriftBeaconWebApp(service)

    status, _headers, body = _request(
        app,
        "POST",
        "/scans",
        body=urlencode({"repository_url": "https://example.com/not/github"}),
    )

    assert status.startswith("400")
    assert "Only HTTPS GitHub repository URLs are supported" in body


def test_web_report_prioritises_production_health_and_reuses_explanations(
    current_scan: ScanResult,
) -> None:
    enrich_findings_for_analysis(current_scan.findings)
    comparison = compare_scans(current_scan, None)
    current_scan.summary.update(
        {
            "coverage_state": "partial_coverage",
            "production_coverage_state": "partial_coverage",
            "production_health_score": 61,
            "production_grade": "D",
            "production_grade_provisional": True,
            "production_score_reason": (
                "Production Health calculated from successful scanner output; "
                "coverage is incomplete."
            ),
            "production_actionable_findings": 3,
            "production_critical_findings": 1,
            "production_high_findings": 2,
            "production_medium_findings": 0,
            "production_low_findings": 0,
            "finding_source_breakdown": {
                "trivy_secret": {
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total_actionable": 1,
                }
            },
            "directory_group_breakdown": {
                "production": {
                    "critical": 1,
                    "high": 2,
                    "medium": 0,
                    "low": 0,
                    "total_actionable": 3,
                }
            },
        }
    )

    html = render_repository_report_page(current_scan, comparison)

    assert html.index("Production Health") < html.index("Overall Health")
    assert html.index("Production Health") < html.index("Severity distribution")
    assert "What to fix next" in html
    assert "AWS Access Key ID" in html
    assert "Why it matters" in html
    assert "Remove the hardcoded secret and rotate it if it was committed." in html
    assert "Production path" in html
    assert "Partial coverage" in html
    assert "Provisional grade" in html
    assert "unavailable in this MVP" in html
    assert "Estimated effort: 1" not in html
    assert "Projected risk reduction: 61%" not in html


def test_web_service_uses_configurable_limits_without_plan_enforcement(tmp_path: Path) -> None:
    config = WebConfig(
        output_dir=tmp_path / "web",
        database_path=tmp_path / "web" / "web.sqlite3",
        report_dir=tmp_path / "web" / "reports",
        working_dir=tmp_path / "web" / "work",
        max_concurrent_scans=1,
        max_queued_scans=2,
        max_scan_seconds=10,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        retention_days=7,
        scans_per_hour=2,
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
    )
    service = WebScanService(config, runner=_fake_runner, synchronous=True)

    first = service.submit("https://github.com/owner/one", client_id="client")
    second = service.submit("https://github.com/owner/two", client_id="client")

    assert first.status == "completed"
    assert second.status == "completed"
    assert not hasattr(config, "plan")

    with pytest.raises(ValueError, match="Too many scans"):
        service.submit("https://github.com/owner/three", client_id="client")


def test_web_rejects_when_queue_capacity_is_full(tmp_path: Path) -> None:
    config = WebConfig(
        output_dir=tmp_path / "web",
        database_path=tmp_path / "web" / "web.sqlite3",
        report_dir=tmp_path / "web" / "reports",
        working_dir=tmp_path / "web" / "work",
        max_concurrent_scans=1,
        max_queued_scans=0,
        max_scan_seconds=10,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        retention_days=7,
        scans_per_hour=2,
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
    )
    service = WebScanService(config, runner=_fake_runner, synchronous=True)
    app = DriftBeaconWebApp(service)

    status, _headers, body = _request(
        app,
        "POST",
        "/scans",
        body=urlencode({"repository_url": "https://github.com/owner/repo"}),
    )

    assert status.startswith("503")
    assert "currently at capacity" in body


def test_repository_limits_use_safe_public_errors(tmp_path: Path) -> None:
    files_repo = tmp_path / "files"
    files_repo.mkdir()
    for index in range(3):
        (files_repo / f"{index}.tf").write_text("resource {}\n", encoding="utf-8")
    file_config = _web_config(tmp_path)
    file_config = replace(file_config, max_repository_files=2)

    with pytest.raises(WebScanFailure) as file_error:
        _enforce_repository_limits(files_repo, file_config)
    assert file_error.value.error_code == "repository_file_limit_exceeded"
    assert "file-count limit" in file_error.value.safe_message

    bytes_repo = tmp_path / "bytes"
    bytes_repo.mkdir()
    (bytes_repo / "main.tf").write_text("x" * 64, encoding="utf-8")
    byte_config = replace(_web_config(tmp_path), max_repository_bytes=10)

    with pytest.raises(WebScanFailure) as byte_error:
        _enforce_repository_limits(bytes_repo, byte_config)
    assert byte_error.value.error_code == "repository_too_large"
    assert "size limit" in byte_error.value.safe_message


def test_clone_timeout_maps_to_safe_error(tmp_path: Path) -> None:
    class TimeoutProvider(PublicGitHubRepositoryProvider):
        def clone(
            self,
            repository_url: str,
            clone_path: Path,
            *,
            timeout_seconds: int,
        ) -> None:
            _ = repository_url, clone_path, timeout_seconds
            raise ValueError("git clone timed out after 1s")

    with pytest.raises(WebScanFailure) as exc_info:
        run_public_repository_scan(
            "abcdef123456",
            "https://github.com/owner/repo.git",
            tmp_path / "work",
            _web_config(tmp_path),
            TimeoutProvider(),
            FileReportStore(tmp_path / "reports"),
            lambda _status, _message, _progress: None,
        )

    assert exc_info.value.error_code == "clone_timeout"
    assert "time limit" in exc_info.value.safe_message


def test_scan_timeout_maps_to_safe_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyProvider(PublicGitHubRepositoryProvider):
        def clone(
            self,
            repository_url: str,
            clone_path: Path,
            *,
            timeout_seconds: int,
        ) -> None:
            _ = repository_url, timeout_seconds
            clone_path.mkdir(parents=True)

    def timeout_scan(*_args: object, **_kwargs: object) -> object:
        raise TimeoutError("scan timed out")

    monkeypatch.setattr("driftbeacon.web.run_scan_with_engine", timeout_scan)

    with pytest.raises(WebScanFailure) as exc_info:
        run_public_repository_scan(
            "abcdef123456",
            "https://github.com/owner/repo.git",
            tmp_path / "work",
            _web_config(tmp_path),
            EmptyProvider(),
            FileReportStore(tmp_path / "reports"),
            lambda _status, _message, _progress: None,
        )

    assert exc_info.value.error_code == "scan_timeout"
    assert "time limit" in exc_info.value.safe_message


def test_progress_page_keeps_scanner_errors_visible() -> None:
    now = current = ScanResult.from_dict(
        {
            "repository": "owner/repo",
            "branch": "main",
            "commit_sha": "abc123",
            "started_at": "2026-07-24T09:00:00+00:00",
            "completed_at": "2026-07-24T09:00:01+00:00",
            "scanner_statuses": {},
            "findings": [],
            "health_score": None,
            "summary": {},
        }
    ).completed_at
    state = WebScanState(
        scan_id="abcdef123456",
        repository_url="https://github.com/owner/repo.git",
        status="failed",
        message="Scan failed.",
        progress=100,
        created_at=now or current,
        updated_at=now or current,
        client_id="client",
        safe_error_message="scanner exited 2: malformed JSON",
    )

    html = render_progress_page(state)

    assert "scanner exited 2" in html
