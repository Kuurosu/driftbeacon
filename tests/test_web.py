from __future__ import annotations

import io
import json
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlencode
from wsgiref.util import setup_testing_defaults

import pytest

from driftbeacon.analysis_metrics import enrich_findings_for_analysis
from driftbeacon.comparison import compare_scans
from driftbeacon.models import ScanResult
from driftbeacon.web import (
    DriftBeaconWebApp,
    PublicGitHubRepositoryProvider,
    WebConfig,
    WebScanArtifacts,
    WebScanService,
    WebScanState,
    normalise_public_github_url,
    render_home_page,
    render_progress_page,
    render_repository_report_page,
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
    progress: object,
) -> WebScanArtifacts:
    output_dir.mkdir(parents=True, exist_ok=True)
    progress("cloning", "Cloning public GitHub repository.", 20)  # type: ignore[operator]
    progress("scanning", "Running scanners.", 50)  # type: ignore[operator]
    progress("rendering", "Rendering report.", 90)  # type: ignore[operator]
    report_path = output_dir / "report.md"
    scan_path = output_dir / "current-scan.json"
    comparison_path = output_dir / "comparison-summary.json"
    web_report_path = output_dir / "web-report.html"
    report_path.write_text("# DriftBeacon Report\n", encoding="utf-8")
    scan_path.write_text(
        json.dumps({"report_type": "repository", "repository": "owner/repo"}),
        encoding="utf-8",
    )
    comparison_path.write_text(json.dumps({"has_baseline": False}), encoding="utf-8")
    web_report_path.write_text(
        "<h1>owner/repo</h1><h2>Production Health</h2><h2>What to fix next</h2>",
        encoding="utf-8",
    )
    return WebScanArtifacts(
        repository="owner/repo",
        branch="main",
        commit_sha="abc123456789",
        report_path=report_path,
        scan_path=scan_path,
        comparison_path=comparison_path,
        web_report_path=web_report_path,
    )


def _web_config(tmp_path: Path) -> WebConfig:
    return WebConfig(
        output_dir=tmp_path / "web",
        max_concurrent_scans=1,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        scan_retention_seconds=60,
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
        max_concurrent_scans=1,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        scan_retention_seconds=60,
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
        error="scanner exited 2: malformed JSON",
    )

    html = render_progress_page(state)

    assert "scanner exited 2" in html
