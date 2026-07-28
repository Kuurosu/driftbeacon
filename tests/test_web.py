from __future__ import annotations

import io
import json
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode
from wsgiref.util import setup_testing_defaults

import pytest

from driftbeacon.analysis_metrics import enrich_findings_for_analysis
from driftbeacon.comparison import compare_scans
from driftbeacon.models import ComparisonSummary, ScanResult
from driftbeacon.web import (
    BetaConfig,
    DriftBeaconWebApp,
    FileReportStore,
    PublicGitHubRepositoryProvider,
    ReportFindingOptions,
    WebConfig,
    WebScanArtifacts,
    WebScanFailure,
    WebScanService,
    WebScanState,
    _enforce_repository_limits,
    client_source_from_environ,
    hash_submission_source,
    normalise_public_github_url,
    render_home_page,
    render_progress_page,
    render_repository_report_page,
    run_public_repository_scan,
    sample_report_data,
)
from driftbeacon.worker import WebScanWorker, WorkerConfig


def _request(
    app: DriftBeaconWebApp,
    method: str,
    path: str,
    *,
    body: str = "",
    remote_addr: str = "127.0.0.1",
    headers: dict[str, str] | None = None,
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
            "PATH_INFO": path.split("?", 1)[0],
            "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "",
            "REMOTE_ADDR": remote_addr,
            "wsgi.input": io.BytesIO(body.encode("utf-8")),
            "CONTENT_LENGTH": str(len(body.encode("utf-8"))),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
        }
    )
    for key, value in (headers or {}).items():
        environ[key] = value
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
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
        beta=BetaConfig(rate_limit_secret="test-secret"),
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
    config = _web_config(tmp_path)
    service = WebScanService(config)
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
    assert "Queued" in body

    scan_id = location.rsplit("/", 1)[-1]
    status, _headers, body = _request(app, "GET", f"/api/scans/{scan_id}")
    data = json.loads(body)
    assert status.startswith("200")
    assert data["status"] == "queued"

    worker = WebScanWorker(
        config,
        WorkerConfig(worker_id="test-worker", poll_interval_seconds=0.1, stale_seconds=60),
        runner=_fake_runner,
    )
    assert worker.process_once() is True

    status, _headers, body = _request(app, "GET", f"/api/scans/{scan_id}")
    data = json.loads(body)
    assert status.startswith("200")
    assert data["status"] == "completed"
    assert data["repository"] == "owner/repo"

    status, _headers, body = _request(app, "GET", location)
    assert status.startswith("200")
    assert "owner/repo" in body
    assert "Top priorities" in body
    assert "All findings" in body
    assert "No deduplicated active actionable findings were available to explore." in body
    assert "data-interest-link" in body

    status, _headers, body = _request(app, "GET", f"/scans/{scan_id}/report.md")
    assert status.startswith("200")
    assert "# DriftBeacon Report" in body

    status, _headers, body = _request(app, "GET", f"/scans/{scan_id}/report.json")
    assert status.startswith("200")
    assert json.loads(body)["scan"]["repository"] == "owner/repo"

    restarted = DriftBeaconWebApp(WebScanService(config))
    status, _headers, body = _request(restarted, "GET", location)
    assert status.startswith("200")
    assert "owner/repo" in body
    assert "Anyone with this link can view it" in body
    assert "Did this report help you decide what to fix?" in body


def test_web_rejects_invalid_repository_without_starting_scan(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path))
    app = DriftBeaconWebApp(service)

    status, _headers, body = _request(
        app,
        "POST",
        "/scans",
        body=urlencode({"repository_url": "https://example.com/not/github"}),
    )

    assert status.startswith("400")
    assert "Only HTTPS GitHub repository URLs are supported" in body


def test_health_endpoints_do_not_expose_internal_paths(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path))
    app = DriftBeaconWebApp(service)

    live_status, _headers, live_body = _request(app, "GET", "/health/live")
    ready_status, _headers, ready_body = _request(app, "GET", "/health/ready")

    assert live_status.startswith("200")
    assert json.loads(live_body) == {"status": "alive"}
    assert ready_status.startswith("200")
    assert json.loads(ready_body) == {"status": "ready"}
    assert str(tmp_path) not in live_body
    assert str(tmp_path) not in ready_body


def test_progress_page_updates_step_list_from_polling_state(tmp_path: Path) -> None:
    state = WebScanState(
        scan_id="abcdef123456",
        repository_url="https://github.com/owner/repo.git",
        repository_owner="owner",
        repository_name="repo",
        status="queued",
        message="Queued for analysis.",
        progress=5,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    html = render_progress_page(state)

    assert 'data-step-key="queued"' in html
    assert 'data-step-key="analysing"' in html
    assert "updateProgressSteps(data.status)" in html
    assert "stageLabels[data.status]" in html


def test_readiness_fails_safely_when_storage_is_unhealthy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = WebScanService(_web_config(tmp_path))
    monkeypatch.setattr(service.store, "check_ready", lambda: False)
    app = DriftBeaconWebApp(service)

    status, _headers, body = _request(app, "GET", "/health/ready")

    assert status.startswith("503")
    assert json.loads(body) == {"status": "not_ready"}
    assert str(tmp_path) not in body


def test_web_submission_only_queues_scan(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path))
    app = DriftBeaconWebApp(service)

    status, headers, _body = _request(
        app,
        "POST",
        "/scans",
        body=urlencode({"repository_url": "https://github.com/owner/repo"}),
    )
    scan_id = headers["Location"].rsplit("/", 1)[-1]
    state = service.get(scan_id)

    assert status.startswith("303")
    assert state is not None
    assert state.status == "queued"
    assert service.report_store.load(scan_id) is None


def test_invite_mode_requires_valid_beta_access_code(tmp_path: Path) -> None:
    config = replace(
        _web_config(tmp_path),
        beta=BetaConfig(
            access_mode="invite",
            access_codes=("correct-code",),
            rate_limit_secret="test-secret",
        ),
    )
    service = WebScanService(config)
    app = DriftBeaconWebApp(service)

    invalid = urlencode(
        {
            "repository_url": "https://github.com/owner/repo",
            "beta_access_code": "wrong-code",
        }
    )
    status, _headers, body = _request(app, "POST", "/scans", body=invalid)

    assert status.startswith("403")
    assert "valid beta access code" in body
    assert "wrong-code" not in body
    assert service.store.count_queued_scans() == 0

    valid = urlencode(
        {
            "repository_url": "https://github.com/owner/repo",
            "beta_access_code": "correct-code",
        }
    )
    status, headers, _body = _request(app, "POST", "/scans", body=valid)

    assert status.startswith("303")
    assert headers["Location"].startswith("/scans/")
    assert "correct-code" not in str(service.store.recent_scans(limit=1)[0].to_dict())


def test_kill_switch_rejects_new_scans_but_keeps_reports_accessible(tmp_path: Path) -> None:
    active_config = _web_config(tmp_path)
    service = WebScanService(active_config)
    app = DriftBeaconWebApp(service)
    status, headers, _body = _request(
        app,
        "POST",
        "/scans",
        body=urlencode({"repository_url": "https://github.com/owner/repo"}),
    )
    scan_id = headers["Location"].rsplit("/", 1)[-1]
    worker = WebScanWorker(
        active_config,
        WorkerConfig(worker_id="test-worker", poll_interval_seconds=0.1, stale_seconds=60),
        runner=_fake_runner,
    )
    assert status.startswith("303")
    assert worker.process_once() is True

    paused_config = replace(
        active_config,
        beta=BetaConfig(accepting_scans=False, rate_limit_secret="test-secret"),
    )
    paused_app = DriftBeaconWebApp(WebScanService(paused_config))
    status, _headers, body = _request(
        paused_app,
        "POST",
        "/scans",
        body=urlencode({"repository_url": "https://github.com/owner/other"}),
    )
    assert status.startswith("503")
    assert "temporarily paused" in body

    status, _headers, body = _request(paused_app, "GET", f"/scans/{scan_id}")
    assert status.startswith("200")
    assert "owner/repo" in body


def test_daily_rate_limits_are_sqlite_backed_and_do_not_store_raw_ip(tmp_path: Path) -> None:
    config = replace(
        _web_config(tmp_path),
        max_queued_scans=10,
        beta=BetaConfig(
            max_scans_per_source_per_day=1,
            max_total_scans_per_day=10,
            rate_limit_secret="test-secret",
        ),
    )
    service = WebScanService(config)

    service.submit("https://github.com/owner/one", client_id="203.0.113.7")
    with pytest.raises(ValueError, match="public beta scan limit"):
        service.submit("https://github.com/owner/two", client_id="203.0.113.7")

    expected_hash = hash_submission_source("203.0.113.7", "test-secret")
    usage = service.store.source_daily_usage(
        source_hash=expected_hash,
        date_bucket=datetime.now(UTC).date().isoformat(),
    )
    assert usage == {"accepted": 1, "rejected": 1}
    assert "203.0.113.7" not in config.database_path.read_text(
        encoding="utf-8",
        errors="ignore",
    )


def test_global_daily_rate_limit_rejects_without_queueing(tmp_path: Path) -> None:
    config = replace(
        _web_config(tmp_path),
        max_queued_scans=10,
        beta=BetaConfig(
            max_scans_per_source_per_day=10,
            max_total_scans_per_day=1,
            rate_limit_secret="test-secret",
        ),
    )
    service = WebScanService(config)

    service.submit("https://github.com/owner/one", client_id="203.0.113.7")
    with pytest.raises(ValueError, match="public beta scan limit"):
        service.submit("https://github.com/owner/two", client_id="203.0.113.8")

    assert service.store.count_queued_scans() == 1


def test_trusted_proxy_header_is_used_only_for_configured_proxy() -> None:
    environ: dict[str, object] = {
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_X_FORWARDED_FOR": "203.0.113.7, 10.0.0.1",
    }
    beta = BetaConfig(rate_limit_secret="test-secret")

    assert client_source_from_environ(environ, beta) == "203.0.113.7"

    untrusted = {
        "REMOTE_ADDR": "198.51.100.10",
        "HTTP_X_FORWARDED_FOR": "203.0.113.7",
    }
    assert client_source_from_environ(untrusted, beta) == "198.51.100.10"


def test_sample_report_uses_fixture_data_without_database_job(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path))
    app = DriftBeaconWebApp(service)

    status, _headers, body = _request(app, "GET", "/sample-report")

    assert status.startswith("200")
    assert "Example report" in body
    assert "Production Health" in body
    assert "Top priorities" in body
    assert "View all" in body
    assert "sort=#all-findings" not in body
    assert "example/public-infra-demo" in body
    assert service.store.count_queued_scans() == 0


def test_feedback_submission_stores_optional_email_only_with_consent(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path))
    app = DriftBeaconWebApp(service)
    form = urlencode(
        {
            "helpfulness": "partly",
            "changed_priority": "maybe",
            "difficult_to_understand": "score_difference",
            "comment": "<script>useful but confusing</script>",
            "private_monitoring_interest": "yes",
            "email": "tester@example.com",
        }
    )

    status, headers, _body = _request(app, "POST", "/feedback", body=form)

    assert status.startswith("303")
    assert headers["Location"] == "/sample-report?feedback=thanks"
    rows = service.store.list_feedback()
    assert len(rows) == 1
    assert rows[0].comment == "<script>useful but confusing</script>"
    assert rows[0].difficult_to_understand == "score_difference"
    assert rows[0].private_monitoring_interest is True
    assert rows[0].email is None
    assert rows[0].consent_to_contact is False

    consenting = urlencode(
        {
            "helpfulness": "yes",
            "changed_priority": "yes",
            "comment": "weekly would help",
            "email": "tester@example.com",
            "consent_to_contact": "yes",
        }
    )
    _request(app, "POST", "/feedback", body=consenting, remote_addr="127.0.0.2")
    rows = service.store.list_feedback()
    assert rows[0].email == "tester@example.com"
    assert rows[0].consent_to_contact is True


def test_feedback_honeypot_does_not_store_submission(tmp_path: Path) -> None:
    service = WebScanService(_web_config(tmp_path))
    app = DriftBeaconWebApp(service)
    form = urlencode(
        {
            "helpfulness": "yes",
            "changed_priority": "yes",
            "comment": "spam",
            "website": "https://spam.example",
        }
    )

    status, _headers, _body = _request(app, "POST", "/feedback", body=form)

    assert status.startswith("303")
    assert service.store.list_feedback() == []


def test_sample_report_explains_score_divergence_and_full_explorer() -> None:
    scan, comparison = sample_report_data()

    html = render_repository_report_page(scan, comparison, sample=True)

    assert "Why are these scores so different?" in html
    assert "Production Health is" in html
    assert "Overall Health is" in html
    assert "How this score is calculated" in html
    assert "View all 64 deduplicated active actionable findings" in html
    assert 'href="/sample-report?view=all&amp;sort=recommended&amp;page=1#finding-' in html
    assert 'href="/sample-report?view=all#all-findings" target="_blank"' in html
    assert "data-report-tab=\"overview\"" in html
    assert "data-theme-toggle" in html
    assert 'class="header-scan-form"' in html
    assert 'id="header_repository_url"' in html
    assert 'class="theme-icon theme-icon-sun"' in html
    assert 'class="theme-icon theme-icon-moon"' in html
    assert "const theme = stored || 'dark'" in html
    assert "localStorage.setItem('driftbeacon-theme'" in html
    assert "help-popover" in html
    assert 'class="brand-lockup"' in html
    assert 'class="brand-mark"' in html
    assert 'class="repo-identity"' in html
    assert 'class="repo-owner">example</span>' in html
    assert 'class="repo-name">public-infra-demo</span>' in html
    assert "Repository metric" in html
    assert "support-score" not in html
    assert ".site-footer { position:fixed" in html
    assert 'class="footer-links"' in html
    assert "--accent:#63e6aa" in html
    assert "@keyframes beacon-flow" in html
    assert 'class="scanner-status-card"' in html
    assert 'class="coverage-breakdown"' in html
    assert 'class="breakdown-list"' in html
    assert 'class="metric-row"' in html
    assert 'class="metric-pill metric-critical"' in html
    assert "Checkov config" in html
    assert "Trivy vuln" in html
    assert "table-scroll" not in html
    assert "What was hardest to understand?" in html
    assert "overflow-wrap:anywhere" in html


def test_report_finding_explorer_filters_and_paginates() -> None:
    scan, comparison = sample_report_data()

    filtered = render_repository_report_page(
        scan,
        comparison,
        sample=True,
        options=ReportFindingOptions(severity="medium"),
    )
    second_page = render_repository_report_page(
        scan,
        comparison,
        sample=True,
        options=ReportFindingOptions(page=2),
    )
    expanded_second_page = render_repository_report_page(
        scan,
        comparison,
        sample=True,
        options=ReportFindingOptions(view="all", page=2),
    )

    assert "Showing 7 filtered results from 64 deduplicated active actionable findings." in filtered
    assert 'value="medium" selected' in filtered
    assert "Page 2 of 5" in second_page
    assert "Open the full findings explorer" in second_page
    assert "Page 2 of 2" in expanded_second_page
    assert "Expanded findings explorer" in expanded_second_page
    assert "Generated example dependency vulnerability" in expanded_second_page


def test_report_top_summary_handles_exactly_three_findings() -> None:
    scan, _comparison = sample_report_data()
    scan.findings = scan.findings[:3]
    comparison = compare_scans(scan, None)

    html = render_repository_report_page(scan, comparison, sample=True)

    assert "All 3 deduplicated active actionable findings are shown here." in html
    assert "View all 3" not in html


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
    assert html.index("Production Health") < html.index("Top priorities")
    assert "Top priorities" in html
    assert "All findings" in html
    assert "How to read this report" in html
    assert "Scanner coverage" in html
    assert "AWS Access Key ID" in html
    assert "Why this matters" in html
    assert "Remove the hardcoded secret and rotate it if it was committed." in html
    assert "Production path" in html
    assert "Partial coverage" in html
    assert "Provisional grade" in html
    assert "Supporting evidence" not in html
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
        max_queued_scans=10,
        max_scan_seconds=10,
        scanner_timeout_seconds=10,
        clone_timeout_seconds=10,
        retention_days=7,
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
        beta=BetaConfig(
            max_scans_per_source_per_day=2,
            max_total_scans_per_day=25,
            rate_limit_secret="test-secret",
        ),
    )
    service = WebScanService(config)

    first = service.submit("https://github.com/owner/one", client_id="client")
    second = service.submit("https://github.com/owner/two", client_id="client")

    assert first.status == "queued"
    assert second.status == "queued"
    assert not hasattr(config, "plan")

    with pytest.raises(ValueError, match="public beta scan limit"):
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
        max_repository_files=10,
        max_repository_bytes=1024 * 1024,
        top_findings=3,
        beta=BetaConfig(rate_limit_secret="test-secret"),
    )
    service = WebScanService(config)
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

    assert "scanner exited 2" not in html
    assert "Scan could not complete" in html


def test_unsupported_target_report_does_not_show_perfect_health() -> None:
    scan, comparison = sample_report_data()
    scan.findings = []
    scan.health_score = None
    scan.summary = {
        "coverage_state": "not_scored_no_supported_files",
        "production_coverage_state": "not_scored_no_supported_files",
        "production_health_score": None,
        "production_grade": None,
        "production_score_reason": "No supported files were detected.",
    }

    html = render_repository_report_page(scan, comparison)

    assert "No eligible scan targets were found" in html
    assert "Not scored" in html
    assert "100/100" not in html
