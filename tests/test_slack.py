from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from driftbeacon.analysis_metrics import enrich_findings_for_analysis
from driftbeacon.comparison import compare_scans
from driftbeacon.models import ScanResult
from driftbeacon.redaction import redact_secrets
from driftbeacon.reporting import generate_report
from driftbeacon.slack import (
    SlackPayloadBuild,
    build_slack_payload,
    build_slack_payload_from_data,
    build_slack_payload_from_path,
    detect_json_report_type,
    detect_markdown_report_type,
    markdown_to_slack_summary,
    send_slack_report,
    send_slack_report_from_path,
)


def _payload_text(payload: dict[str, object]) -> str:
    parts: list[str] = [str(payload.get("text", ""))]
    for block in payload.get("blocks", []):
        if not isinstance(block, dict):
            continue
        text = block.get("text")
        if isinstance(text, dict):
            parts.append(str(text.get("text", "")))
    return "\n".join(parts)


def _prepare_repository_payload(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    enrich_findings_for_analysis(current_scan.findings)
    comparison = compare_scans(current_scan, previous_scan)
    current_scan.summary.update(
        {
            "coverage_state": "complete_coverage",
            "score_state": "scored",
            "grade_provisional": False,
            "production_health_score": 80,
            "production_grade": "B",
            "production_grade_provisional": False,
            "production_score_reason": "Production Health calculated from production paths.",
        }
    )
    report = generate_report(current_scan, comparison)
    return current_scan.to_dict(), comparison.to_dict(), report


def _portfolio_summary_json() -> dict[str, Any]:
    return {
        "report_type": "portfolio_summary",
        "schema_version": "2.0",
        "metadata": {
            "scan_date": "2026-07-24T09:00:00+00:00",
            "repositories_requested": 3,
            "successful_scans": 2,
            "failed_scans": 1,
            "scan_mode": "initial_baseline",
        },
        "aggregate_statistics": {
            "average_health_score": 24,
            "median_health_score": 10,
            "scored_repositories": 2,
            "unscored_repositories": 0,
            "repositories_with_scanner_errors": 1,
            "total_actionable_findings": 49942,
        },
        "repository_results": [
            {
                "repository": "argoproj/argo-cd",
                "status": "success",
                "health_score": 0,
                "grade": "F",
                "grade_provisional": True,
                "coverage_state": "partial_coverage",
                "production_health_score": 0,
                "production_grade": "F",
                "production_grade_provisional": True,
                "production_critical_findings": 2,
                "production_high_findings": 4,
                "production_medium_findings": 8,
                "production_low_findings": 16,
                "finding_source_breakdown": {
                    "trivy_misconfiguration": {"total_actionable": 30}
                },
            },
            {
                "repository": "hashicorp/terraform-provider-aws",
                "status": "success",
                "health_score": 20,
                "grade": "F",
                "grade_provisional": False,
                "coverage_state": "complete_coverage",
                "production_health_score": 100,
                "production_grade": "A",
                "production_grade_provisional": True,
                "production_critical_findings": 0,
                "production_high_findings": 0,
                "production_medium_findings": 0,
                "production_low_findings": 0,
                "finding_source_breakdown": {
                    "checkov_configuration": {"total_actionable": 7}
                },
            },
        ],
        "common_findings": [
            {
                "title": "Default security context configured",
                "total_occurrences": 3550,
            }
        ],
        "scanner_issues": [
            {"repository": "argoproj/argo-cd", "scanner": "checkov", "status": "timed_out"}
        ],
        "failure_details": [
            {
                "repository": "bad/repo",
                "git_url": "https://github.com/bad/repo.git",
                "error": "git clone failed",
            }
        ],
    }


def test_slack_payload_redacts_and_escapes_untrusted_text() -> None:
    payload = build_slack_payload(
        "# DriftBeacon Report\n"
        "**Repository:** <bad> password=secret-value https://hooks.slack.com/services/T/B/C  \n"
        "**Health score:** 90/100 (unchanged)  \n"
        "**Trend:** unchanged\n"
    )

    encoded = json.dumps(payload)
    assert "secret-value" not in encoded
    assert "hooks.slack.com" not in encoded
    assert "&lt;bad&gt;" in encoded


def test_slack_payload_uses_digest_blocks() -> None:
    payload = build_slack_payload(
        "# DriftBeacon Report\n"
        "**Repository:** driftbeacon-mvp  \n"
        "**Branch:** main  \n"
        "**Health score:** 12/100 (down 8 points)  \n"
        "**Active findings:** 6  \n"
        "**Trend:** 2 new findings, 3 recurring findings, 1 resolved finding\n"
        "## Fix these first\n"
        "### 1. AWS Access Key ID\n"
        "**Severity:** Critical | **Category:** secret  \n"
        "**Location:** terraform/secrets.tf:4  \n"
        "**Why:** Ranked highly because it is a new critical-severity secret issue.  \n"
        "**Action:** Remove the hardcoded secret and rotate it.  \n"
        "## Scanner status\n"
        "- Checkov: Success: loaded 3 findings from JSON\n"
        "- Trivy: Success: loaded 3 findings from JSON\n"
    )

    blocks = payload["blocks"]  # type: ignore[assignment]
    text = _payload_text(payload)
    assert blocks[0]["type"] == "header"  # type: ignore[index]
    assert "Top priorities" in text
    assert "AWS Access Key ID" in text
    assert "Why this matters" in text
    assert "Recommended action" in text
    assert "Scanner status" in text


def test_repository_json_slack_output_is_actionable(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    report_data, comparison_data, markdown = _prepare_repository_payload(
        current_scan,
        previous_scan,
    )
    payload = build_slack_payload_from_data(report_data, comparison_data)
    text = _payload_text(payload)

    assert "Kuurosu/driftbeacon" in text
    assert "Overall Health" in text
    assert "Production Health" in text
    assert "80/100 (B)" in text
    assert "Trend" in text
    assert "Active findings" in text
    assert "AWS Access Key ID" in text
    assert "Rule: aws-access-key-id" in text
    assert "Severity: Critical" in text
    assert "Location: terraform/production/secrets.tf:4" in text
    assert "Directory group: production" in text
    assert "Source: Trivy secrets" in text
    assert "Why this matters" in text
    assert "Recommended action" in text
    assert "Status: new" in text
    assert "Scanner status" in text
    assert "Recently resolved" in text
    assert "Security group allows unrestricted SSH" in text
    assert "No active findings were detected" not in text
    assert "No scanner status was recorded" not in text

    assert "**Rule ID:** aws-access-key-id" in markdown
    assert "**Why:**" in markdown
    assert "**Action:** Remove the hardcoded secret and rotate it if it was committed." in markdown


def test_report_file_prefers_repository_sibling_json(
    tmp_path: Path,
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    report_data, comparison_data, _markdown = _prepare_repository_payload(
        current_scan,
        previous_scan,
    )
    (tmp_path / "current-scan.json").write_text(json.dumps(report_data), encoding="utf-8")
    (tmp_path / "comparison-summary.json").write_text(
        json.dumps(comparison_data),
        encoding="utf-8",
    )
    (tmp_path / "report.md").write_text(
        "# DriftBeacon Report\n**Repository:** unknown\nNo active findings were detected.\n",
        encoding="utf-8",
    )

    built = build_slack_payload_from_path(tmp_path / "report.md")
    text = _payload_text(built.payload)

    assert isinstance(built, SlackPayloadBuild)
    assert built.warning is None
    assert "Kuurosu/driftbeacon" in text
    assert "AWS Access Key ID" in text
    assert "Recently resolved" in text
    assert "Repository:* unknown" not in text


def test_missing_sibling_json_uses_markdown_fallback_with_warning(tmp_path: Path) -> None:
    report_path = tmp_path / "report.md"
    report_path.write_text(
        "# DriftBeacon Weekly\n"
        "Repository: driftbeacon-mvp\n"
        "Branch: main\n"
        "Health score: 12/100\n"
        "## Fix these first\n"
        "### 1. AWS Access Key ID\n"
        "**Severity:** Critical\n"
        "**Location:** terraform/secrets.tf:4\n",
        encoding="utf-8",
    )

    built = build_slack_payload_from_path(report_path)
    text = _payload_text(built.payload)

    assert built.warning == (
        "Warning: structured JSON not found; used Markdown compatibility fallback."
    )
    assert "DriftBeacon Repository Report" in text
    assert "driftbeacon-mvp" in text
    assert "AWS Access Key ID" in text


def test_portfolio_json_slack_output_is_portfolio_specific() -> None:
    payload = build_slack_payload_from_data(_portfolio_summary_json())
    text = _payload_text(payload)

    assert "DriftBeacon Portfolio Summary" in text
    assert "Repositories requested:* 3" in text
    assert "Average health:* 24" in text
    assert "Median health:* 10" in text
    assert "Repositories requiring attention" in text
    assert "argoproj/argo-cd" in text
    assert "Overall Health: 0/F*" in text
    assert "Production Health: 0/F*" in text
    assert "Coverage: Partial" in text
    assert "Default security context configured" in text
    assert "Scanner issues" in text
    assert "1 repositories could not be processed" in text
    assert "DriftBeacon Repository Report" not in text
    assert "Repository:* unknown" not in text
    assert "No active findings were detected" not in text
    assert "No scanner status was recorded" not in text


def test_analysis_summary_markdown_prefers_portfolio_sibling_json(tmp_path: Path) -> None:
    (tmp_path / "analysis-summary.json").write_text(
        json.dumps(_portfolio_summary_json()),
        encoding="utf-8",
    )
    (tmp_path / "analysis-summary.md").write_text(
        "# DriftBeacon Report\n**Repository:** unknown\n",
        encoding="utf-8",
    )

    built = build_slack_payload_from_path(tmp_path / "analysis-summary.md")
    text = _payload_text(built.payload)

    assert built.warning is None
    assert "DriftBeacon Portfolio Summary" in text
    assert "Repositories requested:* 3" in text
    assert "Repository:* unknown" not in text


def test_portfolio_markdown_fallback_detects_summary(tmp_path: Path) -> None:
    summary_path = tmp_path / "analysis-summary.md"
    summary_path.write_text(
        "# DriftBeacon Repository Analysis Summary\n\n"
        "**Scan date:** 2026-07-24T09:00:00+00:00  \n"
        "**Repositories requested:** 2  \n"
        "**Successful scans:** 1  \n"
        "**Failed scans:** 1  \n"
        "**Scored repositories:** 1  \n"
        "**Unscored repositories:** 0  \n"
        "**Run type:** Initial baseline\n\n"
        "## Executive summary\n"
        "- Average health score: 24\n"
        "- Median health score: 24\n\n"
        "## Leaderboard\n\n"
        "| Rank | Repository | Health | Production Health |\n"
        "| ---: | --- | ---: | ---: |\n"
        "| 1 | risky/repo | 24 | 12 |\n\n"
        "## Scanner issues\n\n"
        "| Repository | Scanner | Status |\n"
        "| --- | --- | --- |\n"
        "| risky/repo | checkov | timed_out |\n",
        encoding="utf-8",
    )

    built = build_slack_payload_from_path(summary_path)
    text = _payload_text(built.payload)

    assert built.warning == (
        "Warning: structured JSON not found; used Markdown compatibility fallback."
    )
    assert "DriftBeacon Portfolio Summary" in text
    assert "risky/repo" in text
    assert "timed_out" in text
    assert "DriftBeacon Repository Report" not in text


def test_portfolio_slack_handles_empty_summary() -> None:
    payload = build_slack_payload_from_data(
        {
            "report_type": "portfolio_summary",
            "metadata": {
                "scan_date": "2026-07-24T09:00:00+00:00",
                "repositories_requested": 0,
                "successful_scans": 0,
                "failed_scans": 0,
                "scan_mode": "initial_baseline",
            },
            "aggregate_statistics": {
                "average_health_score": 0,
                "median_health_score": 0,
                "scored_repositories": 0,
                "unscored_repositories": 0,
                "repositories_with_scanner_errors": 0,
                "total_actionable_findings": 0,
            },
            "repository_results": [],
            "common_findings": [],
            "scanner_issues": [],
            "failure_details": [],
        }
    )
    text = _payload_text(payload)

    assert "No scored repositories" in text
    assert "No common actionable findings recorded" in text
    assert "No scanner failures recorded" in text
    assert "0 repositories could not be processed" in text


def test_report_type_detection_rejects_unsupported_shapes(
    current_scan: ScanResult,
) -> None:
    assert detect_json_report_type(current_scan.to_dict()) == "repository"
    assert detect_json_report_type(_portfolio_summary_json()) == "portfolio_summary"
    assert (
        detect_markdown_report_type("# DriftBeacon Report\n**Repository:** demo\n")
        == "repository"
    )
    assert (
        detect_markdown_report_type(
            "# DriftBeacon Repository Analysis Summary\n\n"
            "## Executive summary\n"
            "## Leaderboard\n"
        )
        == "portfolio_summary"
    )

    with pytest.raises(ValueError, match="Unsupported or unrecognised"):
        build_slack_payload("# Not a DriftBeacon report\n")
    with pytest.raises(ValueError, match="Unsupported or unrecognised"):
        build_slack_payload_from_data({"hello": "world"})


def test_report_path_errors_are_clear(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        build_slack_payload_from_path(tmp_path / "missing.md")

    bad_json = tmp_path / "current-scan.json"
    bad_json.write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="Malformed DriftBeacon JSON report"):
        build_slack_payload_from_path(bad_json)


def test_markdown_to_slack_summary_preserves_report_shape() -> None:
    summary = markdown_to_slack_summary(
        "# DriftBeacon Weekly\n"
        "**Repository:** driftbeacon-mvp  \n"
        "## Fix these first\n"
        "### 1. AWS Access Key ID\n"
        "- 1 resolved finding\n"
    )

    assert summary.splitlines() == [
        "*DriftBeacon Weekly*",
        "*Repository:* driftbeacon-mvp",
        "*Fix these first*",
        "*1. AWS Access Key ID*",
        "- 1 resolved finding",
    ]


def test_slack_send_skips_when_webhook_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    result = send_slack_report("hello")

    assert result.sent is False
    assert result.message == "Slack skipped: SLACK_WEBHOOK_URL is not set."


def test_path_send_validates_report_before_missing_webhook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    report_path = tmp_path / "report.md"
    report_path.write_text("# Not a DriftBeacon report\n", encoding="utf-8")

    result = send_slack_report_from_path(report_path)

    assert result.sent is False
    assert result.message == "Unsupported or unrecognised DriftBeacon report format."


def test_redaction_removes_obvious_secret_shapes() -> None:
    redacted = redact_secrets("token=abc12345678901234567890 AKIA1234567890ABCDEF")

    assert "abc12345678901234567890" not in redacted
    assert "AKIA1234567890ABCDEF" not in redacted
