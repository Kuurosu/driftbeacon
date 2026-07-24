from __future__ import annotations

from driftbeacon.comparison import compare_scans
from driftbeacon.models import ComparisonSummary, Finding, ScanResult


def test_first_run_marks_all_current_findings_new(current_scan: ScanResult) -> None:
    comparison = compare_scans(current_scan, None)

    assert comparison.has_baseline is False
    assert len(comparison.new_findings) == len(current_scan.findings)
    assert not comparison.resolved_findings
    assert all(finding.status == "new" for finding in current_scan.findings)


def test_compare_detects_new_recurring_resolved_and_severity_changes(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    comparison = compare_scans(current_scan, previous_scan)

    assert comparison.has_baseline is True
    assert {finding.rule_id for finding in comparison.recurring_findings} == {
        "CKV_AWS_355",
        "CVE-2025-12345",
    }
    assert {finding.rule_id for finding in comparison.new_findings} == {
        "CKV_AWS_20",
        "aws-access-key-id",
    }
    assert [finding.rule_id for finding in comparison.resolved_findings] == ["CKV_AWS_24"]
    assert comparison.severity_changes == [
        {
            "fingerprint": "2deedfe59ec161bcc047",
            "rule_id": "CKV_AWS_355",
            "title": "Wildcard IAM permissions added",
            "from": "medium",
            "to": "high",
        }
    ]
    assert comparison.health_score_change is not None
    assert comparison.active_findings_change == 1


def test_comparison_summary_counts_only_actionable_severities() -> None:
    actionable = _finding("high-1", "high", "resolved")
    unknown = _finding("unknown-1", "unknown", "resolved")
    comparison = ComparisonSummary(
        has_baseline=True,
        new_findings=[
            _finding("critical-1", "critical", "new"),
            _finding("unknown-2", "unknown", "new"),
        ],
        recurring_findings=[
            _finding("medium-1", "medium", "recurring"),
            _finding("info-1", "info", "recurring"),
        ],
        resolved_findings=[actionable, unknown],
        severity_changes=[],
        health_score_change=None,
        active_findings_change=None,
    )

    assert comparison.to_dict()["counts"] == {
        "new": 1,
        "recurring": 1,
        "resolved": 1,
        "severity_changes": 0,
    }


def _finding(fingerprint: str, severity: str, status: str) -> Finding:
    return Finding(
        id=fingerprint,
        scanner="checkov",
        rule_id=fingerprint,
        title="Finding",
        description="Finding",
        severity=severity,  # type: ignore[arg-type]
        category="misconfiguration",
        file_path="main.tf",
        line_start=1,
        resource="aws_example.demo",
        status=status,  # type: ignore[arg-type]
        first_seen=None,
        last_seen=None,
        fingerprint=fingerprint,
    )
