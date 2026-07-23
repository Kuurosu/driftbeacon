from __future__ import annotations

from DriftBeacon.comparison import compare_scans
from DriftBeacon.models import ScanResult


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
