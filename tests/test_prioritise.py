from __future__ import annotations

from datetime import UTC, datetime

from DriftBeacon.comparison import compare_scans
from DriftBeacon.models import ScanResult
from DriftBeacon.prioritise import is_production_like, prioritise_findings, priority_score


def test_priority_order_considers_more_than_severity(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    compare_scans(current_scan, previous_scan)
    top = prioritise_findings(
        current_scan.findings,
        limit=3,
        now=datetime(2026, 7, 23, tzinfo=UTC),
    )

    assert len(top) == 3
    assert "CKV_AWS_19" not in {item.finding.rule_id for item in top}
    assert top[0].score >= top[-1].score
    assert "Ranked highly because" in top[0].reason


def test_production_and_blast_radius_raise_priority(current_scan: ScanResult) -> None:
    iam = next(finding for finding in current_scan.findings if finding.rule_id == "CKV_AWS_355")
    s3 = next(finding for finding in current_scan.findings if finding.rule_id == "CKV_AWS_20")

    assert is_production_like(iam.file_path)
    assert priority_score(iam) >= priority_score(s3)
