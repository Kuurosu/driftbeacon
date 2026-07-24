from __future__ import annotations

from copy import deepcopy

from driftbeacon.models import Finding
from driftbeacon.scoring import calculate_health_score


def test_health_score_subtracts_weighted_active_findings(current_scan: object) -> None:
    findings = current_scan.findings  # type: ignore[attr-defined]
    score = calculate_health_score(findings)

    assert 0 <= score < 100


def test_resolved_findings_do_not_penalise_score(current_scan: object) -> None:
    finding = deepcopy(current_scan.findings[0])  # type: ignore[attr-defined]
    finding.status = "resolved"

    assert calculate_health_score([finding]) == 100


def test_new_findings_penalise_slightly_more_than_recurring(current_scan: object) -> None:
    new_finding: Finding = deepcopy(current_scan.findings[0])  # type: ignore[attr-defined]
    recurring_finding: Finding = deepcopy(current_scan.findings[0])  # type: ignore[attr-defined]
    new_finding.status = "new"
    recurring_finding.status = "recurring"

    assert calculate_health_score([new_finding]) < calculate_health_score([recurring_finding])
