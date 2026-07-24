from __future__ import annotations

from dataclasses import replace

from driftbeacon.models import Finding, Severity
from driftbeacon.scoring import calculate_health_score


def _finding(severity: Severity, *, fingerprint: str = "fp", status: str = "new") -> Finding:
    return Finding(
        id=f"id-{fingerprint}",
        scanner="test",
        rule_id="TEST_RULE",
        title="Test finding",
        description="Test finding",
        severity=severity,
        category="misconfiguration",
        file_path="main.tf",
        line_start=1,
        resource="resource.demo",
        status=status,  # type: ignore[arg-type]
        first_seen=None,
        last_seen=None,
        fingerprint=fingerprint,
    )


def test_zero_active_findings_produces_score_of_100() -> None:
    assert calculate_health_score([]) == 100
    assert calculate_health_score([_finding("critical", status="resolved")]) == 100


def test_low_only_findings_reduce_score_slightly() -> None:
    score = calculate_health_score(
        [_finding("low", fingerprint=f"low-{index}") for index in range(4)]
    )

    assert 95 <= score < 100


def test_medium_findings_reduce_score_more_than_low_findings() -> None:
    low_score = calculate_health_score([_finding("low", fingerprint="low")])
    medium_score = calculate_health_score([_finding("medium", fingerprint="medium")])

    assert medium_score < low_score


def test_high_findings_reduce_score_substantially() -> None:
    score = calculate_health_score(
        [_finding("high", fingerprint=f"high-{index}") for index in range(3)]
    )

    assert score <= 64


def test_critical_findings_reduce_score_most() -> None:
    critical_score = calculate_health_score([_finding("critical", fingerprint="critical")])
    high_score = calculate_health_score([_finding("high", fingerprint="high")])

    assert critical_score < high_score


def test_duplicate_findings_do_not_multiply_penalty() -> None:
    finding = _finding("critical", fingerprint="same")

    assert calculate_health_score([finding, replace(finding)]) == calculate_health_score([finding])


def test_first_scan_new_status_does_not_affect_score() -> None:
    new_finding = _finding("high", status="new")
    recurring_finding = _finding("high", status="recurring")

    assert calculate_health_score([new_finding]) == calculate_health_score([recurring_finding])


def test_informational_and_unknown_findings_do_not_affect_score() -> None:
    assert calculate_health_score([_finding("info"), _finding("unknown", fingerprint="u")]) == 100


def test_score_always_remains_between_zero_and_100() -> None:
    findings = [_finding("critical", fingerprint=f"critical-{index}") for index in range(100)]

    score = calculate_health_score(findings)

    assert 0 <= score <= 100
