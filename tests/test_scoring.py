from __future__ import annotations

from dataclasses import replace

from driftbeacon.models import Finding, Severity
from driftbeacon.scoring import SCORE_FORMULA_VERSION, calculate_health_score


def _finding(
    severity: Severity,
    *,
    fingerprint: str = "fp",
    status: str = "new",
    excluded: bool = False,
) -> Finding:
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
        excluded_from_score=excluded,
        score_exclusion_reason="excluded_path_group:tests" if excluded else None,
    )


def _findings(
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    for severity, count in {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }.items():
        findings.extend(
            _finding(severity, fingerprint=f"{severity}-{index}")  # type: ignore[arg-type]
            for index in range(count)
        )
    return findings


def test_score_formula_version_is_named() -> None:
    assert SCORE_FORMULA_VERSION == "driftbeacon-health-v2"


def test_clean_repository_scores_100() -> None:
    assert calculate_health_score([]) == 100
    assert calculate_health_score([_finding("critical", status="resolved")]) == 100


def test_minor_repository_scores_healthy_above_70() -> None:
    assert calculate_health_score(_findings(medium=2, low=5)) > 70


def test_moderate_repository_is_degraded_but_above_zero() -> None:
    score = calculate_health_score(_findings(high=3, medium=8, low=10))

    assert 0 < score < 80


def test_serious_repository_is_poor_but_not_automatically_zero() -> None:
    score = calculate_health_score(_findings(critical=2, high=8, medium=20, low=20))

    assert 0 < score < 40


def test_extreme_repository_is_near_zero() -> None:
    score = calculate_health_score(_findings(critical=100, high=1000, medium=5000))

    assert score <= 1


def test_monotonicity_when_adding_actionable_findings() -> None:
    base = calculate_health_score(_findings(high=1, medium=1))
    for severity in ("critical", "high", "medium", "low"):
        with_added = calculate_health_score(
            _findings(high=1, medium=1)
            + [_finding(severity, fingerprint=f"added-{severity}")]  # type: ignore[arg-type]
        )
        assert with_added <= base


def test_severity_ordering_for_single_findings() -> None:
    critical_score = calculate_health_score([_finding("critical", fingerprint="critical")])
    high_score = calculate_health_score([_finding("high", fingerprint="high")])
    medium_score = calculate_health_score([_finding("medium", fingerprint="medium")])
    low_score = calculate_health_score([_finding("low", fingerprint="low")])

    assert critical_score < high_score < medium_score < low_score


def test_scan_like_examples_do_not_all_collapse_to_zero() -> None:
    rds = calculate_health_score(_findings(critical=3, high=2, medium=5, low=3))
    eks = calculate_health_score(_findings(critical=8, high=7, medium=12, low=24))
    lambda_repo = calculate_health_score(_findings(critical=1, high=24, medium=11, low=11))

    assert all(score > 0 for score in (rds, eks, lambda_repo))
    assert len({rds, eks, lambda_repo}) > 1


def test_duplicates_first_scan_status_and_ignored_records_do_not_affect_score() -> None:
    finding = _finding("critical", fingerprint="same")
    assert calculate_health_score([finding, replace(finding)]) == calculate_health_score([finding])
    assert calculate_health_score([_finding("high", status="new")]) == calculate_health_score(
        [_finding("high", status="recurring")]
    )
    ignored = [
        _finding("info", fingerprint="info"),
        _finding("unknown", fingerprint="unknown"),
        _finding("critical", fingerprint="excluded", excluded=True),
    ]
    assert calculate_health_score(ignored) == 100


def test_score_always_remains_between_zero_and_100() -> None:
    score = calculate_health_score(_findings(critical=200, high=200, medium=200, low=200))

    assert 0 <= score <= 100
