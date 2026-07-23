"""Deterministic infrastructure health scoring."""

from __future__ import annotations

from .models import Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "critical": 25,
    "high": 12,
    "medium": 5,
    "low": 2,
    "info": 0,
    "unknown": 3,
}

SEVERITY_CAPS: dict[Severity, int] = {
    "critical": 50,
    "high": 36,
    "medium": 30,
    "low": 12,
    "info": 0,
    "unknown": 12,
}


def calculate_health_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 score from active findings.

    Resolved findings do not count against the current score. New findings carry
    a small multiplier so fresh regressions are visible without overwhelming the
    severity weighting.
    """

    penalties_by_severity: dict[Severity, float] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    for finding in findings:
        if finding.status == "resolved":
            continue
        multiplier = 1.2 if finding.status == "new" else 1.0
        penalties_by_severity[finding.severity] += SEVERITY_WEIGHTS[finding.severity] * multiplier

    capped_penalty = sum(
        min(penalty, SEVERITY_CAPS[severity]) for severity, penalty in penalties_by_severity.items()
    )
    capped_penalty = min(capped_penalty, 90)
    return max(0, min(100, round(100 - capped_penalty)))
