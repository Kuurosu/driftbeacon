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

SCORE_DAMPING_FACTOR = 100


def calculate_health_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 score from active findings.

    Resolved findings do not count against the current score. New findings carry a small
    multiplier so fresh regressions are visible. A diminishing-returns curve avoids flattening
    noisy repositories to the same score, which keeps trend deltas useful in demos and CI.
    """

    raw_penalty = 0.0
    for finding in findings:
        if finding.status == "resolved":
            continue
        multiplier = 1.2 if finding.status == "new" else 1.0
        raw_penalty += SEVERITY_WEIGHTS[finding.severity] * multiplier

    score = 100 / (1 + (raw_penalty / SCORE_DAMPING_FACTOR))
    return max(0, min(100, round(score)))
