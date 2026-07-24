"""Deterministic infrastructure health scoring."""

from __future__ import annotations

import math

from .models import Finding, Severity

ACTIONABLE_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")
SCORE_FORMULA_VERSION = "driftbeacon-health-v2"
HEALTH_RISK_SCALE = 80.0
EXTREME_ZERO_RISK = 1000.0

SEVERITY_WEIGHTS: dict[Severity, float] = {
    "critical": 12.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.0,
    "unknown": 0.0,
}


def calculate_health_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 score from active findings using health model v2.

    Only deduplicated active critical, high, medium, and low findings count by default.
    Informational and unknown-severity findings are reported for auditability but do not
    reduce health. First-scan "new" status does not affect the score.
    """

    weighted = weighted_risk(findings)
    score = round(100 * math.exp(-weighted / HEALTH_RISK_SCALE))
    if 0 < weighted < EXTREME_ZERO_RISK and score == 0:
        return 1
    return max(0, min(100, score))


def weighted_risk(findings: list[Finding]) -> float:
    """Return weighted actionable risk before health-score decay."""

    return sum(
        SEVERITY_WEIGHTS[finding.severity] for finding in actionable_active_findings(findings)
    )


def actionable_active_findings(findings: list[Finding]) -> list[Finding]:
    """Return deduplicated active findings that affect health and severity totals."""

    return [
        finding
        for finding in actionable_findings(findings)
        if finding.status != "resolved" and not finding.excluded_from_score
    ]


def actionable_findings(findings: list[Finding]) -> list[Finding]:
    """Return deduplicated findings with actionable severities regardless of lifecycle."""

    return [
        finding
        for finding in deduplicate_findings_by_fingerprint(findings)
        if finding.severity in ACTIONABLE_SEVERITIES and not finding.excluded_from_score
    ]


def ignored_active_findings(findings: list[Finding]) -> list[Finding]:
    """Return active findings kept for audit but ignored by the health score."""

    return [
        finding
        for finding in deduplicate_findings_by_fingerprint(findings)
        if finding.status != "resolved" and finding.severity not in ACTIONABLE_SEVERITIES
    ]


def deduplicate_findings_by_fingerprint(findings: list[Finding]) -> list[Finding]:
    """Collapse exact duplicate fingerprints without merging distinct resources."""

    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Count deduplicated actionable active findings by severity."""

    actionable = actionable_active_findings(findings)
    return {
        "critical": sum(1 for finding in actionable if finding.severity == "critical"),
        "high": sum(1 for finding in actionable if finding.severity == "high"),
        "medium": sum(1 for finding in actionable if finding.severity == "medium"),
        "low": sum(1 for finding in actionable if finding.severity == "low"),
        "info": 0,
        "unknown": 0,
    }
