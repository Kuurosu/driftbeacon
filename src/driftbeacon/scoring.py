"""Deterministic infrastructure health scoring."""

from __future__ import annotations

from .models import Finding, Severity

ACTIONABLE_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")

SEVERITY_WEIGHTS: dict[Severity, float] = {
    "critical": 30.0,
    "high": 12.0,
    "medium": 4.0,
    "low": 0.25,
    "info": 0.0,
    "unknown": 0.0,
}

SEVERITY_CAPS: dict[Severity, float] = {
    "critical": 70.0,
    "high": 50.0,
    "medium": 30.0,
    "low": 10.0,
    "info": 0.0,
    "unknown": 0.0,
}


def calculate_health_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 score from active findings.

    Only deduplicated active critical, high, medium, and low findings count by default.
    Informational and unknown-severity findings are reported for auditability but do not
    reduce health. First-scan "new" status does not affect the score.
    """

    penalties_by_severity: dict[Severity, float] = {
        "critical": 0.0,
        "high": 0.0,
        "medium": 0.0,
        "low": 0.0,
        "info": 0.0,
        "unknown": 0.0,
    }
    for finding in actionable_active_findings(findings):
        penalties_by_severity[finding.severity] += SEVERITY_WEIGHTS[finding.severity]

    penalty = sum(
        min(penalties_by_severity[severity], SEVERITY_CAPS[severity])
        for severity in ACTIONABLE_SEVERITIES
    )
    return max(0, min(100, round(100 - min(penalty, 100))))


def actionable_active_findings(findings: list[Finding]) -> list[Finding]:
    """Return deduplicated active findings that affect health and severity totals."""

    return [
        finding
        for finding in actionable_findings(findings)
        if finding.status != "resolved"
    ]


def actionable_findings(findings: list[Finding]) -> list[Finding]:
    """Return deduplicated findings with actionable severities regardless of lifecycle."""

    return [
        finding
        for finding in deduplicate_findings_by_fingerprint(findings)
        if finding.severity in ACTIONABLE_SEVERITIES
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
