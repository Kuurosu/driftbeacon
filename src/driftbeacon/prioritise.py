"""Transparent prioritisation rules for the top findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .config import DEFAULT_PRODUCTION_PATTERNS
from .models import Finding, Severity

SEVERITY_PRIORITY: dict[Severity, int] = {
    "critical": 100,
    "high": 75,
    "medium": 45,
    "low": 20,
    "unknown": 15,
    "info": 5,
}

CATEGORY_PRIORITY: dict[str, int] = {
    "secret": 30,
    "iam": 25,
    "vulnerability": 20,
    "network": 15,
    "storage": 10,
    "container": 8,
    "misconfiguration": 5,
}


@dataclass(frozen=True, slots=True)
class PrioritisedFinding:
    """A finding with its transparent priority score and explanation."""

    finding: Finding
    score: int
    reason: str


def prioritise_findings(
    findings: list[Finding],
    *,
    limit: int = 3,
    production_patterns: tuple[str, ...] = DEFAULT_PRODUCTION_PATTERNS,
    now: datetime | None = None,
) -> list[PrioritisedFinding]:
    """Return the most important active findings using deterministic rules."""

    timestamp = now or datetime.now(UTC)
    scored = [
        PrioritisedFinding(
            finding=finding,
            score=priority_score(finding, production_patterns, timestamp),
            reason=priority_reason(finding, production_patterns, timestamp),
        )
        for finding in findings
        if finding.status != "resolved"
    ]
    return sorted(
        scored,
        key=lambda item: (
            item.score,
            SEVERITY_PRIORITY[item.finding.severity],
            item.finding.status == "new",
            item.finding.rule_id,
        ),
        reverse=True,
    )[:limit]


def priority_score(
    finding: Finding,
    production_patterns: tuple[str, ...] = DEFAULT_PRODUCTION_PATTERNS,
    now: datetime | None = None,
) -> int:
    """Calculate a deterministic priority score."""

    score = SEVERITY_PRIORITY[finding.severity]
    if finding.status == "new":
        score += 25
    elif finding.status == "recurring":
        score += 5

    if is_production_like(finding.file_path, production_patterns):
        score += 20

    score += CATEGORY_PRIORITY.get(finding.category, 5)
    score += blast_radius_bonus(finding)
    score += recurrence_bonus(finding, now or datetime.now(UTC))

    if finding.remediation or finding.documentation_url:
        score += 5
    return score


def priority_reason(
    finding: Finding,
    production_patterns: tuple[str, ...] = DEFAULT_PRODUCTION_PATTERNS,
    now: datetime | None = None,
) -> str:
    """Explain why the finding was ranked highly."""

    parts = [f"{finding.status.capitalize()} {finding.severity}-severity {finding.category} issue"]
    if is_production_like(finding.file_path, production_patterns):
        parts.append("in a production-like path")
    if blast_radius_bonus(finding) >= 15:
        parts.append("with broad blast radius indicators")
    if recurrence_bonus(finding, now or datetime.now(UTC)) > 0:
        parts.append("seen across previous scans")
    if finding.remediation or finding.documentation_url:
        parts.append("with remediation guidance")
    return " ".join(parts) + "."


def is_production_like(
    file_path: str | None,
    production_patterns: tuple[str, ...] = DEFAULT_PRODUCTION_PATTERNS,
) -> bool:
    if not file_path:
        return False
    lowered = file_path.lower()
    return any(pattern.lower() in lowered for pattern in production_patterns)


def blast_radius_bonus(finding: Finding) -> int:
    """Add priority for language that suggests larger operational impact."""

    text = " ".join(
        item.lower()
        for item in (
            finding.title,
            finding.description,
            finding.resource or "",
            finding.file_path or "",
            finding.rule_id,
        )
    )
    score = 0
    if any(word in text for word in ("wildcard", '"*"', "admin", "administrator", "root")):
        score += 20
    if any(word in text for word in ("public", "0.0.0.0/0", "internet", "world")):
        score += 20
    if any(word in text for word in ("account", "cluster", "vpc", "global", "organization")):
        score += 15
    return min(score, 35)


def recurrence_bonus(finding: Finding, now: datetime) -> int:
    if finding.status != "recurring" or finding.first_seen is None:
        return 0
    age_days = max(0, (now - finding.first_seen).days)
    if age_days >= 90:
        return 15
    if age_days >= 30:
        return 10
    return 5
