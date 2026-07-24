"""Core DriftBeacon data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
FindingStatus = Literal["new", "recurring", "resolved"]
ScannerState = Literal["success", "partial", "failed", "skipped"]

VALID_SEVERITIES: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
)
VALID_STATUSES: tuple[FindingStatus, ...] = ("new", "recurring", "resolved")
VALID_SCANNER_STATES: tuple[ScannerState, ...] = ("success", "partial", "failed", "skipped")
SEVERITY_RANK: dict[Severity, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "unknown": 1,
    "info": 0,
}


def normalize_severity(value: object) -> Severity:
    """Convert scanner severity strings into DriftBeacon's severity vocabulary."""

    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    aliases = {
        "fatal": "critical",
        "severe": "critical",
        "important": "high",
        "moderate": "medium",
        "negligible": "low",
        "none": "info",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in VALID_SEVERITIES:
        return normalized
    return "unknown"


def parse_datetime(value: object) -> datetime | None:
    """Parse ISO datetime values emitted by DriftBeacon."""

    if not isinstance(value, str) or not value:
        return None
    candidate = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def format_datetime(value: datetime | None) -> str | None:
    """Format datetimes consistently for JSON output."""

    if value is None:
        return None
    return value.isoformat()


@dataclass(slots=True)
class Finding:
    """A single scanner finding normalized into DriftBeacon's internal format."""

    id: str
    scanner: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str
    file_path: str | None
    line_start: int | None
    resource: str | None
    status: FindingStatus
    first_seen: datetime | None
    last_seen: datetime | None
    fingerprint: str
    remediation: str | None = None
    documentation_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "resource": self.resource,
            "status": self.status,
            "first_seen": format_datetime(self.first_seen),
            "last_seen": format_datetime(self.last_seen),
            "fingerprint": self.fingerprint,
            "remediation": self.remediation,
            "documentation_url": self.documentation_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        severity = normalize_severity(data.get("severity"))
        raw_status = str(data.get("status", "new")).lower()
        status: FindingStatus = raw_status if raw_status in VALID_STATUSES else "new"
        line_value = data.get("line_start")
        line_start = line_value if isinstance(line_value, int) else None
        return cls(
            id=str(data.get("id", data.get("fingerprint", ""))),
            scanner=str(data.get("scanner", "unknown")),
            rule_id=str(data.get("rule_id", "unknown")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            severity=severity,
            category=str(data.get("category", "unknown")),
            file_path=data.get("file_path") if isinstance(data.get("file_path"), str) else None,
            line_start=line_start,
            resource=data.get("resource") if isinstance(data.get("resource"), str) else None,
            status=status,
            first_seen=parse_datetime(data.get("first_seen")),
            last_seen=parse_datetime(data.get("last_seen")),
            fingerprint=str(data.get("fingerprint", data.get("id", ""))),
            remediation=data.get("remediation")
            if isinstance(data.get("remediation"), str)
            else None,
            documentation_url=(
                data.get("documentation_url")
                if isinstance(data.get("documentation_url"), str)
                else None
            ),
        )


@dataclass(slots=True)
class ScannerStatus:
    """Status for an individual scanner execution."""

    name: str
    status: ScannerState
    message: str
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScannerStatus:
        raw_status = str(data.get("status", "failed")).lower()
        status: ScannerState = raw_status if raw_status in VALID_SCANNER_STATES else "failed"
        duration = data.get("duration_seconds")
        return cls(
            name=str(data.get("name", "unknown")),
            status=status,
            message=str(data.get("message", "")),
            duration_seconds=duration if isinstance(duration, (int, float)) else None,
        )


@dataclass(slots=True)
class ScanResult:
    """A complete driftbeacon scan result."""

    repository: str
    branch: str
    commit_sha: str
    started_at: datetime
    completed_at: datetime
    scanner_statuses: dict[str, ScannerStatus]
    findings: list[Finding]
    health_score: int
    summary: dict[str, int | str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "started_at": format_datetime(self.started_at),
            "completed_at": format_datetime(self.completed_at),
            "scanner_statuses": {
                name: status.to_dict() for name, status in sorted(self.scanner_statuses.items())
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "health_score": self.health_score,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        started_at = parse_datetime(data.get("started_at")) or datetime.min
        completed_at = parse_datetime(data.get("completed_at")) or started_at
        raw_statuses = data.get("scanner_statuses")
        statuses: dict[str, ScannerStatus] = {}
        if isinstance(raw_statuses, dict):
            for name, status_data in raw_statuses.items():
                if isinstance(status_data, dict):
                    statuses[str(name)] = ScannerStatus.from_dict(status_data)
        raw_findings = data.get("findings")
        findings = (
            [Finding.from_dict(item) for item in raw_findings if isinstance(item, dict)]
            if isinstance(raw_findings, list)
            else []
        )
        summary = data.get("summary")
        return cls(
            repository=str(data.get("repository", "unknown")),
            branch=str(data.get("branch", "unknown")),
            commit_sha=str(data.get("commit_sha", "unknown")),
            started_at=started_at,
            completed_at=completed_at,
            scanner_statuses=statuses,
            findings=findings,
            health_score=int(data.get("health_score", 100)),
            summary=summary if isinstance(summary, dict) else {},
        )


@dataclass(slots=True)
class ComparisonSummary:
    """Current versus previous scan comparison."""

    has_baseline: bool
    new_findings: list[Finding]
    recurring_findings: list[Finding]
    resolved_findings: list[Finding]
    severity_changes: list[dict[str, str]]
    health_score_change: int | None
    active_findings_change: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_baseline": self.has_baseline,
            "new_findings": [finding.to_dict() for finding in self.new_findings],
            "recurring_findings": [finding.to_dict() for finding in self.recurring_findings],
            "resolved_findings": [finding.to_dict() for finding in self.resolved_findings],
            "severity_changes": self.severity_changes,
            "health_score_change": self.health_score_change,
            "active_findings_change": self.active_findings_change,
            "counts": {
                "new": actionable_count(self.new_findings),
                "recurring": actionable_count(self.recurring_findings),
                "resolved": actionable_count(self.resolved_findings),
                "severity_changes": len(self.severity_changes),
            },
        }


def active_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings that are still active."""

    return [finding for finding in findings if finding.status != "resolved"]


def actionable_count(findings: list[Finding]) -> int:
    """Count findings with severities that DriftBeacon treats as actionable."""

    actionable_severities = {"critical", "high", "medium", "low"}
    return sum(1 for finding in findings if finding.severity in actionable_severities)
