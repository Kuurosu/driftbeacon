"""Compare scan results and classify finding lifecycle state."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime

from .models import ComparisonSummary, Finding, ScanResult, active_findings
from .scoring import (
    SCORE_FORMULA_VERSION,
    actionable_active_findings,
    actionable_findings,
    calculate_health_score,
)


def compare_scans(current: ScanResult, previous: ScanResult | None) -> ComparisonSummary:
    """Compare the current scan to a previous scan and update current finding statuses."""

    previous_findings = active_findings(previous.findings) if previous is not None else []
    comparison = compare_findings(
        current.findings,
        previous_findings,
        current.started_at,
        current.completed_at,
    )
    current.health_score = calculate_health_score(current.findings)

    current_formula = str(current.summary.get("score_formula_version", SCORE_FORMULA_VERSION))
    previous_formula = (
        str(previous.summary.get("score_formula_version", "unknown"))
        if previous is not None
        else None
    )
    comparison.score_formula_version = current_formula
    comparison.previous_score_formula_version = previous_formula
    comparison.score_formula_changed = bool(
        previous is not None and previous_formula != current_formula
    )

    if previous is not None and not comparison.score_formula_changed:
        if current.health_score is not None and previous.health_score is not None:
            comparison.health_score_change = current.health_score - previous.health_score
        comparison.active_findings_change = len(
            actionable_active_findings(current.findings)
        ) - len(actionable_active_findings(previous_findings))

    current.summary = {
        **current.summary,
        "active_findings": len(actionable_active_findings(current.findings)),
        "actionable_findings": len(actionable_active_findings(current.findings)),
        "new_findings": len(actionable_active_findings(comparison.new_findings)),
        "recurring_findings": len(actionable_active_findings(comparison.recurring_findings)),
        "resolved_findings": len(actionable_findings(comparison.resolved_findings)),
        "severity_changes": len(comparison.severity_changes),
        "baseline_status": "comparison_scan" if comparison.has_baseline else "initial_baseline",
        "score_formula_version": current_formula,
        "previous_score_formula_version": previous_formula or "",
        "score_formula_changed": "true" if comparison.score_formula_changed else "false",
    }
    return comparison


def compare_findings(
    current_findings: list[Finding],
    previous_findings: list[Finding],
    started_at: datetime,
    completed_at: datetime,
) -> ComparisonSummary:
    """Compare current findings to previous findings by stable fingerprint."""

    if not previous_findings:
        for finding in current_findings:
            finding.status = "new"
            finding.first_seen = finding.first_seen or started_at
            finding.last_seen = completed_at
        return ComparisonSummary(
            has_baseline=False,
            new_findings=list(current_findings),
            recurring_findings=[],
            resolved_findings=[],
            severity_changes=[],
            health_score_change=None,
            active_findings_change=None,
        )

    previous_by_fingerprint = {finding.fingerprint: finding for finding in previous_findings}
    current_by_fingerprint = {finding.fingerprint: finding for finding in current_findings}

    new_findings: list[Finding] = []
    recurring_findings: list[Finding] = []
    resolved_findings: list[Finding] = []
    severity_changes: list[dict[str, str]] = []

    for finding in current_findings:
        previous = previous_by_fingerprint.get(finding.fingerprint)
        finding.last_seen = completed_at
        if previous is None:
            finding.status = "new"
            finding.first_seen = finding.first_seen or started_at
            new_findings.append(finding)
            continue
        finding.status = "recurring"
        finding.first_seen = previous.first_seen or previous.last_seen or started_at
        recurring_findings.append(finding)
        if previous.severity != finding.severity:
            severity_changes.append(
                {
                    "fingerprint": finding.fingerprint,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "from": previous.severity,
                    "to": finding.severity,
                }
            )

    for fingerprint, previous in previous_by_fingerprint.items():
        if fingerprint in current_by_fingerprint:
            continue
        resolved = deepcopy(previous)
        resolved.status = "resolved"
        resolved.last_seen = previous.last_seen or previous.first_seen or completed_at
        resolved_findings.append(resolved)

    return ComparisonSummary(
        has_baseline=True,
        new_findings=new_findings,
        recurring_findings=recurring_findings,
        resolved_findings=resolved_findings,
        severity_changes=severity_changes,
        health_score_change=None,
        active_findings_change=None,
    )
