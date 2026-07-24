"""Repository scan orchestration shared by CLI commands."""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .analysis_metrics import (
    directory_group_breakdown,
    enrich_findings_for_analysis,
    excluded_finding_counts,
    finding_source_breakdown,
    top_paths_by_findings,
)
from .comparison import compare_scans
from .config import Config
from .models import Finding, ScannerStatus, ScanResult
from .scanners import CheckovScanner, ScannerExecution, TrivyScanner
from .scoring import (
    SCORE_FORMULA_VERSION,
    actionable_active_findings,
    calculate_health_score,
    deduplicate_findings_by_fingerprint,
    ignored_active_findings,
)


def run_scan(
    config: Config,
    *,
    timeout_seconds: int = 300,
    checkov_json: Path | None = None,
    trivy_json: Path | None = None,
    compare_with_previous: bool = False,
) -> tuple[ScanResult, list[ScannerExecution]]:
    """Run or load scanner outputs and return a scan result."""

    started_at = datetime.now(UTC)
    executions: list[ScannerExecution] = []

    if config.checkov_enabled:
        checkov = CheckovScanner()
        if checkov_json is not None:
            executions.append(checkov.from_file(checkov_json, config.repository_path))
        else:
            executions.append(checkov.run(config.repository_path, timeout_seconds=timeout_seconds))
    else:
        executions.append(
            ScannerExecution(
                "checkov",
                ScannerStatus("checkov", "skipped", "disabled by configuration"),
                [],
            )
        )

    if config.trivy_enabled:
        trivy = TrivyScanner(secret_scanning=config.trivy_secret_scanning)
        if trivy_json is not None:
            executions.append(trivy.from_file(trivy_json, config.repository_path))
        else:
            executions.append(trivy.run(config.repository_path, timeout_seconds=timeout_seconds))
    else:
        executions.append(
            ScannerExecution(
                "trivy",
                ScannerStatus("trivy", "skipped", "disabled by configuration"),
                [],
            )
        )

    completed_at = datetime.now(UTC)
    findings = [finding for execution in executions for finding in execution.findings]
    for finding in findings:
        finding.first_seen = finding.first_seen or started_at
        finding.last_seen = completed_at
    enrich_findings_for_analysis(findings)
    repository, branch, commit_sha = detect_repository_metadata(config.repository_path)
    scanner_statuses = {execution.scanner: execution.status for execution in executions}
    scan = ScanResult(
        repository=repository,
        branch=branch,
        commit_sha=commit_sha,
        started_at=started_at,
        completed_at=completed_at,
        scanner_statuses=scanner_statuses,
        findings=findings,
        health_score=calculate_health_score(findings),
        summary=build_scan_summary(findings, executions),
    )
    if compare_with_previous:
        compare_scans(scan, None)
    return scan, executions


def build_scan_summary(
    findings: list[Finding],
    executions: list[ScannerExecution],
) -> dict[str, Any]:
    """Build audit counts for a scan result."""

    actionable = actionable_active_findings(findings)
    ignored = ignored_active_findings(findings)
    deduplicated = deduplicate_findings_by_fingerprint(findings)
    diagnostics = [execution.diagnostics or {} for execution in executions]
    scanner_errors = sum(
        1 for execution in executions if execution.status.status in {"failed", "partial"}
    )
    skipped_scanners = sum(1 for execution in executions if execution.status.status == "skipped")
    return {
        "active_findings": len(actionable),
        "actionable_findings": len(actionable),
        "ignored_findings": len(ignored),
        "deduplicated_findings": len(deduplicated),
        "deduplicated_active_findings": len(actionable),
        "raw_scanner_results": _sum_diagnostics(diagnostics, "raw_results"),
        "normalised_findings": _sum_diagnostics(diagnostics, "normalised_findings"),
        "duplicate_findings_removed": _sum_diagnostics(
            diagnostics, "duplicate_findings_removed"
        ),
        "passed_checks": _sum_diagnostics(diagnostics, "passed_results"),
        "informational_findings": _sum_diagnostics(diagnostics, "informational_findings"),
        "unknown_severity_findings": _sum_diagnostics(diagnostics, "unknown_severity_findings"),
        "scanner_errors": scanner_errors,
        "skipped_scanners": skipped_scanners,
        "new_findings": 0,
        "recurring_findings": 0,
        "resolved_findings": 0,
        "severity_changes": 0,
        "score_formula_version": SCORE_FORMULA_VERSION,
        "score_state": "scored",
        "coverage_state": "complete_coverage",
        "score_reason": "Score calculated from configured scanner output.",
        "finding_source_breakdown": finding_source_breakdown(findings),
        "directory_group_breakdown": directory_group_breakdown(findings),
        "excluded_finding_counts": excluded_finding_counts(findings),
        "top_directories": top_paths_by_findings(findings, by_file=False),
        "top_files": top_paths_by_findings(findings, by_file=True),
    }


def _sum_diagnostics(diagnostics: list[dict[str, int]], key: str) -> int:
    return sum(value.get(key, 0) for value in diagnostics)


def detect_repository_metadata(repository_path: Path) -> tuple[str, str, str]:
    """Detect repository name, branch, and commit SHA from GitHub Actions or Git."""

    repository = os.environ.get("GITHUB_REPOSITORY") or _git_remote_repository(repository_path)
    branch = os.environ.get("GITHUB_REF_NAME") or _git_output(
        repository_path, ["git", "rev-parse", "--abbrev-ref", "HEAD"]
    )
    commit_sha = os.environ.get("GITHUB_SHA") or _git_output(
        repository_path, ["git", "rev-parse", "HEAD"]
    )
    return (
        repository or repository_path.name,
        branch or "unknown",
        commit_sha or "unknown",
    )


def _git_remote_repository(repository_path: Path) -> str | None:
    remote = _git_output(repository_path, ["git", "config", "--get", "remote.origin.url"])
    if not remote:
        return None
    if remote.endswith(".git"):
        remote = remote[:-4]
    if remote.startswith("git@github.com:"):
        return remote.removeprefix("git@github.com:")
    if "github.com/" in remote:
        return remote.split("github.com/", 1)[1]
    return remote


def _git_output(repository_path: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            args,
            cwd=repository_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    output = completed.stdout.strip()
    return output or None
