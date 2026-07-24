from __future__ import annotations

from pathlib import Path

from driftbeacon.models import Finding, ScannerStatus
from driftbeacon.scan import build_scan_summary
from driftbeacon.scanners import ScannerExecution


def _finding(
    fingerprint: str,
    severity: str,
    *,
    status: str = "new",
    file_path: str = "main.tf",
) -> Finding:
    return Finding(
        id=f"id-{fingerprint}",
        scanner="checkov",
        rule_id=f"RULE-{fingerprint}",
        title="Test finding",
        description="Test finding",
        severity=severity,  # type: ignore[arg-type]
        category="misconfiguration",
        file_path=file_path,
        line_start=1,
        resource="aws_example.demo",
        status=status,  # type: ignore[arg-type]
        first_seen=None,
        last_seen=None,
        fingerprint=fingerprint,
    )


def test_build_scan_summary_separates_actionable_ignored_and_scanner_audit() -> None:
    findings = [
        _finding("critical-1", "critical"),
        _finding("critical-1", "critical"),
        _finding("unknown-1", "unknown"),
        _finding("info-1", "info"),
        _finding("resolved-1", "high", status="resolved"),
    ]
    executions = [
        ScannerExecution(
            "checkov",
            ScannerStatus("checkov", "success", "loaded JSON"),
            findings,
            diagnostics={
                "raw_results": 6,
                "normalised_findings": 5,
                "duplicate_findings_removed": 1,
                "passed_results": 3,
                "informational_findings": 1,
                "unknown_severity_findings": 1,
            },
        ),
        ScannerExecution(
            "trivy",
            ScannerStatus("trivy", "skipped", "not installed"),
            [],
        ),
    ]

    summary = build_scan_summary(findings, executions)

    assert summary["actionable_findings"] == 1
    assert summary["ignored_findings"] == 2
    assert summary["deduplicated_findings"] == 4
    assert summary["duplicate_findings_removed"] == 1
    assert summary["passed_checks"] == 3
    assert summary["informational_findings"] == 1
    assert summary["unknown_severity_findings"] == 1
    assert summary["scanner_errors"] == 0
    assert summary["skipped_scanners"] == 1


def test_build_scan_summary_includes_production_health() -> None:
    findings = [
        _finding("test-1", "high", file_path="tests/main.tf"),
        _finding("prod-1", "high", file_path="main.tf"),
    ]
    executions = [
        ScannerExecution("checkov", ScannerStatus("checkov", "success", "loaded JSON"), findings)
    ]

    summary = build_scan_summary(
        findings,
        executions,
        supported_files=[Path("main.tf"), Path("tests/main.tf")],
    )

    assert summary["production_health_score"] is not None
    assert summary["production_health_score"] > 0
    assert summary["production_actionable_findings"] == 1
    assert summary["production_high_findings"] == 1
