from __future__ import annotations

from driftbeacon.comparison import compare_scans
from driftbeacon.models import ScannerStatus, ScanResult
from driftbeacon.reporting import generate_report


def test_report_generation_includes_summary_and_scanner_failure(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    current_scan.scanner_statuses["trivy"] = ScannerStatus(
        "trivy",
        "partial",
        "scanner exited 2: bad token password=super-secret",
    )
    comparison = compare_scans(current_scan, previous_scan)
    report = generate_report(current_scan, comparison)

    assert "# DriftBeacon Report" in report
    assert "What happened" in report
    assert "What changed" in report
    assert "Fix these first" in report
    assert "1 resolved finding" in report
    assert "Trivy: Partial" in report
    assert "super-secret" not in report
    assert "<redacted>" in report


def test_report_generation_includes_top_directories_and_files(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    current_scan.summary["top_directories"] = [
        {"path": "terraform/production", "actionable_findings": 3}
    ]
    current_scan.summary["top_files"] = [
        {"path": "terraform/production/main.tf", "actionable_findings": 2}
    ]

    report = generate_report(current_scan, compare_scans(current_scan, previous_scan))

    assert "## Top directories by actionable findings" in report
    assert "| terraform/production | 3 |" in report
    assert "## Top files by actionable findings" in report
    assert "| terraform/production/main.tf | 2 |" in report


def test_report_generation_marks_partial_grades_provisional(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    comparison = compare_scans(current_scan, previous_scan)
    current_scan.health_score = 95
    current_scan.summary.update(
        {
            "coverage_state": "partial_coverage",
            "grade_provisional": True,
            "production_health_score": 95,
            "production_grade": "A",
            "production_grade_provisional": True,
            "production_score_reason": (
                "Production Health calculated from successful scanner output; "
                "coverage is incomplete."
            ),
        }
    )

    report = generate_report(current_scan, comparison)

    assert "**Grade:** A*" in report
    assert "**Production Health:** 95/100" in report
    assert "**Production Grade:** A*" in report
    assert "Grade is provisional because one or more applicable scanners failed." in report


def test_report_generation_keeps_complete_grade_unmarked(
    current_scan: ScanResult,
    previous_scan: ScanResult,
) -> None:
    comparison = compare_scans(current_scan, previous_scan)
    current_scan.health_score = 95
    current_scan.summary.update(
        {
            "coverage_state": "complete_coverage",
            "grade_provisional": False,
            "production_health_score": None,
            "production_grade": "N/A",
            "production_grade_provisional": False,
        }
    )

    report = generate_report(current_scan, comparison)

    assert "**Grade:** A" in report
    assert "**Grade:** A*" not in report
    assert "**Production Grade:** N/A" in report
    assert "N/A*" not in report
