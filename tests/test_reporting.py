from __future__ import annotations

from DriftBeacon.comparison import compare_scans
from DriftBeacon.models import ScannerStatus, ScanResult
from DriftBeacon.reporting import generate_report


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

    assert "# DriftBeacon Weekly" in report
    assert "Fix these first" in report
    assert "1 resolved finding" in report
    assert "Trivy: Partial" in report
    assert "super-secret" not in report
    assert "<redacted>" in report
