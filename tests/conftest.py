from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from driftbeacon.models import ScannerStatus, ScanResult
from driftbeacon.normalise import normalise_checkov, normalise_trivy
from driftbeacon.scoring import calculate_health_score

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def current_scan() -> ScanResult:
    checkov_findings = normalise_checkov(load_fixture("checkov.json"))
    trivy_findings = normalise_trivy(load_fixture("trivy.json"))
    findings = checkov_findings + trivy_findings
    return ScanResult(
        repository="Kuurosu/driftbeacon",
        branch="main",
        commit_sha="2222222222222222222222222222222222222222",
        started_at=ScanResult.from_dict(load_fixture("previous-scan.json")).started_at,
        completed_at=ScanResult.from_dict(load_fixture("previous-scan.json")).completed_at,
        scanner_statuses={
            "checkov": ScannerStatus("checkov", "success", "loaded 2 findings from JSON"),
            "trivy": ScannerStatus("trivy", "success", "loaded 2 findings from JSON"),
        },
        findings=findings,
        health_score=calculate_health_score(findings),
        summary={},
    )


@pytest.fixture
def previous_scan() -> ScanResult:
    return ScanResult.from_dict(load_fixture("previous-scan.json"))
