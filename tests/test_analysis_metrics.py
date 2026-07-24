from __future__ import annotations

from pathlib import Path

from driftbeacon.analysis_metrics import (
    classify_path_group,
    classify_repository,
    density_metrics,
    enrich_findings_for_analysis,
    evaluate_score,
    scanner_result_from_execution,
)
from driftbeacon.models import Finding, ScannerStatus
from driftbeacon.scanners import ScannerExecution


def _finding(
    fingerprint: str,
    severity: str = "high",
    *,
    file_path: str = "main.tf",
) -> Finding:
    return Finding(
        id=f"id-{fingerprint}",
        scanner="trivy",
        rule_id=f"RULE-{fingerprint}",
        title="Test finding",
        description="Test finding",
        severity=severity,  # type: ignore[arg-type]
        category="misconfiguration",
        file_path=file_path,
        line_start=1,
        resource="resource.demo",
        status="new",
        first_seen=None,
        last_seen=None,
        fingerprint=fingerprint,
        finding_family="trivy_misconfiguration",
    )


def _execution(scanner: str, status: str, message: str = "scanner completed") -> ScannerExecution:
    return ScannerExecution(
        scanner,
        ScannerStatus(scanner, status, message),  # type: ignore[arg-type]
        [],
    )


def test_score_not_scored_when_no_supported_files() -> None:
    scanner = scanner_result_from_execution(
        "repo", _execution("checkov", "skipped"), applicable=False
    )

    score = evaluate_score([], supported_file_count=0, scanner_results=[scanner])

    assert score.health_score is None
    assert score.score_state == "not_scored_no_supported_files"
    assert score.coverage_state == "not_scored_no_supported_files"
    assert score.scanner_results[0].status == "skipped_no_supported_files"


def test_score_not_scored_when_all_applicable_scanners_fail() -> None:
    scanners = [
        scanner_result_from_execution("repo", _execution("checkov", "failed"), applicable=True),
        scanner_result_from_execution("repo", _execution("trivy", "failed"), applicable=True),
    ]

    score = evaluate_score([], supported_file_count=2, scanner_results=scanners)

    assert score.health_score is None
    assert score.score_state == "not_scored_all_scanners_failed"
    assert all(result.score_impact == "not scored" for result in score.scanner_results)


def test_partial_coverage_when_one_applicable_scanner_fails() -> None:
    finding = _finding("one")
    scanners = [
        scanner_result_from_execution("repo", _execution("checkov", "success"), applicable=True),
        scanner_result_from_execution("repo", _execution("trivy", "failed"), applicable=True),
    ]

    score = evaluate_score([finding], supported_file_count=2, scanner_results=scanners)

    assert score.health_score is not None
    assert score.coverage_state == "partial_coverage"
    assert score.scanner_results[1].score_impact == "partial coverage"


def test_complete_coverage_with_success_and_not_applicable_scanner() -> None:
    scanners = [
        scanner_result_from_execution("repo", _execution("checkov", "success"), applicable=True),
        scanner_result_from_execution("repo", _execution("trivy", "skipped"), applicable=False),
    ]

    score = evaluate_score([], supported_file_count=1, scanner_results=scanners)

    assert score.health_score == 100
    assert score.coverage_state == "complete_coverage"
    assert score.scanner_results[1].status == "skipped_not_applicable"


def test_parse_failure_status_is_attributable() -> None:
    scanner = scanner_result_from_execution(
        "repo",
        _execution("checkov", "failed", "scanner produced malformed JSON"),
        applicable=True,
    )

    assert scanner.status == "parse_failed"
    assert scanner.error == "scanner produced malformed JSON"


def test_path_group_classification_uses_segments_not_substrings() -> None:
    assert classify_path_group("examples/main.tf") == "examples"
    assert classify_path_group("src/contest/main.tf") == "production"
    assert classify_path_group("charts/app/values.yaml") == "charts"
    assert classify_path_group(None) == "unknown"


def test_explicit_path_group_exclusion_marks_findings() -> None:
    findings = [_finding("example", file_path="examples/main.tf"), _finding("prod")]

    enrich_findings_for_analysis(findings, excluded_path_groups=("examples",))

    assert findings[0].excluded_from_score is True
    assert findings[0].score_exclusion_reason == "excluded_path_group:examples"
    assert findings[1].excluded_from_score is False


def test_density_metrics_handle_zero_and_multiple_findings() -> None:
    assert density_metrics([], []).findings_per_100_supported_files is None
    metrics = density_metrics(
        [_finding("one", file_path="main.tf"), _finding("two", file_path="main.tf")],
        [Path("main.tf"), Path("variables.tf")],
    )

    assert metrics.affected_supported_files == 1
    assert metrics.affected_file_percentage == 50.0
    assert metrics.findings_per_affected_file == 2.0
    assert metrics.findings_per_100_supported_files == 100.0


def test_density_can_exceed_100_findings_per_100_supported_files() -> None:
    findings = [_finding(f"f-{index}", file_path="main.tf") for index in range(3)]

    metrics = density_metrics(findings, [Path("main.tf")])

    assert metrics.findings_per_100_supported_files == 300.0


def test_repository_category_regressions(tmp_path: Path) -> None:
    assert classify_repository("gruntwork-io/terragrunt", tmp_path, []).category == (
        "Terraform tooling"
    )
    assert classify_repository("hashicorp/terraform-cdk", tmp_path, []).category == (
        "Terraform tooling"
    )
    assert classify_repository("hashicorp/terraform-provider-aws", tmp_path, []).category == (
        "Terraform provider"
    )
    assert classify_repository(
        "terraform-aws-modules/terraform-aws-vpc",
        tmp_path,
        [Path("main.tf"), Path("variables.tf"), Path("outputs.tf")],
    ).category == "Terraform module"
    assert classify_repository(
        "argoproj/argo-cd",
        tmp_path,
        [Path("manifests/app.yaml")],
    ).category == "Kubernetes application or controller"
    assert classify_repository(
        "example/mixed",
        tmp_path,
        [Path("main.tf"), Path("kubernetes/deployment.yaml")],
    ).category == "Mixed infrastructure repository"
