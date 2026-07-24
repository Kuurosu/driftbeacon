from __future__ import annotations

from pathlib import Path

from conftest import load_fixture

from driftbeacon.normalise import (
    normalise_checkov,
    normalise_checkov_with_diagnostics,
    normalise_trivy,
    stable_fingerprint,
)


def test_checkov_normalisation_extracts_core_fields() -> None:
    findings = normalise_checkov(load_fixture("checkov.json"))

    assert len(findings) == 2
    iam = findings[0]
    assert iam.scanner == "checkov"
    assert iam.rule_id == "CKV_AWS_355"
    assert iam.severity == "high"
    assert iam.category == "iam"
    assert iam.file_path == "terraform/production/iam.tf"
    assert iam.line_start == 12
    assert iam.fingerprint == "2deedfe59ec161bcc047"


def test_checkov_normalisation_strips_repository_prefix_from_scanner_paths() -> None:
    findings = normalise_checkov(
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_16",
                        "check_name": "Container should not be privileged",
                        "file_path": "/examples/demo-infrastructure/kubernetes/privileged-pod.yaml",
                        "file_line_range": [10, 14],
                        "resource": "Pod.default.demo",
                        "severity": "HIGH",
                        "bc_category": "Kubernetes",
                    }
                ]
            }
        },
        Path.cwd() / "examples/demo-infrastructure",
    )

    assert findings[0].file_path == "kubernetes/privileged-pod.yaml"


def test_trivy_normalisation_extracts_vulnerabilities_and_secrets() -> None:
    findings = normalise_trivy(load_fixture("trivy.json"))

    assert {finding.category for finding in findings} == {"vulnerability", "secret"}
    secret = next(finding for finding in findings if finding.category == "secret")
    assert secret.severity == "critical"
    assert secret.file_path == "terraform/production/secrets.tf"
    assert "<redacted>" in secret.description
    assert "AKIA1234567890ABCDEF" not in secret.description


def test_stable_fingerprint_ignores_timestamps_and_text() -> None:
    first = stable_fingerprint(
        "checkov", "CKV_AWS_355", "terraform/production/iam.tf", "aws_iam_policy.admin", 12
    )
    second = stable_fingerprint(
        "checkov", "CKV_AWS_355", "terraform/production/iam.tf", "aws_iam_policy.admin", 12
    )
    moved = stable_fingerprint(
        "checkov", "CKV_AWS_355", "terraform/production/iam.tf", "aws_iam_policy.admin", 13
    )

    assert first == second
    assert first != moved


def test_checkov_diagnostics_count_passed_and_duplicate_results() -> None:
    duplicate = {
        "check_id": "CKV_AWS_20",
        "check_name": "S3 bucket allows public read access",
        "file_path": "/terraform/s3.tf",
        "file_line_range": [7, 11],
        "resource": "aws_s3_bucket_acl.public",
        "severity": "HIGH",
    }
    result = normalise_checkov_with_diagnostics(
        {
            "results": {
                "failed_checks": [duplicate, dict(duplicate)],
                "passed_checks": [{"check_id": "CKV_AWS_18"}],
            }
        }
    )

    assert len(result.findings) == 1
    assert result.diagnostics.raw_results == 3
    assert result.diagnostics.passed_results == 1
    assert result.diagnostics.normalised_findings == 2
    assert result.diagnostics.deduplicated_findings == 1
    assert result.diagnostics.duplicate_findings_removed == 1


def test_unknown_checkov_severity_is_audited_not_promoted() -> None:
    result = normalise_checkov_with_diagnostics(
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_UNKNOWN",
                        "check_name": "Scanner did not provide severity",
                        "file_path": "/terraform/main.tf",
                        "resource": "aws_example.demo",
                    }
                ]
            }
        }
    )

    assert result.findings[0].severity == "unknown"
    assert result.diagnostics.unknown_severity_findings == 1
