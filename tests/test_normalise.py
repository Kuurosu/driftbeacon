from __future__ import annotations

from conftest import load_fixture

from driftbeacon.normalise import normalise_checkov, normalise_trivy, stable_fingerprint


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
