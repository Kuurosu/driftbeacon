"""Checkov scanner adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from DriftBeacon.models import ScannerStatus
from DriftBeacon.normalise import normalise_checkov

from .base import (
    ScannerExecution,
    executable_exists,
    load_json_file,
    parse_json_output,
    run_subprocess,
    safe_walk,
)


class CheckovScanner:
    """Run and normalize Checkov results."""

    name = "checkov"

    def run(self, repository_path: Path, *, timeout_seconds: int = 300) -> ScannerExecution:
        if not has_relevant_files(repository_path):
            return ScannerExecution(
                scanner=self.name,
                status=ScannerStatus(
                    self.name,
                    "skipped",
                    "no Terraform, CloudFormation, Kubernetes, or Docker files found",
                ),
                findings=[],
            )
        if not executable_exists("checkov"):
            return ScannerExecution(
                scanner=self.name,
                status=ScannerStatus(self.name, "skipped", "checkov executable not found on PATH"),
                findings=[],
            )

        stdout, stderr, _returncode, status, _duration = run_subprocess(
            ["checkov", "-d", str(repository_path), "-o", "json", "--quiet"],
            cwd=repository_path,
            scanner=self.name,
            timeout_seconds=timeout_seconds,
            acceptable_exit_codes={0, 1},
        )
        if not stdout.strip():
            return ScannerExecution(self.name, status, [], stdout=stdout, stderr=stderr)
        return execution_from_json_output(
            stdout, repository_path, stderr=stderr, base_status=status
        )

    def from_file(self, json_path: Path, repository_path: Path) -> ScannerExecution:
        data = load_json_file(json_path)
        return execution_from_data(data, repository_path)


def execution_from_json_output(
    stdout: str,
    repository_path: Path,
    *,
    stderr: str = "",
    base_status: ScannerStatus | None = None,
) -> ScannerExecution:
    data, parse_status = parse_json_output("checkov", stdout)
    if data is None:
        return ScannerExecution("checkov", parse_status, [], stdout=stdout, stderr=stderr)
    findings = normalise_checkov(data, repository_path)
    status = base_status or parse_status
    if base_status is not None and base_status.status != "success":
        status = ScannerStatus(
            "checkov", base_status.status, base_status.message, base_status.duration_seconds
        )
    return ScannerExecution(
        "checkov", status, findings, raw_json=data, stdout=stdout, stderr=stderr
    )


def execution_from_data(data: Any, repository_path: Path) -> ScannerExecution:
    findings = normalise_checkov(data, repository_path)
    return ScannerExecution(
        scanner="checkov",
        status=ScannerStatus("checkov", "success", f"loaded {len(findings)} findings from JSON"),
        findings=findings,
        raw_json=data,
    )


def has_relevant_files(repository_path: Path) -> bool:
    """Detect files Checkov can usefully inspect."""

    for path in safe_walk(repository_path):
        name = path.name.lower()
        suffix = path.suffix.lower()
        if name in {"dockerfile", "dockerfile.prod"} or name.startswith("dockerfile."):
            return True
        if suffix in {".tf", ".tfvars"} or path.name.endswith(".tf.json"):
            return True
        if suffix in {".yaml", ".yml", ".json"} and _looks_like_iac(path):
            return True
    return False


def _looks_like_iac(path: Path) -> bool:
    try:
        sample = path.read_text(encoding="utf-8", errors="ignore")[:8192].lower()
    except OSError:
        return False
    return any(
        marker in sample
        for marker in (
            "apiversion:",
            "kind:",
            "resources:",
            "awstemplateformatversion",
            "type: aws::",
        )
    )
