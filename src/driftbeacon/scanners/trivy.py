"""Trivy scanner adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from driftbeacon.models import ScannerStatus
from driftbeacon.normalise import normalise_trivy_with_diagnostics

from .base import (
    SCANNER_SKIP_PATTERNS,
    ScannerExecution,
    executable_path,
    load_json_file,
    parse_json_output,
    run_subprocess,
    safe_walk,
)

DEPENDENCY_FILES = {
    "cargo.lock",
    "composer.lock",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "requirements.txt",
    "yarn.lock",
}


class TrivyScanner:
    """Run and normalize Trivy filesystem scans."""

    name = "trivy"

    def __init__(self, *, secret_scanning: bool = False) -> None:
        self.secret_scanning = secret_scanning

    def run(self, repository_path: Path, *, timeout_seconds: int = 300) -> ScannerExecution:
        if not has_relevant_files(repository_path):
            return ScannerExecution(
                scanner=self.name,
                status=ScannerStatus(
                    self.name, "skipped", "no dependency, IaC, Kubernetes, or Docker files found"
                ),
                findings=[],
            )
        trivy_path = executable_path("trivy")
        if trivy_path is None:
            return ScannerExecution(
                scanner=self.name,
                status=ScannerStatus(self.name, "skipped", "trivy executable not found on PATH"),
                findings=[],
            )

        scanners = "vuln,misconfig"
        if self.secret_scanning:
            scanners += ",secret"
        command = [
            trivy_path,
            "fs",
            "--format",
            "json",
            "--scanners",
            scanners,
            "--quiet",
            "--skip-check-update",
            "--skip-version-check",
        ]
        for pattern in SCANNER_SKIP_PATTERNS:
            command.extend(["--skip-dirs", pattern])
        command.append(str(repository_path))

        stdout, stderr, _returncode, status, _duration = run_subprocess(
            command,
            cwd=repository_path,
            scanner=self.name,
            timeout_seconds=timeout_seconds,
            acceptable_exit_codes={0},
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
    data, parse_status = parse_json_output("trivy", stdout)
    if data is None:
        return ScannerExecution("trivy", parse_status, [], stdout=stdout, stderr=stderr)
    result = normalise_trivy_with_diagnostics(data, repository_path)
    status = base_status or parse_status
    if base_status is not None and base_status.status != "success":
        status = ScannerStatus(
            "trivy", base_status.status, base_status.message, base_status.duration_seconds
        )
    return ScannerExecution(
        "trivy",
        status,
        result.findings,
        raw_json=data,
        stdout=stdout,
        stderr=stderr,
        diagnostics=result.diagnostics.to_dict(),
    )


def execution_from_data(data: Any, repository_path: Path) -> ScannerExecution:
    result = normalise_trivy_with_diagnostics(data, repository_path)
    return ScannerExecution(
        scanner="trivy",
        status=ScannerStatus(
            "trivy", "success", f"loaded {len(result.findings)} findings from JSON"
        ),
        findings=result.findings,
        raw_json=data,
        diagnostics=result.diagnostics.to_dict(),
    )


def has_relevant_files(repository_path: Path) -> bool:
    """Detect files Trivy can usefully inspect."""

    for path in safe_walk(repository_path):
        name = path.name.lower()
        suffix = path.suffix.lower()
        if name in DEPENDENCY_FILES:
            return True
        if name == "dockerfile" or name.startswith("dockerfile."):
            return True
        if suffix in {".tf", ".tfvars", ".yaml", ".yml", ".json"}:
            return True
    return False
