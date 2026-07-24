"""Shared scanner adapter primitives."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from driftbeacon.models import Finding, ScannerStatus
from driftbeacon.redaction import redact_secrets, truncate

IGNORED_DIRS = {
    ".git",
    ".driftbeacon",
    ".driftbeacon-demo",
    ".driftbeacon-history",
    ".driftbeacon-sample",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}

SCANNER_SKIP_PATTERNS = (
    ".git",
    ".driftbeacon",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
)


@dataclass(slots=True)
class ScannerExecution:
    """A scanner execution result with normalized findings."""

    scanner: str
    status: ScannerStatus
    findings: list[Finding]
    raw_json: Any | None = None
    stdout: str = ""
    stderr: str = ""
    diagnostics: dict[str, int] | None = None


def executable_exists(name: str) -> bool:
    """Return whether a scanner executable is available on PATH."""

    return shutil.which(name) is not None


def executable_path(name: str) -> str | None:
    """Return the resolved executable path when available."""

    path = shutil.which(name)
    return str(Path(path).resolve()) if path is not None else None


def safe_walk(repository_path: Path) -> list[Path]:
    """Walk a repository without following symlinks or noisy generated directories."""

    files: list[Path] = []
    for root, dirnames, filenames in os.walk(repository_path, followlinks=False):
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in IGNORED_DIRS
            and not dirname.startswith(".driftbeacon")
            and not (Path(root) / dirname).is_symlink()
        ]
        for filename in filenames:
            path = Path(root) / filename
            if not path.is_symlink():
                files.append(path)
    return files


def load_json_file(path: Path) -> Any:
    """Load scanner JSON from a file."""

    if path.is_symlink():
        raise ValueError(f"refusing to read symlinked JSON file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def parse_json_output(scanner: str, stdout: str) -> tuple[Any | None, ScannerStatus]:
    """Parse scanner stdout and convert malformed JSON into a visible scanner failure."""

    if not stdout.strip():
        return None, ScannerStatus(scanner, "failed", "scanner produced no JSON output")
    try:
        return json.loads(stdout), ScannerStatus(scanner, "success", "scanner completed")
    except json.JSONDecodeError as exc:
        message = truncate(redact_secrets(str(exc)), 200)
        return None, ScannerStatus(scanner, "failed", f"scanner produced malformed JSON: {message}")


def run_subprocess(
    args: list[str],
    *,
    cwd: Path,
    scanner: str,
    timeout_seconds: int,
    acceptable_exit_codes: set[int],
) -> tuple[str, str, int | None, ScannerStatus, float]:
    """Run a scanner safely with timeout and captured output."""

    start = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except OSError as exc:
        duration = time.monotonic() - start
        message = truncate(_scrub_repository_path(redact_secrets(str(exc)), cwd), 240)
        return (
            "",
            "",
            None,
            ScannerStatus(scanner, "failed", f"scanner could not start: {message}", duration),
            duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        stderr = _scrub_repository_path(redact_secrets(stderr), cwd)
        return (
            stdout,
            stderr,
            None,
            ScannerStatus(
                scanner,
                "failed",
                f"scanner timed out after {timeout_seconds}s",
                duration,
            ),
            duration,
        )
    duration = time.monotonic() - start
    stderr = _scrub_repository_path(redact_secrets(completed.stderr), cwd)
    if completed.returncode in acceptable_exit_codes:
        return (
            completed.stdout,
            stderr,
            completed.returncode,
            ScannerStatus(
                scanner,
                "success",
                "scanner completed",
                duration,
            ),
            duration,
        )
    return (
        completed.stdout,
        stderr,
        completed.returncode,
        ScannerStatus(
            scanner,
            "partial" if completed.stdout.strip() else "failed",
            truncate(f"scanner exited {completed.returncode}: {stderr}", 300),
            duration,
        ),
        duration,
    )


def _scrub_repository_path(value: str, repository_path: Path) -> str:
    """Remove local checkout paths from scanner status messages."""

    cleaned = value
    candidates = {repository_path.as_posix()}
    with suppress(OSError, RuntimeError):
        candidates.add(repository_path.resolve().as_posix())
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate:
            cleaned = cleaned.replace(candidate, ".")
    return cleaned
