"""Bulk public repository analysis mode."""

from __future__ import annotations

import csv
import re
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .comparison import compare_scans
from .config import load_config
from .models import Finding, active_findings
from .prioritise import prioritise_findings
from .redaction import redact_secrets, truncate
from .reporting import generate_report
from .scan import run_scan
from .scanners.base import safe_walk
from .scanners.trivy import DEPENDENCY_FILES
from .storage import LocalStorage

ProgressWriter = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class AnalysisOptions:
    """Options for repository analysis runs."""

    output_dir: Path = Path(".driftbeacon-analysis")
    workers: int = 4
    keep: bool = False
    scanner_timeout_seconds: int = 300
    clone_timeout_seconds: int = 300


@dataclass(frozen=True, slots=True)
class AnalysisTask:
    """A single repository scheduled for analysis."""

    index: int
    total: int
    git_url: str
    output_name: str


@dataclass(frozen=True, slots=True)
class RepositoryAnalysisResult:
    """Summary for one analysed repository."""

    index: int
    git_url: str
    repository: str
    status: str
    health_score: int | None
    critical_findings: int
    high_findings: int
    medium_findings: int
    new_findings: int
    active_findings: int
    supported_files: int
    output_dir: Path | None
    report_path: Path | None
    scan_path: Path | None
    clone_path: Path | None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "success"

    def one_line_summary(self) -> str:
        if not self.succeeded:
            return f"{self.repository}: failed: {self.error or 'unknown error'}"
        return (
            f"{self.repository}: health={self.health_score} "
            f"critical={self.critical_findings} high={self.high_findings} "
            f"medium={self.medium_findings} new={self.new_findings}"
        )


@dataclass(frozen=True, slots=True)
class AnalysisRunResult:
    """Result of a bulk analysis run."""

    results: list[RepositoryAnalysisResult]
    csv_path: Path
    markdown_path: Path

    @property
    def succeeded(self) -> list[RepositoryAnalysisResult]:
        return [result for result in self.results if result.succeeded]

    @property
    def failed(self) -> list[RepositoryAnalysisResult]:
        return [result for result in self.results if not result.succeeded]

    def final_summary_lines(self) -> list[str]:
        successes = self.succeeded
        total_health = sum(result.health_score or 0 for result in successes)
        average_health = round(total_health / len(successes)) if successes else 0
        return [
            f"Repositories scanned: {len(self.results)}",
            f"Succeeded: {len(successes)}",
            f"Failed: {len(self.failed)}",
            f"Average health score: {average_health}",
            f"Critical findings: {sum(result.critical_findings for result in successes)}",
            f"High findings: {sum(result.high_findings for result in successes)}",
        ]


def read_repository_list(path: Path) -> list[str]:
    """Read one Git repository URL per line, ignoring blank lines and comments."""

    if path.is_symlink():
        raise ValueError(f"refusing to read symlinked repository list: {path}")
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        urls.append(stripped)
    return urls


def analyse_repositories(
    git_urls: Sequence[str],
    options: AnalysisOptions,
    *,
    progress: ProgressWriter | None = print,
) -> AnalysisRunResult:
    """Analyse many repositories, continuing when one repository fails."""

    urls = [url.strip() for url in git_urls if url.strip()]
    if not urls:
        raise ValueError("no repository URLs provided")
    if options.workers < 1:
        raise ValueError("--workers must be at least 1")

    output_dir = options.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise ValueError(f"output directory must not be a symlink: {output_dir}")

    tasks = _build_tasks(urls)
    results: list[RepositoryAnalysisResult] = []
    writer = _threadsafe_progress(progress)

    with ThreadPoolExecutor(max_workers=min(options.workers, len(tasks))) as executor:
        futures = {
            executor.submit(analyse_repository, task, options, output_dir, writer): task
            for task in tasks
        }
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - defensive boundary
                result = _failure_result(task, f"unexpected analysis failure: {exc}")
            results.append(result)
            writer(result.one_line_summary())

    ordered_results = sorted(results, key=lambda result: result.index)
    csv_path, markdown_path = write_analysis_summaries(ordered_results, output_dir)
    return AnalysisRunResult(ordered_results, csv_path, markdown_path)


def analyse_repository(
    task: AnalysisTask,
    options: AnalysisOptions,
    analysis_output_dir: Path,
    progress: ProgressWriter,
) -> RepositoryAnalysisResult:
    """Clone and analyse one repository."""

    repository_name = repository_name_from_url(task.git_url)
    progress(f"[{task.index}/{task.total}] Scanning {repository_name}...")
    temp_root = Path(tempfile.mkdtemp(prefix="driftbeacon-analysis-"))
    clone_path = temp_root / "repository"
    repo_output_dir = analysis_output_dir / task.output_name
    kept_clone_path: Path | None = clone_path if options.keep else None
    try:
        clone_repository(task.git_url, clone_path, timeout_seconds=options.clone_timeout_seconds)
        supported_files = detect_supported_infrastructure_files(clone_path)
        config = load_config(
            repository_path=clone_path,
            output_dir=repo_output_dir,
            no_slack=True,
        )
        scan, _executions = run_scan(config, timeout_seconds=options.scanner_timeout_seconds)
        comparison = compare_scans(scan, None)
        top = prioritise_findings(
            scan.findings,
            limit=config.top_findings,
            production_patterns=config.production_patterns,
        )
        report = generate_report(
            scan,
            comparison,
            top_items=top,
            production_patterns=config.production_patterns,
            top_limit=config.top_findings,
        )
        storage = LocalStorage(config.output_dir)
        scan_path = storage.save_current_scan(scan)
        comparison_path = storage.save_comparison(comparison.to_dict())
        report_path = storage.save_report(report)
        _ = comparison_path
        counts = _severity_counts(scan.findings)
        return RepositoryAnalysisResult(
            index=task.index,
            git_url=redact_secrets(task.git_url),
            repository=redact_secrets(scan.repository),
            status="success",
            health_score=scan.health_score,
            critical_findings=counts["critical"],
            high_findings=counts["high"],
            medium_findings=counts["medium"],
            new_findings=len(comparison.new_findings),
            active_findings=len(active_findings(scan.findings)),
            supported_files=len(supported_files),
            output_dir=config.output_dir,
            report_path=report_path,
            scan_path=scan_path,
            clone_path=kept_clone_path,
        )
    except Exception as exc:
        return _failure_result(task, truncate(redact_secrets(str(exc)), 300), kept_clone_path)
    finally:
        if not options.keep:
            shutil.rmtree(temp_root, ignore_errors=True)


def clone_repository(git_url: str, clone_path: Path, *, timeout_seconds: int) -> None:
    """Clone a repository into a temporary directory."""

    clone_path.parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--depth", "1", "--quiet", git_url, str(clone_path)]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"git clone timed out after {timeout_seconds}s") from exc
    except OSError as exc:
        raise ValueError(f"git clone could not start: {exc}") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown git error"
        raise ValueError(f"git clone failed: {truncate(redact_secrets(message), 260)}")


def detect_supported_infrastructure_files(repository_path: Path) -> list[Path]:
    """Return files that existing DriftBeacon scanners can inspect."""

    files: list[Path] = []
    for path in safe_walk(repository_path):
        if _is_supported_file(path):
            files.append(path.relative_to(repository_path))
    return sorted(files)


def write_analysis_summaries(
    results: Sequence[RepositoryAnalysisResult],
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write CSV and Markdown summaries for a bulk analysis run."""

    csv_path = output_dir / "analysis-summary.csv"
    markdown_path = output_dir / "analysis-summary.md"
    _write_csv(results, csv_path)
    _write_text(markdown_path, analysis_summary_markdown(results))
    return csv_path, markdown_path


def analysis_summary_markdown(results: Sequence[RepositoryAnalysisResult]) -> str:
    """Render a Markdown summary ranked by lowest health score first."""

    successes = sorted(
        (result for result in results if result.succeeded),
        key=lambda result: result.health_score if result.health_score is not None else 101,
    )
    failures = [result for result in results if not result.succeeded]
    lines = [
        "# DriftBeacon Repository Analysis Summary",
        "",
        "| Rank | Repository | Health | Critical | High | Medium | New | Report |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    if successes:
        for rank, result in enumerate(successes, start=1):
            lines.append(
                "| "
                f"{rank} | {result.repository} | {result.health_score} | "
                f"{result.critical_findings} | {result.high_findings} | "
                f"{result.medium_findings} | {result.new_findings} | "
                f"{_path_text(result.report_path)} |"
            )
    else:
        lines.append("| - | No repositories succeeded | - | - | - | - | - | - |")

    if failures:
        lines.extend(
            [
                "",
                "## Failed repositories",
                "",
                "| Repository | Error |",
                "| --- | --- |",
            ]
        )
        for result in failures:
            lines.append(f"| {result.repository} | {result.error or 'unknown error'} |")
    lines.append("")
    return "\n".join(lines)


def repository_name_from_url(git_url: str) -> str:
    """Derive a display name from common Git URL shapes."""

    cleaned = git_url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if cleaned.startswith("git@") and ":" in cleaned:
        cleaned = cleaned.rsplit(":", 1)[1]
    return cleaned.rsplit("/", 1)[-1] or "repository"


def _build_tasks(git_urls: Sequence[str]) -> list[AnalysisTask]:
    used: set[str] = set()
    tasks: list[AnalysisTask] = []
    total = len(git_urls)
    for index, git_url in enumerate(git_urls, start=1):
        name = _unique_output_name(_slugify(repository_name_from_url(git_url)), used)
        tasks.append(AnalysisTask(index=index, total=total, git_url=git_url, output_name=name))
    return tasks


def _failure_result(
    task: AnalysisTask,
    error: str,
    clone_path: Path | None = None,
) -> RepositoryAnalysisResult:
    return RepositoryAnalysisResult(
        index=task.index,
        git_url=redact_secrets(task.git_url),
        repository=redact_secrets(repository_name_from_url(task.git_url)),
        status="failed",
        health_score=None,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        new_findings=0,
        active_findings=0,
        supported_files=0,
        output_dir=None,
        report_path=None,
        scan_path=None,
        clone_path=clone_path,
        error=error,
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    active = active_findings(findings)
    return {
        "critical": sum(1 for finding in active if finding.severity == "critical"),
        "high": sum(1 for finding in active if finding.severity == "high"),
        "medium": sum(1 for finding in active if finding.severity == "medium"),
    }


def _write_csv(results: Sequence[RepositoryAnalysisResult], path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing to write symlinked analysis summary: {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "repository",
                "git_url",
                "status",
                "health_score",
                "critical",
                "high",
                "medium",
                "new_findings",
                "active_findings",
                "supported_files",
                "report_path",
                "scan_path",
                "clone_path",
                "error",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "repository": result.repository,
                    "git_url": result.git_url,
                    "status": result.status,
                    "health_score": result.health_score if result.health_score is not None else "",
                    "critical": result.critical_findings,
                    "high": result.high_findings,
                    "medium": result.medium_findings,
                    "new_findings": result.new_findings,
                    "active_findings": result.active_findings,
                    "supported_files": result.supported_files,
                    "report_path": _path_text(result.report_path),
                    "scan_path": _path_text(result.scan_path),
                    "clone_path": _path_text(result.clone_path),
                    "error": result.error or "",
                }
            )


def _write_text(path: Path, text: str) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing to write symlinked analysis summary: {path}")
    path.write_text(text, encoding="utf-8")


def _path_text(path: Path | None) -> str:
    return path.as_posix() if path is not None else ""


def _is_supported_file(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in DEPENDENCY_FILES:
        return True
    if name == "dockerfile" or name.startswith("dockerfile."):
        return True
    if suffix in {".tf", ".tfvars"} or path.name.endswith(".tf.json"):
        return True
    return suffix in {".yaml", ".yml", ".json"}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-_").lower()
    return slug or "repository"


def _unique_output_name(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _threadsafe_progress(progress: ProgressWriter | None) -> ProgressWriter:
    if progress is None:
        return lambda _message: None
    lock = threading.Lock()

    def write(message: str) -> None:
        with lock:
            progress(message)

    return write
