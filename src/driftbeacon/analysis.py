"""Bulk public repository analysis mode."""

from __future__ import annotations

import csv
import json
import re
import shutil
import subprocess
import tempfile
import threading
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

from . import __version__
from .comparison import compare_scans
from .config import load_config
from .models import Finding, ScanResult, Severity
from .prioritise import prioritise_findings
from .redaction import redact_secrets, truncate
from .reporting import generate_report
from .scan import run_scan
from .scanners.base import safe_walk
from .scanners.trivy import DEPENDENCY_FILES
from .scoring import actionable_active_findings, actionable_findings, severity_counts
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
class FindingSummary:
    """A compact per-repository finding group."""

    rule_id: str
    title: str
    severity: Severity
    occurrences: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "occurrences": self.occurrences,
        }


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
    category: str = "Unknown"
    low_findings: int = 0
    total_findings: int = 0
    resolved_findings: int = 0
    recurring_findings: int = 0
    has_baseline: bool = False
    raw_scanner_results: int = 0
    normalised_findings: int = 0
    deduplicated_findings: int = 0
    duplicate_findings_removed: int = 0
    passed_checks: int = 0
    informational_findings: int = 0
    unknown_severity_findings: int = 0
    ignored_findings: int = 0
    scanner_errors: int = 0
    checkov_status: str = "unknown"
    trivy_status: str = "unknown"
    finding_summaries: tuple[FindingSummary, ...] = field(default_factory=tuple)

    @property
    def succeeded(self) -> bool:
        return self.status == "success"

    @property
    def grade(self) -> str:
        return health_grade(self.health_score)

    @property
    def findings_per_100_files(self) -> float:
        if self.supported_files <= 0:
            return 0.0
        return round((self.total_findings / self.supported_files) * 100, 1)

    @property
    def scan_mode(self) -> str:
        return "comparison_scan" if self.has_baseline else "initial_baseline"

    def one_line_summary(self) -> str:
        if not self.succeeded:
            return f"{self.repository}: failed: {self.error or 'unknown error'}"
        return (
            f"{self.repository}: health={self.health_score} "
            f"critical={self.critical_findings} high={self.high_findings} "
            f"medium={self.medium_findings} new={self.new_findings if self.has_baseline else '-'}"
        )

    def to_dict(self, output_dir: Path) -> dict[str, Any]:
        clone_path = _path_text(self.clone_path) if self.clone_path is not None else ""
        return {
            "repository": self.repository,
            "git_url": self.git_url,
            "status": self.status,
            "scan_mode": self.scan_mode,
            "category": self.category,
            "health_score": self.health_score,
            "grade": self.grade,
            "critical": self.critical_findings,
            "high": self.high_findings,
            "medium": self.medium_findings,
            "low": self.low_findings,
            "total_findings": self.total_findings,
            "new_findings": self.new_findings if self.has_baseline else None,
            "resolved_findings": self.resolved_findings if self.has_baseline else None,
            "recurring_findings": self.recurring_findings if self.has_baseline else None,
            "supported_files": self.supported_files,
            "findings_per_100_files": self.findings_per_100_files,
            "report_path": _relative_path_text(self.report_path, output_dir),
            "scan_path": _relative_path_text(self.scan_path, output_dir),
            "clone_path": clone_path,
            "scanner_status": {
                "checkov": self.checkov_status,
                "trivy": self.trivy_status,
            },
            "audit": {
                "raw_scanner_results": self.raw_scanner_results,
                "normalised_findings": self.normalised_findings,
                "deduplicated_findings": self.deduplicated_findings,
                "deduplicated_active_findings": self.total_findings,
                "duplicate_findings_removed": self.duplicate_findings_removed,
                "passed_checks": self.passed_checks,
                "informational_findings": self.informational_findings,
                "unknown_severity_findings": self.unknown_severity_findings,
                "ignored_findings": self.ignored_findings,
                "scanner_errors": self.scanner_errors,
            },
            "common_findings": [finding.to_dict() for finding in self.finding_summaries],
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class AnalysisRunResult:
    """Result of a bulk analysis run."""

    results: list[RepositoryAnalysisResult]
    csv_path: Path
    markdown_path: Path
    json_path: Path

    @property
    def succeeded(self) -> list[RepositoryAnalysisResult]:
        return [result for result in self.results if result.succeeded]

    @property
    def failed(self) -> list[RepositoryAnalysisResult]:
        return [result for result in self.results if not result.succeeded]

    def final_summary_lines(self) -> list[str]:
        stats = aggregate_statistics(self.results)
        return [
            f"Repositories scanned: {len(self.results)}",
            f"Succeeded: {len(self.succeeded)}",
            f"Failed: {len(self.failed)}",
            f"Average health score: {stats['average_health_score']}",
            f"Critical findings: {stats['total_critical_findings']}",
            f"High findings: {stats['total_high_findings']}",
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
    csv_path, markdown_path, json_path = write_analysis_summaries(ordered_results, output_dir)
    return AnalysisRunResult(ordered_results, csv_path, markdown_path, json_path)


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
        previous_scan = _load_existing_scan(repo_output_dir)
        clone_repository(task.git_url, clone_path, timeout_seconds=options.clone_timeout_seconds)
        supported_files = detect_supported_infrastructure_files(clone_path)
        config = load_config(
            repository_path=clone_path,
            output_dir=repo_output_dir,
            no_slack=True,
        )
        scan, _executions = run_scan(config, timeout_seconds=options.scanner_timeout_seconds)
        comparison = compare_scans(scan, previous_scan)
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
        storage.save_comparison(comparison.to_dict())
        report_path = storage.save_report(report)
        counts = severity_counts(scan.findings)
        actionable = actionable_active_findings(scan.findings)
        total_findings = sum(counts[severity] for severity in ("critical", "high", "medium", "low"))
        repository = redact_secrets(repository_full_name_from_url(task.git_url))
        return RepositoryAnalysisResult(
            index=task.index,
            git_url=redact_secrets(task.git_url),
            repository=repository,
            status="success",
            health_score=scan.health_score,
            critical_findings=counts["critical"],
            high_findings=counts["high"],
            medium_findings=counts["medium"],
            new_findings=len(actionable_active_findings(comparison.new_findings))
            if comparison.has_baseline
            else 0,
            active_findings=total_findings,
            supported_files=len(supported_files),
            output_dir=config.output_dir,
            report_path=report_path,
            scan_path=scan_path,
            clone_path=kept_clone_path,
            category=detect_repository_category(repository, supported_files),
            low_findings=counts["low"],
            total_findings=total_findings,
            resolved_findings=len(actionable_findings(comparison.resolved_findings))
            if comparison.has_baseline
            else 0,
            recurring_findings=len(actionable_active_findings(comparison.recurring_findings))
            if comparison.has_baseline
            else 0,
            has_baseline=comparison.has_baseline,
            raw_scanner_results=_summary_int(scan.summary, "raw_scanner_results"),
            normalised_findings=_summary_int(scan.summary, "normalised_findings"),
            deduplicated_findings=_summary_int(scan.summary, "deduplicated_findings"),
            duplicate_findings_removed=_summary_int(scan.summary, "duplicate_findings_removed"),
            passed_checks=_summary_int(scan.summary, "passed_checks"),
            informational_findings=_summary_int(scan.summary, "informational_findings"),
            unknown_severity_findings=_summary_int(scan.summary, "unknown_severity_findings"),
            ignored_findings=_summary_int(scan.summary, "ignored_findings"),
            scanner_errors=_summary_int(scan.summary, "scanner_errors"),
            checkov_status=_scanner_status_text(scan, "checkov"),
            trivy_status=_scanner_status_text(scan, "trivy"),
            finding_summaries=finding_summaries(actionable),
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


def detect_repository_category(repository: str, supported_files: Sequence[Path]) -> str:
    """Classify a repository into a broad, explainable bucket."""

    name = repository.lower()
    repo_name = name.rsplit("/", 1)[-1]
    if any(word in name for word in ("guide", "example", "learn", "sample", "demo", "tutorial")):
        return "Examples or guides"
    if repo_name.startswith("terraform-provider-"):
        return "Terraform provider"
    file_kinds = _file_kinds(supported_files)
    if repo_name.startswith("terraform-") and "terraform" in file_kinds:
        return "Terraform module"
    if _looks_like_kubernetes_project(name, supported_files):
        return "Kubernetes project"
    if len(file_kinds) >= 2:
        return "Mixed infrastructure repository"
    return "Unknown"


def write_analysis_summaries(
    results: Sequence[RepositoryAnalysisResult],
    output_dir: Path,
) -> tuple[Path, Path, Path]:
    """Write CSV, Markdown, and JSON summaries for a bulk analysis run."""

    generated_at = datetime.now(UTC)
    csv_path = output_dir / "analysis-summary.csv"
    markdown_path = output_dir / "analysis-summary.md"
    json_path = output_dir / "analysis-summary.json"
    _write_csv(results, csv_path, output_dir)
    _write_text(markdown_path, analysis_summary_markdown(results, output_dir, generated_at))
    _write_text(
        json_path,
        json.dumps(analysis_summary_json(results, output_dir, generated_at), indent=2)
        + "\n",
    )
    return csv_path, markdown_path, json_path


def analysis_summary_markdown(
    results: Sequence[RepositoryAnalysisResult],
    output_dir: Path,
    generated_at: datetime | None = None,
) -> str:
    """Render a Markdown summary ranked by lowest health score first."""

    timestamp = generated_at or datetime.now(UTC)
    successes = _ranked_successes(results)
    failures = [result for result in results if not result.succeeded]
    stats = aggregate_statistics(results)
    include_comparison = any(result.has_baseline for result in successes)
    lines = [
        "# DriftBeacon Repository Analysis Summary",
        "",
        f"**Scan date:** {timestamp.isoformat()}  ",
        f"**DriftBeacon version:** {__version__}  ",
        f"**Repositories requested:** {len(results)}  ",
        f"**Successful scans:** {len(successes)}  ",
        f"**Failed scans:** {len(failures)}  ",
        f"**Run type:** {_scan_mode_label(results)}",
        "",
        "## Executive summary",
        f"- Average health score: {stats['average_health_score']}",
        f"- Median health score: {stats['median_health_score']}",
        f"- Total actionable findings: {stats['total_actionable_findings']}",
        f"- Total critical findings: {stats['total_critical_findings']}",
        f"- Total high findings: {stats['total_high_findings']}",
        f"- Total medium findings: {stats['total_medium_findings']}",
        f"- Total low findings: {stats['total_low_findings']}",
        f"- Repositories with scanner errors: {stats['repositories_with_scanner_errors']}",
        "",
        "## Leaderboard",
        "",
        _leaderboard_header(include_comparison),
        _leaderboard_separator(include_comparison),
    ]
    if successes:
        for rank, result in enumerate(successes, start=1):
            lines.append(_leaderboard_row(rank, result, output_dir, include_comparison))
    else:
        lines.append(_empty_leaderboard_row(include_comparison))

    lines.extend(_common_findings_section(results))
    lines.extend(_scanner_coverage_section(results))
    lines.extend(_failed_repositories_section(failures))
    lines.extend(
        [
            "",
            "## Methodology and limitations",
            "",
            "- Results are based on static analysis from Checkov and Trivy.",
            "- Findings may include false positives.",
            "- Public repositories may include intentionally insecure examples and test fixtures.",
            "- A low score is not proof that a project is insecure.",
            "- Scores represent the scanned commit at the scan time.",
            "- Large and small repositories are not directly comparable by raw finding count.",
            "- Results should not be presented as an accusation against maintainers.",
            "- Health uses deduplicated active critical, high, medium, and low findings only.",
            "- Informational and unknown-severity findings are audited but ignored by the score.",
            "",
        ]
    )
    return "\n".join(lines)


def analysis_summary_json(
    results: Sequence[RepositoryAnalysisResult],
    output_dir: Path,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Return a stable JSON summary suitable for later research."""

    timestamp = generated_at or datetime.now(UTC)
    failures = [result for result in results if not result.succeeded]
    return {
        "schema_version": "1.0",
        "metadata": {
            "scan_date": timestamp.isoformat(),
            "driftbeacon_version": __version__,
            "repositories_requested": len(results),
            "successful_scans": len([result for result in results if result.succeeded]),
            "failed_scans": len(failures),
            "scan_mode": _scan_mode(results),
        },
        "aggregate_statistics": aggregate_statistics(results),
        "severity_totals": severity_totals(results),
        "scanner_coverage": scanner_coverage(results),
        "common_findings": common_findings(results),
        "failure_details": [
            {"repository": result.repository, "git_url": result.git_url, "error": result.error}
            for result in failures
        ],
        "raw_vs_deduplicated_counts": raw_vs_deduplicated_counts(results),
        "repository_results": [result.to_dict(output_dir) for result in results],
    }


def aggregate_statistics(results: Sequence[RepositoryAnalysisResult]) -> dict[str, int]:
    """Aggregate successful repository results."""

    successes = [result for result in results if result.succeeded]
    health_scores = [result.health_score or 0 for result in successes]
    return {
        "average_health_score": round(sum(health_scores) / len(health_scores))
        if health_scores
        else 0,
        "median_health_score": round(median(health_scores)) if health_scores else 0,
        "total_actionable_findings": sum(result.total_findings for result in successes),
        "total_critical_findings": sum(result.critical_findings for result in successes),
        "total_high_findings": sum(result.high_findings for result in successes),
        "total_medium_findings": sum(result.medium_findings for result in successes),
        "total_low_findings": sum(result.low_findings for result in successes),
        "repositories_with_scanner_errors": sum(
            1 for result in successes if result.scanner_errors > 0
        ),
    }


def severity_totals(results: Sequence[RepositoryAnalysisResult]) -> dict[str, int]:
    successes = [result for result in results if result.succeeded]
    return {
        "critical": sum(result.critical_findings for result in successes),
        "high": sum(result.high_findings for result in successes),
        "medium": sum(result.medium_findings for result in successes),
        "low": sum(result.low_findings for result in successes),
    }


def scanner_coverage(results: Sequence[RepositoryAnalysisResult]) -> dict[str, dict[str, int]]:
    successes = [result for result in results if result.succeeded]
    coverage: dict[str, dict[str, int]] = {
        "checkov": {"success": 0, "skipped": 0, "failed": 0},
        "trivy": {"success": 0, "skipped": 0, "failed": 0},
    }
    for result in successes:
        _add_scanner_status(coverage["checkov"], result.checkov_status)
        _add_scanner_status(coverage["trivy"], result.trivy_status)
    return coverage


def common_findings(
    results: Sequence[RepositoryAnalysisResult],
    limit: int = 10,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, Severity], dict[str, Any]] = {}
    affected: dict[tuple[str, str, Severity], set[str]] = defaultdict(set)
    for result in results:
        if not result.succeeded:
            continue
        for finding in result.finding_summaries:
            key = (finding.rule_id, finding.title, finding.severity)
            affected[key].add(result.repository)
            if key not in grouped:
                grouped[key] = {
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "affected_repositories": 0,
                    "total_occurrences": 0,
                }
            grouped[key]["total_occurrences"] += finding.occurrences
    for key, value in grouped.items():
        value["affected_repositories"] = len(affected[key])
    return sorted(
        grouped.values(),
        key=lambda item: (item["affected_repositories"], item["total_occurrences"]),
        reverse=True,
    )[:limit]


def raw_vs_deduplicated_counts(results: Sequence[RepositoryAnalysisResult]) -> dict[str, int]:
    successes = [result for result in results if result.succeeded]
    return {
        "raw_scanner_results": sum(result.raw_scanner_results for result in successes),
        "normalised_findings": sum(result.normalised_findings for result in successes),
        "deduplicated_findings": sum(result.deduplicated_findings for result in successes),
        "deduplicated_active_findings": sum(result.total_findings for result in successes),
        "duplicate_findings_removed": sum(
            result.duplicate_findings_removed for result in successes
        ),
        "passed_checks": sum(result.passed_checks for result in successes),
        "informational_findings": sum(result.informational_findings for result in successes),
        "unknown_severity_findings": sum(result.unknown_severity_findings for result in successes),
        "ignored_findings": sum(result.ignored_findings for result in successes),
    }


def repository_name_from_url(git_url: str) -> str:
    """Derive a repository name from common Git URL shapes."""

    return repository_full_name_from_url(git_url).rsplit("/", 1)[-1]


def repository_full_name_from_url(git_url: str) -> str:
    """Derive owner/repository when a Git URL contains owner context."""

    cleaned = git_url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if cleaned.startswith("git@") and ":" in cleaned:
        cleaned = cleaned.rsplit(":", 1)[1]
    parts = [part for part in cleaned.split("/") if part]
    if len(parts) >= 2 and "." not in parts[-2]:
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1] if parts else "repository"


def finding_summaries(findings: Sequence[Finding]) -> tuple[FindingSummary, ...]:
    counts: Counter[tuple[str, str, Severity]] = Counter(
        (finding.rule_id, finding.title, finding.severity) for finding in findings
    )
    return tuple(
        FindingSummary(rule_id=rule_id, title=title, severity=severity, occurrences=count)
        for (rule_id, title, severity), count in sorted(counts.items())
    )


def health_grade(score: int | None) -> str:
    if score is None:
        return "-"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _build_tasks(git_urls: Sequence[str]) -> list[AnalysisTask]:
    used: set[str] = set()
    tasks: list[AnalysisTask] = []
    total = len(git_urls)
    for index, git_url in enumerate(git_urls, start=1):
        base = _slugify(repository_full_name_from_url(git_url).replace("/", "--"))
        name = _unique_output_name(base, used)
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
        repository=redact_secrets(repository_full_name_from_url(task.git_url)),
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


def _load_existing_scan(output_dir: Path) -> ScanResult | None:
    path = output_dir / "current-scan.json"
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError(f"refusing to read symlinked previous scan: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    return ScanResult.from_dict(data)


def _summary_int(summary: dict[str, int | str], key: str) -> int:
    value = summary.get(key, 0)
    return value if isinstance(value, int) else 0


def _ranked_successes(
    results: Sequence[RepositoryAnalysisResult],
) -> list[RepositoryAnalysisResult]:
    return sorted(
        (result for result in results if result.succeeded),
        key=lambda result: result.health_score if result.health_score is not None else 101,
    )


def _write_csv(
    results: Sequence[RepositoryAnalysisResult], path: Path, output_dir: Path
) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing to write symlinked analysis summary: {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_csv_fieldnames())
        writer.writeheader()
        for result in results:
            writer.writerow(_csv_row(result, output_dir))


def _csv_fieldnames() -> list[str]:
    return [
        "repository",
        "git_url",
        "status",
        "scan_mode",
        "category",
        "health_score",
        "grade",
        "critical",
        "high",
        "medium",
        "low",
        "total_findings",
        "new_findings",
        "resolved_findings",
        "recurring_findings",
        "files_scanned",
        "findings_per_100_files",
        "report_path",
        "scan_path",
        "checkov_status",
        "trivy_status",
        "scanner_errors",
        "raw_scanner_results",
        "normalised_findings",
        "deduplicated_findings",
        "duplicate_findings_removed",
        "passed_checks",
        "informational_findings",
        "unknown_severity_findings",
        "ignored_findings",
        "clone_path",
        "error",
    ]


def _csv_row(result: RepositoryAnalysisResult, output_dir: Path) -> dict[str, int | str]:
    return {
        "repository": result.repository,
        "git_url": result.git_url,
        "status": result.status,
        "scan_mode": result.scan_mode,
        "category": result.category,
        "health_score": result.health_score if result.health_score is not None else "",
        "grade": result.grade,
        "critical": result.critical_findings,
        "high": result.high_findings,
        "medium": result.medium_findings,
        "low": result.low_findings,
        "total_findings": result.total_findings,
        "new_findings": result.new_findings if result.has_baseline else "",
        "resolved_findings": result.resolved_findings if result.has_baseline else "",
        "recurring_findings": result.recurring_findings if result.has_baseline else "",
        "files_scanned": result.supported_files,
        "findings_per_100_files": f"{result.findings_per_100_files:.1f}",
        "report_path": _relative_path_text(result.report_path, output_dir),
        "scan_path": _relative_path_text(result.scan_path, output_dir),
        "checkov_status": result.checkov_status,
        "trivy_status": result.trivy_status,
        "scanner_errors": result.scanner_errors,
        "raw_scanner_results": result.raw_scanner_results,
        "normalised_findings": result.normalised_findings,
        "deduplicated_findings": result.deduplicated_findings,
        "duplicate_findings_removed": result.duplicate_findings_removed,
        "passed_checks": result.passed_checks,
        "informational_findings": result.informational_findings,
        "unknown_severity_findings": result.unknown_severity_findings,
        "ignored_findings": result.ignored_findings,
        "clone_path": _path_text(result.clone_path),
        "error": result.error or "",
    }


def _write_text(path: Path, text: str) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing to write symlinked analysis summary: {path}")
    path.write_text(text, encoding="utf-8")


def _leaderboard_header(include_comparison: bool) -> str:
    columns = [
        "Rank",
        "Repository",
        "Category",
        "Health",
        "Grade",
        "Critical",
        "High",
        "Medium",
        "Low",
        "Total Findings",
    ]
    if include_comparison:
        columns.extend(["New", "Resolved", "Recurring"])
    columns.extend(["Files Scanned", "Findings per 100 Files", "Report"])
    return "| " + " | ".join(columns) + " |"


def _leaderboard_separator(include_comparison: bool) -> str:
    columns = [
        "---:",
        "---",
        "---",
        "---:",
        "---",
        "---:",
        "---:",
        "---:",
        "---:",
        "---:",
    ]
    if include_comparison:
        columns.extend(["---:", "---:", "---:"])
    columns.extend(["---:", "---:", "---"])
    return "| " + " | ".join(columns) + " |"


def _leaderboard_row(
    rank: int,
    result: RepositoryAnalysisResult,
    output_dir: Path,
    include_comparison: bool,
) -> str:
    values: list[str | int] = [
        rank,
        result.repository,
        result.category,
        result.health_score if result.health_score is not None else "-",
        result.grade,
        result.critical_findings,
        result.high_findings,
        result.medium_findings,
        result.low_findings,
        result.total_findings,
    ]
    if include_comparison:
        values.extend(
            [
                result.new_findings if result.has_baseline else "-",
                result.resolved_findings if result.has_baseline else "-",
                result.recurring_findings if result.has_baseline else "-",
            ]
        )
    values.extend(
        [
            result.supported_files,
            f"{result.findings_per_100_files:.1f}",
            _report_link(result, output_dir),
        ]
    )
    return "| " + " | ".join(_markdown_cell(value) for value in values) + " |"


def _empty_leaderboard_row(include_comparison: bool) -> str:
    cells = ["-", "No repositories succeeded", "-", "-", "-", "-", "-", "-", "-", "-"]
    if include_comparison:
        cells.extend(["-", "-", "-"])
    cells.extend(["-", "-", "-"])
    return "| " + " | ".join(cells) + " |"


def _common_findings_section(results: Sequence[RepositoryAnalysisResult]) -> list[str]:
    findings = common_findings(results)
    lines = [
        "",
        "## Most common findings",
        "",
        "| Rule ID | Title | Severity | Affected repositories | Total occurrences |",
        "| --- | --- | --- | ---: | ---: |",
    ]
    if not findings:
        lines.append("| - | No actionable findings detected | - | - | - |")
        return lines
    for finding in findings:
        lines.append(
            "| "
            f"{_markdown_cell(finding['rule_id'])} | "
            f"{_markdown_cell(finding['title'])} | "
            f"{_markdown_cell(finding['severity'])} | "
            f"{finding['affected_repositories']} | {finding['total_occurrences']} |"
        )
    return lines


def _scanner_coverage_section(results: Sequence[RepositoryAnalysisResult]) -> list[str]:
    coverage = scanner_coverage(results)
    return [
        "",
        "## Scanner coverage",
        "",
        "| Scanner | Succeeded | Skipped | Failed |",
        "| --- | ---: | ---: | ---: |",
        (
            f"| Checkov | {coverage['checkov']['success']} | {coverage['checkov']['skipped']} | "
            f"{coverage['checkov']['failed']} |"
        ),
        (
            f"| Trivy | {coverage['trivy']['success']} | {coverage['trivy']['skipped']} | "
            f"{coverage['trivy']['failed']} |"
        ),
    ]


def _failed_repositories_section(results: Sequence[RepositoryAnalysisResult]) -> list[str]:
    if not results:
        return []
    lines = [
        "",
        "## Failed repositories",
        "",
        "| Repository | Error |",
        "| --- | --- |",
    ]
    for result in results:
        lines.append(
            f"| {_markdown_cell(result.repository)} | "
            f"{_markdown_cell(result.error or 'unknown error')} |"
        )
    return lines


def _report_link(result: RepositoryAnalysisResult, output_dir: Path) -> str:
    relative = _relative_path_text(result.report_path, output_dir)
    if not relative:
        return ""
    return f"[View report]({relative})"


def _scanner_status_text(scan: ScanResult, scanner: str) -> str:
    status = scan.scanner_statuses.get(scanner)
    return status.status if status else "unknown"


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _relative_path_text(path: Path | None, output_dir: Path) -> str:
    if path is None:
        return ""
    with_context = path.resolve()
    try:
        return with_context.relative_to(output_dir.resolve()).as_posix()
    except ValueError:
        return path.name


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
    if suffix in {".yaml", ".yml", ".json"}:
        return _looks_like_infrastructure_file(path)
    return False


def _looks_like_infrastructure_file(path: Path) -> bool:
    try:
        sample = path.read_text(encoding="utf-8", errors="ignore")[:8192].lower()
    except OSError:
        return False
    return any(
        marker in sample
        for marker in (
            "apiversion:",
            "kind:",
            "awstemplateformatversion",
            "type: aws::",
            "kustomization",
            "helm.sh/chart",
            "docker-compose",
            "services:",
            "resources:",
        )
    )


def _file_kinds(supported_files: Sequence[Path]) -> set[str]:
    kinds: set[str] = set()
    for path in supported_files:
        name = path.name.lower()
        suffix = path.suffix.lower()
        if suffix in {".tf", ".tfvars"} or path.name.endswith(".tf.json"):
            kinds.add("terraform")
        elif name == "dockerfile" or name.startswith("dockerfile."):
            kinds.add("docker")
        elif suffix in {".yaml", ".yml", ".json"}:
            kinds.add("yaml_or_json_iac")
        elif name in DEPENDENCY_FILES:
            kinds.add("dependency")
    return kinds


def _looks_like_kubernetes_project(repository: str, supported_files: Sequence[Path]) -> bool:
    if any(word in repository for word in ("kubernetes", "k8s", "kube", "helm", "operator")):
        return True
    for path in supported_files:
        text = path.as_posix().lower()
        if any(word in text for word in ("kubernetes", "k8s", "helm", "charts/", "kustomize")):
            return True
    return False


def _add_scanner_status(counts: dict[str, int], status: str) -> None:
    if status == "success":
        counts["success"] += 1
    elif status == "skipped":
        counts["skipped"] += 1
    else:
        counts["failed"] += 1


def _scan_mode(results: Sequence[RepositoryAnalysisResult]) -> str:
    successes = [result for result in results if result.succeeded]
    if not successes:
        return "initial_baseline"
    has_baseline_count = sum(1 for result in successes if result.has_baseline)
    if has_baseline_count == 0:
        return "initial_baseline"
    if has_baseline_count == len(successes):
        return "comparison_scan"
    return "mixed"


def _scan_mode_label(results: Sequence[RepositoryAnalysisResult]) -> str:
    labels = {
        "initial_baseline": "Initial baseline",
        "comparison_scan": "Comparison scan",
        "mixed": "Mixed initial and comparison scan",
    }
    return labels[_scan_mode(results)]


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-_").lower()
    return slug or "repository"


def _unique_output_name(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}--{suffix}"
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
