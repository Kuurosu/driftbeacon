"""Repository-analysis metadata, score eligibility, and breakdown helpers."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .models import Finding, ScannerStatus
from .scanners.base import ScannerExecution
from .scoring import ACTIONABLE_SEVERITIES, actionable_active_findings, calculate_health_score

ScoreState = Literal["scored", "not_scored_no_supported_files", "not_scored_all_scanners_failed"]
CoverageState = Literal[
    "complete_coverage",
    "partial_coverage",
    "not_scored_no_supported_files",
    "not_scored_all_scanners_failed",
]
ScannerResultStatus = Literal[
    "succeeded",
    "skipped_not_applicable",
    "skipped_no_supported_files",
    "failed",
    "timed_out",
    "parse_failed",
]
ScoreImpact = Literal["none", "partial coverage", "not scored"]

PATH_GROUPS = (
    "production",
    "examples",
    "tests",
    "fixtures",
    "generated",
    "vendor",
    "third_party",
    "docs",
    "charts",
    "unknown",
)
PRODUCTION_PATH_GROUP = "production"
NON_PRODUCTION_PATH_GROUPS = tuple(group for group in PATH_GROUPS if group != PRODUCTION_PATH_GROUP)

PATH_GROUP_SEGMENTS: dict[str, tuple[str, ...]] = {
    "examples": ("examples", "example", "samples", "sample", "demo"),
    "tests": ("tests", "test", "__tests__"),
    "fixtures": ("fixtures", "fixture", "testdata"),
    "generated": ("generated", "gen", ".generated"),
    "vendor": ("vendor", "vendored", "node_modules"),
    "third_party": ("third_party", "third-party", "3rdparty"),
    "docs": ("docs", "doc", "documentation"),
    "charts": ("charts", "chart", "helm"),
}


@dataclass(frozen=True, slots=True)
class ScannerResult:
    """Attributable scanner outcome for repository-analysis summaries."""

    repository: str
    scanner: str
    applicability: str
    status: ScannerResultStatus
    error: str | None
    score_impact: ScoreImpact

    def to_dict(self) -> dict[str, str | None]:
        return {
            "repository": self.repository,
            "scanner": self.scanner,
            "applicability": self.applicability,
            "status": self.status,
            "error": self.error,
            "score_impact": self.score_impact,
        }


@dataclass(frozen=True, slots=True)
class ScoreEvaluation:
    """Health score plus explicit score and coverage states."""

    health_score: int | None
    score_state: ScoreState
    coverage_state: CoverageState
    score_reason: str
    scanner_results: tuple[ScannerResult, ...]


@dataclass(frozen=True, slots=True)
class DensityMetrics:
    """Repository-level density metrics."""

    supported_files_scanned: int
    affected_supported_files: int
    affected_file_percentage: float | None
    findings_per_100_supported_files: float | None
    findings_per_affected_file: float | None

    def to_dict(self) -> dict[str, float | int | None]:
        return {
            "supported_files_scanned": self.supported_files_scanned,
            "affected_supported_files": self.affected_supported_files,
            "affected_file_percentage": self.affected_file_percentage,
            "findings_per_100_supported_files": self.findings_per_100_supported_files,
            "findings_per_affected_file": self.findings_per_affected_file,
        }


@dataclass(frozen=True, slots=True)
class CategoryResult:
    """Evidence-based repository category."""

    category: str
    confidence: str
    evidence: tuple[str, ...]


def classify_path_group(file_path: str | None) -> str:
    """Classify a finding path using exact path segments, not substrings."""

    if not file_path:
        return "unknown"
    segments = [segment.lower() for segment in Path(file_path).parts if segment not in {"", "."}]
    for group, markers in PATH_GROUP_SEGMENTS.items():
        if any(segment in markers for segment in segments):
            return group
    return "production"


def enrich_findings_for_analysis(
    findings: Sequence[Finding],
    *,
    excluded_path_groups: Iterable[str] = (),
) -> None:
    """Attach source family, directory group, and score-exclusion metadata to findings."""

    excluded = {group.lower() for group in excluded_path_groups}
    for finding in findings:
        finding.finding_family = finding.finding_family or finding_family(finding)
        finding.directory_group = classify_path_group(finding.file_path)
        finding.excluded_from_score = False
        finding.score_exclusion_reason = None
        if finding.severity not in ACTIONABLE_SEVERITIES:
            finding.excluded_from_score = True
            finding.score_exclusion_reason = "non_actionable_severity"
        elif finding.directory_group in excluded:
            finding.excluded_from_score = True
            finding.score_exclusion_reason = f"excluded_path_group:{finding.directory_group}"


def finding_family(finding: Finding) -> str:
    """Return a stable normalized scanner family label."""

    if finding.finding_family:
        return finding.finding_family
    if finding.scanner == "checkov":
        return "checkov_configuration"
    if finding.scanner == "trivy" and finding.category == "vulnerability":
        return "trivy_vulnerability"
    if finding.scanner == "trivy" and finding.category == "secret":
        return "trivy_secret"
    if finding.scanner == "trivy":
        return "trivy_misconfiguration"
    return f"{finding.scanner}_other"


def source_label(source: str) -> str:
    labels = {
        "checkov_configuration": "Checkov configuration",
        "trivy_vulnerability": "Trivy vulnerabilities",
        "trivy_misconfiguration": "Trivy misconfigurations",
        "trivy_secret": "Trivy secrets",
    }
    return labels.get(source, source.replace("_", " ").title())


def evaluate_score(
    findings: list[Finding],
    *,
    supported_file_count: int,
    scanner_results: Sequence[ScannerResult],
) -> ScoreEvaluation:
    """Apply repository-analysis score eligibility rules."""

    if supported_file_count == 0:
        updated = tuple(
            ScannerResult(
                result.repository,
                result.scanner,
                result.applicability,
                "skipped_no_supported_files",
                result.error,
                "none",
            )
            for result in scanner_results
        )
        return ScoreEvaluation(
            None,
            "not_scored_no_supported_files",
            "not_scored_no_supported_files",
            "No supported files detected.",
            updated,
        )

    applicable = [result for result in scanner_results if result.applicability == "applicable"]
    successes = [result for result in applicable if result.status == "succeeded"]
    failures = [
        result
        for result in applicable
        if result.status in {"failed", "timed_out", "parse_failed"}
    ]
    if applicable and failures and not successes:
        return ScoreEvaluation(
            None,
            "not_scored_all_scanners_failed",
            "not_scored_all_scanners_failed",
            "All applicable scanners failed.",
            tuple(_with_score_impact(scanner_results, "not scored")),
        )
    if failures:
        return ScoreEvaluation(
            calculate_health_score(findings),
            "scored",
            "partial_coverage",
            "Score calculated from successful scanner output; coverage is incomplete.",
            tuple(_with_failed_score_impact(scanner_results, "partial coverage")),
        )
    return ScoreEvaluation(
        calculate_health_score(findings),
        "scored",
        "complete_coverage",
        "All applicable scanners succeeded or were not applicable.",
        tuple(scanner_results),
    )


def evaluate_production_score(
    findings: list[Finding],
    *,
    supported_files: Sequence[Path],
    scanner_results: Sequence[ScannerResult],
) -> ScoreEvaluation:
    """Apply score eligibility to production-only findings and supported files."""

    score = evaluate_score(
        production_findings(findings),
        supported_file_count=len(production_supported_files(supported_files)),
        scanner_results=scanner_results,
    )
    if score.score_state == "not_scored_no_supported_files":
        return ScoreEvaluation(
            score.health_score,
            score.score_state,
            score.coverage_state,
            "No production-supported files detected.",
            score.scanner_results,
        )
    if score.score_state == "not_scored_all_scanners_failed":
        return ScoreEvaluation(
            score.health_score,
            score.score_state,
            score.coverage_state,
            "All applicable scanners failed for production paths.",
            score.scanner_results,
        )
    if score.coverage_state == "partial_coverage":
        return ScoreEvaluation(
            score.health_score,
            score.score_state,
            score.coverage_state,
            "Production Health calculated from successful scanner output; coverage is incomplete.",
            score.scanner_results,
        )
    return ScoreEvaluation(
        score.health_score,
        score.score_state,
        score.coverage_state,
        "Production Health calculated from production path findings.",
        score.scanner_results,
    )


def production_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Return findings whose path group is explicitly production."""

    return [
        finding
        for finding in findings
        if (finding.directory_group or classify_path_group(finding.file_path))
        == PRODUCTION_PATH_GROUP
    ]


def production_supported_files(supported_files: Sequence[Path]) -> list[Path]:
    """Return supported files whose path group is explicitly production."""

    return [
        path
        for path in supported_files
        if classify_path_group(path.as_posix()) == PRODUCTION_PATH_GROUP
    ]


def density_metrics(findings: Sequence[Finding], supported_files: Sequence[Path]) -> DensityMetrics:
    actionable = actionable_active_findings(list(findings))
    supported_count = len(supported_files)
    supported_text = {path.as_posix() for path in supported_files}
    affected_files = {
        finding.file_path
        for finding in actionable
        if finding.file_path and finding.file_path in supported_text
    }
    affected_count = len(affected_files)
    return DensityMetrics(
        supported_files_scanned=supported_count,
        affected_supported_files=affected_count,
        affected_file_percentage=round((affected_count / supported_count) * 100, 1)
        if supported_count
        else None,
        findings_per_100_supported_files=round((len(actionable) / supported_count) * 100, 1)
        if supported_count
        else None,
        findings_per_affected_file=round(len(actionable) / affected_count, 1)
        if affected_count
        else None,
    )


def finding_source_breakdown(
    findings: Sequence[Finding],
    *,
    include_repositories: Iterable[str] | None = None,
) -> dict[str, dict[str, int]]:
    """Group actionable findings by scanner family."""

    repositories = set(include_repositories or [])
    breakdown: dict[str, dict[str, int]] = {}
    affected_files: dict[str, set[str]] = defaultdict(set)
    for finding in actionable_active_findings(list(findings)):
        source = finding.finding_family or finding_family(finding)
        row = breakdown.setdefault(source, _empty_breakdown_row())
        row[finding.severity] += 1
        row["total_actionable"] += 1
        if finding.file_path:
            affected_files[source].add(finding.file_path)
    for source, row in breakdown.items():
        row["affected_files"] = len(affected_files[source])
        row["affected_repositories"] = len(repositories) if repositories else 0
    return breakdown


def directory_group_breakdown(findings: Sequence[Finding]) -> dict[str, dict[str, int]]:
    breakdown: dict[str, dict[str, int]] = {}
    for finding in actionable_active_findings(list(findings)):
        group = finding.directory_group or classify_path_group(finding.file_path)
        row = breakdown.setdefault(group, _empty_breakdown_row())
        row[finding.severity] += 1
        row["total_actionable"] += 1
    return breakdown


def excluded_finding_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for finding in findings:
        if finding.excluded_from_score:
            counts[finding.score_exclusion_reason or "excluded"] += 1
    return dict(sorted(counts.items()))


def top_paths_by_findings(
    findings: Sequence[Finding],
    *,
    by_file: bool,
    limit: int = 10,
) -> list[dict[str, int | str]]:
    counts: Counter[str] = Counter()
    for finding in actionable_active_findings(list(findings)):
        file_path = finding.file_path or "unknown"
        key = file_path if by_file else _directory_for(file_path)
        counts[key] += 1
    return [
        {"path": path, "actionable_findings": count}
        for path, count in counts.most_common(limit)
    ]


def scanner_result_from_execution(
    repository: str,
    execution: ScannerExecution,
    *,
    applicable: bool,
) -> ScannerResult:
    if not applicable:
        return ScannerResult(
            repository,
            execution.scanner,
            "not_applicable",
            "skipped_not_applicable",
            None,
            "none",
        )
    status = _scanner_result_status(execution.status)
    error = execution.status.message if status != "succeeded" else None
    return ScannerResult(repository, execution.scanner, "applicable", status, error, "none")


def scanner_issue_rows(results: Sequence[Any]) -> list[ScannerResult]:
    issues: list[ScannerResult] = []
    for result in results:
        if not getattr(result, "succeeded", False):
            continue
        for scanner in getattr(result, "scanner_results", ()):
            if scanner.status in {"failed", "timed_out", "parse_failed"}:
                issues.append(scanner)
    return issues


def classify_repository(
    repository: str,
    repository_path: Path,
    supported_files: Sequence[Path],
) -> CategoryResult:
    name = repository.lower()
    repo_name = name.rsplit("/", 1)[-1]
    files = list(supported_files)
    file_kinds = _file_kinds(files)
    evidence: list[str] = []

    if _looks_like_terraform_tooling(name, repository_path):
        evidence.append("repository name or metadata indicates Terraform tooling")
        if repo_name in {"terragrunt", "terraform-cdk", "cdktf"}:
            evidence.append(f"repository name contains {repo_name}")
        return CategoryResult("Terraform tooling", "high", tuple(evidence))

    if repo_name.startswith("terraform-provider-") or _has_provider_markers(repository_path):
        evidence.append("provider name or Go provider SDK markers detected")
        return CategoryResult("Terraform provider", "high", tuple(evidence))

    if _has_kubernetes_controller_markers(name, repository_path, files):
        evidence.append("Kubernetes controller/operator markers detected")
        return CategoryResult("Kubernetes application or controller", "high", tuple(evidence))

    if _looks_like_terraform_learning_repository(repo_name) and "terraform" in file_kinds:
        evidence.append("repository name indicates Terraform learning material")
        return CategoryResult("Terraform examples or guides", "high", tuple(evidence))

    if "terraform" in file_kinds and "kubernetes" in file_kinds:
        evidence.append("both Terraform and Kubernetes files are present")
        return CategoryResult("Mixed infrastructure repository", "medium", tuple(evidence))

    if _looks_like_terraform_module(name, repository_path, files):
        evidence.append("Terraform module structure detected")
        if name.startswith("terraform-aws-modules/terraform-aws-"):
            evidence.append("terraform-aws-modules organisation module naming detected")
        return CategoryResult("Terraform module", "high", tuple(evidence))

    if _is_examples_repository(name, files):
        evidence.append("repository name or paths indicate examples or guides")
        if "kubernetes" in name or ("kubernetes" in file_kinds and "terraform" not in file_kinds):
            return CategoryResult("Kubernetes examples", "medium", tuple(evidence))
        if "terraform" in file_kinds:
            return CategoryResult("Terraform examples or guides", "medium", tuple(evidence))
        if files:
            return CategoryResult("Kubernetes examples", "low", tuple(evidence))

    if "kubernetes" in file_kinds:
        evidence.append("dominant supported files are Kubernetes manifests")
        return CategoryResult("Kubernetes examples", "low", tuple(evidence))

    if files:
        evidence.append("supported infrastructure files detected")
        return CategoryResult("Infrastructure repository", "low", tuple(evidence))
    return CategoryResult("Unknown", "low", ("no supported infrastructure files detected",))


def _with_score_impact(
    scanner_results: Sequence[ScannerResult],
    impact: ScoreImpact,
) -> Iterable[ScannerResult]:
    for result in scanner_results:
        if result.applicability == "applicable":
            yield ScannerResult(
                result.repository,
                result.scanner,
                result.applicability,
                result.status,
                result.error,
                impact if result.status != "succeeded" else "none",
            )
        else:
            yield result


def _with_failed_score_impact(
    scanner_results: Sequence[ScannerResult],
    impact: ScoreImpact,
) -> Iterable[ScannerResult]:
    for result in scanner_results:
        if result.status in {"failed", "timed_out", "parse_failed"}:
            yield ScannerResult(
                result.repository,
                result.scanner,
                result.applicability,
                result.status,
                result.error,
                impact,
            )
        else:
            yield result


def _scanner_result_status(status: ScannerStatus) -> ScannerResultStatus:
    message = status.message.lower()
    if status.status == "success":
        return "succeeded"
    if "timed out" in message:
        return "timed_out"
    if "malformed json" in message or "no json" in message:
        return "parse_failed"
    return "failed"


def _empty_breakdown_row() -> dict[str, int]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total_actionable": 0,
        "affected_repositories": 0,
        "affected_files": 0,
    }


def _directory_for(file_path: str) -> str:
    path = Path(file_path)
    parent = path.parent.as_posix()
    return parent if parent and parent != "." else "."


def _file_kinds(supported_files: Sequence[Path]) -> set[str]:
    kinds: set[str] = set()
    for path in supported_files:
        name = path.name.lower()
        suffix = path.suffix.lower()
        text = path.as_posix().lower()
        if suffix in {".tf", ".tfvars"} or name.endswith(".tf.json"):
            kinds.add("terraform")
        elif name == "dockerfile" or name.startswith("dockerfile."):
            kinds.add("docker")
        elif suffix in {".yaml", ".yml", ".json"}:
            if any(marker in text for marker in ("k8s", "kubernetes", "helm", "charts")):
                kinds.add("kubernetes")
            else:
                kinds.add("yaml_or_json_iac")
        else:
            kinds.add("dependency")
    return kinds


def _looks_like_terraform_tooling(repository: str, repository_path: Path) -> bool:
    repo_name = repository.rsplit("/", 1)[-1]
    if any(marker in repo_name for marker in ("terragrunt", "terraform-cdk", "cdktf", "tflint")):
        return True
    package_json = repository_path / "package.json"
    if package_json.exists():
        text = _read_text(package_json).lower()
        if "cdktf" in text or "terraform-cdk" in text:
            return True
    return False


def _has_provider_markers(repository_path: Path) -> bool:
    go_mod = repository_path / "go.mod"
    if go_mod.exists():
        text = _read_text(go_mod).lower()
        if "terraform-plugin-sdk" in text or "terraform-plugin-framework" in text:
            return True
    return (repository_path / "internal" / "provider").exists()


def _has_kubernetes_controller_markers(
    repository: str,
    repository_path: Path,
    supported_files: Sequence[Path],
) -> bool:
    repo_name = repository.rsplit("/", 1)[-1]
    if any(marker in repo_name for marker in ("operator", "controller", "argo-cd", "argocd")):
        return True
    if (repository_path / "config" / "crd").exists() or (repository_path / "controllers").exists():
        return True
    paths = [path.as_posix().lower() for path in supported_files]
    crd_count = sum(
        1
        for path in paths
        if "crd" in Path(path).parts or "customresourcedefinition" in path
    )
    chart_count = sum(1 for path in paths if "charts/" in path or "helm/" in path)
    return crd_count >= 3 or chart_count >= 5


def _is_examples_repository(repository: str, supported_files: Sequence[Path]) -> bool:
    if any(
        word in repository
        for word in ("guide", "example", "learn", "sample", "demo", "tutorial")
    ):
        return True
    groups = Counter(classify_path_group(path.as_posix()) for path in supported_files)
    return bool(supported_files) and groups["examples"] >= max(2, len(supported_files) // 2)


def _looks_like_terraform_learning_repository(repo_name: str) -> bool:
    return repo_name.startswith("learn-terraform-")


def _looks_like_terraform_module(
    repository: str,
    repository_path: Path,
    supported_files: Sequence[Path],
) -> bool:
    repo_name = repository.rsplit("/", 1)[-1]
    root_tf = [
        path
        for path in supported_files
        if path.parent.as_posix() == "." and path.suffix == ".tf"
    ]
    module_tf = [
        path
        for path in supported_files
        if path.parts[:1] == ("modules",) and path.suffix == ".tf"
    ]
    if repository.startswith("terraform-aws-modules/terraform-aws-"):
        return bool(root_tf or module_tf)
    if repo_name.startswith(("terraform-aws-", "terraform-google-", "terraform-azurerm-")):
        return bool(root_tf)
    return bool(root_tf) and any(path.name in {"variables.tf", "outputs.tf"} for path in root_tf)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
