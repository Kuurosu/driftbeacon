from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path

import pytest

from driftbeacon import analysis
from driftbeacon.analysis import (
    AnalysisOptions,
    AnalysisTask,
    RepositoryAnalysisResult,
    analyse_repositories,
    analysis_summary_markdown,
    detect_supported_infrastructure_files,
    read_repository_list,
    repository_name_from_url,
    write_analysis_summaries,
)
from driftbeacon.analysis_metrics import DensityMetrics


def _result(
    *,
    index: int,
    repository: str,
    status: str = "success",
    health_score: int | None = 80,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    new: int = 0,
    resolved: int = 0,
    recurring: int = 0,
    has_baseline: bool = False,
    category: str = "Terraform module",
    supported_files: int = 2,
    error: str | None = None,
    score_state: str = "scored",
    coverage_state: str = "complete_coverage",
    score_reason: str = "All applicable scanners succeeded or were not applicable.",
    production_health_score: int | None = None,
    production_score_state: str = "not_scored_no_supported_files",
    production_coverage_state: str = "not_scored_no_supported_files",
    production_score_reason: str = "No production-supported files detected.",
    production_actionable: int = 0,
    production_critical: int = 0,
    production_high: int = 0,
    production_medium: int = 0,
    production_low: int = 0,
    density: DensityMetrics | None = None,
    top_directories: tuple[dict[str, int | str], ...] = (),
    top_files: tuple[dict[str, int | str], ...] = (),
) -> RepositoryAnalysisResult:
    output_dir = Path(".driftbeacon-analysis") / repository
    density = density or DensityMetrics(
        supported_files,
        0,
        0.0 if supported_files else None,
        0.0 if supported_files else None,
        None,
    )
    return RepositoryAnalysisResult(
        index=index,
        git_url=f"https://github.com/example/{repository}.git",
        repository=repository,
        status=status,
        health_score=health_score,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        new_findings=new,
        active_findings=critical + high + medium + low,
        supported_files=supported_files,
        output_dir=output_dir if status == "success" else None,
        report_path=output_dir / "report.md" if status == "success" else None,
        scan_path=output_dir / "current-scan.json" if status == "success" else None,
        clone_path=None,
        error=error,
        category=category,
        score_state=score_state,
        coverage_state=coverage_state,
        score_reason=score_reason,
        production_health_score=production_health_score,
        production_score_state=production_score_state,
        production_coverage_state=production_coverage_state,
        production_score_reason=production_score_reason,
        production_actionable_findings=production_actionable,
        production_critical_findings=production_critical,
        production_high_findings=production_high,
        production_medium_findings=production_medium,
        production_low_findings=production_low,
        total_findings=critical + high + medium + low,
        resolved_findings=resolved,
        recurring_findings=recurring,
        has_baseline=has_baseline,
        raw_scanner_results=critical + high + medium + low + 3,
        normalised_findings=critical + high + medium + low + 1,
        deduplicated_findings=critical + high + medium + low,
        duplicate_findings_removed=1,
        passed_checks=2,
        scanner_errors=0,
        checkov_status="success",
        trivy_status="skipped",
        density=density,
        top_directories=top_directories,
        top_files=top_files,
    )


def test_read_repository_list_ignores_blank_lines_and_comments(tmp_path: Path) -> None:
    repo_file = tmp_path / "repos.txt"
    repo_file.write_text(
        "\n# demo repos\nhttps://github.com/example/one.git\n\nhttps://github.com/example/two.git\n",
        encoding="utf-8",
    )

    assert read_repository_list(repo_file) == [
        "https://github.com/example/one.git",
        "https://github.com/example/two.git",
    ]


def test_repository_name_from_url_handles_common_git_shapes() -> None:
    assert repository_name_from_url("https://github.com/org/terraform-aws-vpc.git") == (
        "terraform-aws-vpc"
    )
    assert repository_name_from_url("git@github.com:org/platform-infra.git") == "platform-infra"


def test_legacy_category_helper_uses_evidence_based_classifier() -> None:
    assert analysis.detect_repository_category("gruntwork-io/terragrunt", []) == (
        "Terraform tooling"
    )


def test_detect_supported_infrastructure_files_skips_generated_dirs(tmp_path: Path) -> None:
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "main.tf").write_text("", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    generated = tmp_path / ".driftbeacon"
    generated.mkdir()
    (generated / "current-scan.json").write_text("{}", encoding="utf-8")

    paths = [path.as_posix() for path in detect_supported_infrastructure_files(tmp_path)]

    assert paths == ["Dockerfile", "terraform/main.tf"]


def test_write_analysis_summaries_writes_csv_markdown_and_json(tmp_path: Path) -> None:
    results = [
        _result(index=1, repository="healthy", health_score=95, high=1, new=1),
        _result(index=2, repository="risky", health_score=20, critical=2, high=3, new=5),
        _result(
            index=3,
            repository="broken",
            status="failed",
            health_score=None,
            error="git clone failed",
        ),
    ]

    csv_path, markdown_path, json_path = write_analysis_summaries(results, tmp_path)

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert [row["repository"] for row in rows] == ["healthy", "risky", "broken"]
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown.index("risky") < markdown.index("healthy")
    assert "| New |" not in markdown
    assert "Initial baseline" in markdown
    assert "Failed repositories" in markdown
    assert "git clone failed" in markdown
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "2.0"
    assert data["metadata"]["score_formula_version"] == "driftbeacon-health-v2"
    assert data["metadata"]["repositories_requested"] == 3
    assert "scanner_issues" in data
    assert data["repository_results"][0]["audit"]["passed_checks"] == 2


def test_summary_ranking_excludes_unscored_and_uses_tiebreakers(tmp_path: Path) -> None:
    alpha = _result(
        index=1,
        repository="alpha",
        health_score=60,
        high=4,
        density=DensityMetrics(10, 2, 20.0, 40.0, 2.0),
    )
    beta = _result(
        index=2,
        repository="beta",
        health_score=60,
        critical=1,
        density=DensityMetrics(10, 1, 10.0, 10.0, 1.0),
    )
    unscored = _result(
        index=3,
        repository="unscored",
        health_score=None,
        supported_files=0,
        score_state="not_scored_no_supported_files",
        coverage_state="not_scored_no_supported_files",
        score_reason="No supported files detected.",
    )

    markdown = analysis_summary_markdown([alpha, beta, unscored], tmp_path)

    assert "Average health score: 60" in markdown
    assert markdown.index("| 1 | beta |") < markdown.index("| 2 | alpha |")
    assert "| 3 | unscored |" not in markdown
    assert "## Unscored repositories" in markdown
    assert "| unscored | Not scored | No supported files detected. | 0 |" in markdown


def test_summary_includes_top_directory_and_file_tables(tmp_path: Path) -> None:
    result = _result(
        index=1,
        repository="repo",
        health_score=40,
        high=3,
        top_directories=({"path": "charts/app", "actionable_findings": 3},),
        top_files=({"path": "charts/app/values.yaml", "actionable_findings": 3},),
    )

    _, markdown_path, json_path = write_analysis_summaries([result], tmp_path)

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "## Top directories by actionable findings" in markdown
    assert "| repo | charts/app | 3 |" in markdown
    assert "## Top files by actionable findings" in markdown
    assert "| repo | charts/app/values.yaml | 3 |" in markdown
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["top_directories"][0]["path"] == "charts/app"
    assert data["top_files"][0]["path"] == "charts/app/values.yaml"


def test_summary_marks_partial_grades_provisional_in_markdown_and_json(tmp_path: Path) -> None:
    complete = _result(
        index=1,
        repository="complete",
        health_score=95,
        production_health_score=95,
        production_score_state="scored",
        production_coverage_state="complete_coverage",
        production_score_reason="Production Health calculated from production path findings.",
    )
    partial = _result(
        index=2,
        repository="partial",
        health_score=94,
        coverage_state="partial_coverage",
        production_health_score=94,
        production_score_state="scored",
        production_coverage_state="partial_coverage",
        production_score_reason=(
            "Production Health calculated from successful scanner output; coverage is incomplete."
        ),
    )
    unscored = _result(
        index=3,
        repository="unscored",
        health_score=None,
        supported_files=0,
        score_state="not_scored_no_supported_files",
        coverage_state="not_scored_no_supported_files",
        score_reason="No supported files detected.",
        production_health_score=None,
    )

    csv_path, markdown_path, json_path = write_analysis_summaries(
        [complete, partial, unscored],
        tmp_path,
    )

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "| 1 | partial | Terraform module | 94 | A* | 94 | A* | Partial |" in markdown
    assert "| 2 | complete | Terraform module | 95 | A | 95 | A | Complete |" in markdown
    assert "N/A*" not in markdown
    data = json.loads(json_path.read_text(encoding="utf-8"))
    partial_json = next(
        result for result in data["repository_results"] if result["repository"] == "partial"
    )
    assert partial_json["grade"] == "A"
    assert partial_json["grade_provisional"] is True
    assert partial_json["production_grade"] == "A"
    assert partial_json["production_grade_provisional"] is True
    rows = {row["repository"]: row for row in csv.DictReader(csv_path.open(encoding="utf-8"))}
    assert rows["partial"]["grade"] == "A"
    assert rows["partial"]["grade_provisional"] == "true"
    assert rows["partial"]["production_grade_provisional"] == "true"


def test_analysis_summary_uses_relative_report_links(tmp_path: Path) -> None:
    result = _result(index=1, repository="org--repo", health_score=80, high=1)
    absolute_report = tmp_path / "org--repo" / "report.md"
    result = replace(
        result,
        output_dir=tmp_path / "org--repo",
        report_path=absolute_report,
        scan_path=tmp_path / "org--repo" / "current-scan.json",
    )

    markdown = analysis_summary_markdown([result], tmp_path)

    assert "[View report](org--repo/report.md)" in markdown
    assert str(tmp_path) not in markdown
    assert "/Users/" not in markdown
    assert "/home/" not in markdown


def test_comparison_summary_adds_change_columns_only_with_baseline(tmp_path: Path) -> None:
    markdown = analysis_summary_markdown(
        [
            _result(
                index=1,
                repository="service",
                health_score=72,
                high=1,
                new=1,
                resolved=1,
                recurring=2,
                has_baseline=True,
            )
        ],
        tmp_path,
    )

    assert "Comparison scan" in markdown
    assert "| New | Resolved | Recurring |" in markdown
    assert "| 1 | service |" in markdown


def test_repository_output_names_preserve_owner_for_colliding_repo_names() -> None:
    tasks = analysis._build_tasks(
        [
            "https://github.com/terraform-aws-modules/terraform-aws-vpc.git",
            "https://github.com/cloudposse/terraform-aws-vpc.git",
            "https://github.com/cloudposse/terraform-aws-vpc.git",
        ]
    )

    assert [task.output_name for task in tasks] == [
        "terraform-aws-modules--terraform-aws-vpc",
        "cloudposse--terraform-aws-vpc",
        "cloudposse--terraform-aws-vpc--2",
    ]


def test_analyse_repositories_continues_when_one_repository_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_analyse_repository(
        task: AnalysisTask,
        _options: AnalysisOptions,
        _analysis_output_dir: Path,
        progress: analysis.ProgressWriter,
    ) -> RepositoryAnalysisResult:
        progress(f"[{task.index}/{task.total}] Scanning fake...")
        if "bad" in task.git_url:
            return _result(
                index=task.index,
                repository="bad",
                status="failed",
                health_score=None,
                error="clone failed",
            )
        return _result(index=task.index, repository="good", health_score=70, critical=1, high=2)

    monkeypatch.setattr(analysis, "analyse_repository", fake_analyse_repository)
    messages: list[str] = []

    run = analyse_repositories(
        ["https://github.com/example/good.git", "https://github.com/example/bad.git"],
        AnalysisOptions(output_dir=tmp_path / "analysis", workers=2),
        progress=messages.append,
    )

    assert len(run.succeeded) == 1
    assert len(run.failed) == 1
    assert run.csv_path.exists()
    assert run.markdown_path.exists()
    assert "Failed: 1" in run.final_summary_lines()
    assert any("failed" in message for message in messages)
