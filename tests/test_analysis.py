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
) -> RepositoryAnalysisResult:
    output_dir = Path(".driftbeacon-analysis") / repository
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
    assert data["schema_version"] == "1.0"
    assert data["metadata"]["repositories_requested"] == 3
    assert data["repository_results"][0]["audit"]["passed_checks"] == 2


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
