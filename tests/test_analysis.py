from __future__ import annotations

import csv
from pathlib import Path

import pytest

from driftbeacon import analysis
from driftbeacon.analysis import (
    AnalysisOptions,
    AnalysisTask,
    RepositoryAnalysisResult,
    analyse_repositories,
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
    new: int = 0,
    error: str | None = None,
) -> RepositoryAnalysisResult:
    return RepositoryAnalysisResult(
        index=index,
        git_url=f"https://github.com/example/{repository}.git",
        repository=repository,
        status=status,
        health_score=health_score,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        new_findings=new,
        active_findings=critical + high + medium,
        supported_files=2,
        output_dir=Path(".driftbeacon-analysis") / repository if status == "success" else None,
        report_path=Path(".driftbeacon-analysis") / repository / "report.md"
        if status == "success"
        else None,
        scan_path=Path(".driftbeacon-analysis") / repository / "current-scan.json"
        if status == "success"
        else None,
        clone_path=None,
        error=error,
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


def test_write_analysis_summaries_writes_csv_and_ranked_markdown(tmp_path: Path) -> None:
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

    csv_path, markdown_path = write_analysis_summaries(results, tmp_path)

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert [row["repository"] for row in rows] == ["healthy", "risky", "broken"]
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown.index("risky") < markdown.index("healthy")
    assert "Failed repositories" in markdown
    assert "git clone failed" in markdown


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
