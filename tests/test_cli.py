from __future__ import annotations

from driftbeacon.cli import build_parser


def test_analyse_repo_parser_accepts_git_url_and_options() -> None:
    args = build_parser().parse_args(
        [
            "analyse-repo",
            "https://github.com/example/infrastructure.git",
            "--workers",
            "2",
            "--keep",
        ]
    )

    assert args.command == "analyse-repo"
    assert args.git_url == "https://github.com/example/infrastructure.git"
    assert args.workers == 2
    assert args.keep is True


def test_analyse_parser_accepts_repository_file_and_worker_count() -> None:
    args = build_parser().parse_args(["analyse", "repos.txt", "--workers", "8"])

    assert args.command == "analyse"
    assert str(args.repository_file) == "repos.txt"
    assert args.workers == 8
