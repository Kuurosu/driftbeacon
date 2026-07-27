from __future__ import annotations

from pathlib import Path

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


def test_web_parser_accepts_local_server_options() -> None:
    args = build_parser().parse_args(
        [
            "web",
            "--host",
            "127.0.0.1",
            "--port",
            "9090",
            "--output-dir",
            ".driftbeacon-web-test",
            "--max-concurrent-scans",
            "1",
        ]
    )

    assert args.command == "web"
    assert args.host == "127.0.0.1"
    assert args.port == 9090
    assert args.output_dir == Path(".driftbeacon-web-test")
    assert args.max_concurrent_scans == 1
