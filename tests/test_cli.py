from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from driftbeacon.cli import build_parser, main
from driftbeacon.web_storage import FeedbackRecord, SQLiteScanStore


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


def test_web_cleanup_parser_accepts_output_dir() -> None:
    args = build_parser().parse_args(
        [
            "web-cleanup",
            "--output-dir",
            ".driftbeacon-web-test",
        ]
    )

    assert args.command == "web-cleanup"
    assert args.output_dir == Path(".driftbeacon-web-test")


def test_worker_parser_accepts_once_and_poll_options() -> None:
    args = build_parser().parse_args(
        [
            "worker",
            "--output-dir",
            ".driftbeacon-web-test",
            "--worker-id",
            "worker-a",
            "--poll-interval",
            "0.5",
            "--once",
        ]
    )

    assert args.command == "worker"
    assert args.output_dir == Path(".driftbeacon-web-test")
    assert args.worker_id == "worker-a"
    assert args.poll_interval == 0.5
    assert args.once is True


def test_beta_admin_parsers_accept_operational_options() -> None:
    status = build_parser().parse_args(["beta-status", "--output-dir", ".driftbeacon-web-test"])
    recent = build_parser().parse_args(["beta-recent-scans", "--limit", "5"])
    failed = build_parser().parse_args(["beta-failed-scans", "--limit", "7"])
    pause = build_parser().parse_args(["beta-pause-instructions"])
    export = build_parser().parse_args(
        ["feedback-export", "--output-dir", ".driftbeacon-web-test", "--output", "feedback.csv"]
    )

    assert status.command == "beta-status"
    assert status.output_dir == Path(".driftbeacon-web-test")
    assert recent.command == "beta-recent-scans"
    assert recent.limit == 5
    assert failed.command == "beta-failed-scans"
    assert failed.limit == 7
    assert pause.command == "beta-pause-instructions"
    assert export.command == "feedback-export"
    assert export.output == Path("feedback.csv")


def test_feedback_export_command_writes_csv(tmp_path: Path) -> None:
    output_dir = tmp_path / "web"
    store = SQLiteScanStore(output_dir / "web.sqlite3")
    store.save_feedback(
        FeedbackRecord(
            feedback_id="abcdef123456",
            created_at=datetime.now(UTC),
            scan_id=None,
            source_hash="hash-only",
            helpfulness="yes",
            changed_priority="maybe",
            private_monitoring_interest=True,
            comment="useful",
            email="tester@example.com",
            consent_to_contact=True,
        )
    )
    output = tmp_path / "feedback.csv"

    exit_code = main(
        [
            "feedback-export",
            "--output-dir",
            str(output_dir),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert "tester@example.com" in text
    assert "useful" in text
