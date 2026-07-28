"""Command-line interface for DriftBeacon."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .analysis import AnalysisOptions, analyse_repositories, read_repository_list
from .comparison import compare_scans
from .config import Config, ConfigError, load_config
from .models import SEVERITY_RANK, ScanResult
from .prioritise import prioritise_findings
from .reporting import generate_job_summary, generate_report
from .scan import run_scan
from .scanners import ScannerExecution
from .slack import send_slack_report_from_path
from .storage import LocalStorage, StorageError
from .web import WebConfig, cleanup_web_storage, run_web_server
from .web_storage import SQLiteScanStore
from .worker import WebScanWorker, WorkerConfig


def main(argv: Sequence[str] | None = None) -> int:
    """Run the DriftBeacon CLI."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except (ConfigError, StorageError, ValueError) as exc:
        print(f"DriftBeacon error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("DriftBeacon interrupted.", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftbeacon",
        description=(
            "Scan infrastructure repositories with Checkov and Trivy, compare findings with "
            "the previous run, and generate Markdown or Slack-ready operational reports."
        ),
        epilog=(
            "Examples:\n"
            "  driftbeacon run --repository-path . --output-dir .driftbeacon --no-slack\n"
            "  driftbeacon web --port 8080\n"
            "  driftbeacon worker\n"
            "  driftbeacon analyse-repo https://github.com/org/infrastructure.git\n"
            "  driftbeacon analyse repos.txt --workers 4\n"
            "  driftbeacon run --checkov-json examples/sample-checkov.json "
            "--trivy-json examples/sample-trivy.json --no-slack\n"
            "  driftbeacon send-slack --report-file .driftbeacon/report.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="driftbeacon 0.1.0")
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="{scan,report,compare,send-slack,run,web,worker,web-cleanup,beta-status,beta-recent-scans,beta-failed-scans,beta-pause-instructions,feedback-export,analyse-repo,analyse}",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan", help="Run scanners and save normalized finding JSON."
    )
    _add_config_args(scan_parser)
    _add_scanner_input_args(scan_parser)
    scan_parser.add_argument("--timeout", type=int, default=300, help="Scanner timeout in seconds.")

    report_parser = subparsers.add_parser(
        "report", help="Generate a Markdown report from scan JSON."
    )
    report_parser.add_argument("--scan-file", required=True, type=Path)
    report_parser.add_argument("--previous-scan", type=Path)
    report_parser.add_argument("--output-file", type=Path)
    report_parser.add_argument("--config", type=Path)
    report_parser.add_argument("--top-findings", type=int, default=None)

    compare_parser = subparsers.add_parser(
        "compare", help="Compare current and previous DriftBeacon scan JSON."
    )
    compare_parser.add_argument("--current-scan", required=True, type=Path)
    compare_parser.add_argument("--previous-scan", type=Path)
    compare_parser.add_argument("--output-file", type=Path)

    slack_parser = subparsers.add_parser(
        "send-slack", help="Send an existing repository or portfolio report to Slack."
    )
    slack_parser.add_argument("--report-file", required=True, type=Path)
    slack_parser.add_argument("--slack-webhook-env", default="SLACK_WEBHOOK_URL")

    run_parser = subparsers.add_parser(
        "run", help="Run scan, compare, report, store, and optional Slack delivery."
    )
    _add_config_args(run_parser)
    _add_scanner_input_args(run_parser)
    run_parser.add_argument("--previous-scan", type=Path)
    run_parser.add_argument("--timeout", type=int, default=300, help="Scanner timeout in seconds.")
    run_parser.add_argument("--github-summary-file", type=Path, default=_github_summary_path())

    web_parser = subparsers.add_parser(
        "web",
        help="Run the public web scan MVP locally.",
    )
    web_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    web_parser.add_argument("--port", type=int, default=8080, help="Port to bind.")
    web_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".driftbeacon"),
        help="Directory for web scan reports and state.",
    )
    web_parser.add_argument(
        "--max-concurrent-scans",
        type=int,
        default=2,
        help="Compatibility setting for web limits; scan execution is handled by workers.",
    )
    web_parser.add_argument(
        "--scanner-timeout",
        type=int,
        default=300,
        help="Scanner timeout in seconds.",
    )
    web_parser.add_argument(
        "--clone-timeout",
        type=int,
        default=120,
        help="Git clone timeout in seconds.",
    )

    cleanup_parser = subparsers.add_parser(
        "web-cleanup",
        help="Expire old public web reports and clean abandoned web work directories.",
    )
    cleanup_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".driftbeacon"),
        help="Base directory for web SQLite, reports and work state.",
    )

    worker_parser = subparsers.add_parser(
        "worker",
        help="Claim and process queued public web scan jobs.",
    )
    worker_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".driftbeacon"),
        help="Base directory for web SQLite, reports and worker state.",
    )
    worker_parser.add_argument(
        "--poll-interval",
        type=float,
        default=None,
        help="Seconds to wait between queue polls.",
    )
    worker_parser.add_argument(
        "--worker-id",
        default=None,
        help="Stable identifier for this worker process.",
    )
    worker_parser.add_argument(
        "--once",
        action="store_true",
        help="Claim and process at most one queued scan, then exit.",
    )

    beta_status_parser = subparsers.add_parser(
        "beta-status",
        help="Show local controlled-beta operational status.",
    )
    beta_status_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".driftbeacon"),
        help="Base directory for web SQLite, reports and worker state.",
    )

    beta_recent_parser = subparsers.add_parser(
        "beta-recent-scans",
        help="List recent public beta scan records.",
    )
    beta_recent_parser.add_argument("--output-dir", type=Path, default=Path(".driftbeacon"))
    beta_recent_parser.add_argument("--limit", type=int, default=20)

    beta_failed_parser = subparsers.add_parser(
        "beta-failed-scans",
        help="List recent failed beta scans with safe error messages.",
    )
    beta_failed_parser.add_argument("--output-dir", type=Path, default=Path(".driftbeacon"))
    beta_failed_parser.add_argument("--limit", type=int, default=20)

    beta_pause_parser = subparsers.add_parser(
        "beta-pause-instructions",
        help="Print how to pause and resume public beta submissions.",
    )
    beta_pause_parser.add_argument("--output-dir", type=Path, default=Path(".driftbeacon"))

    feedback_export_parser = subparsers.add_parser(
        "feedback-export",
        help="Export locally stored beta feedback to CSV.",
    )
    feedback_export_parser.add_argument("--output-dir", type=Path, default=Path(".driftbeacon"))
    feedback_export_parser.add_argument("--output", required=True, type=Path)

    analyse_repo_parser = subparsers.add_parser(
        "analyse-repo",
        help="Clone and analyse one public Git repository.",
    )
    analyse_repo_parser.add_argument("git_url", help="Public Git repository URL to clone.")
    _add_analysis_args(analyse_repo_parser, default_workers=1)

    analyse_parser = subparsers.add_parser(
        "analyse",
        help="Clone and analyse repository URLs listed in a text file.",
    )
    analyse_parser.add_argument(
        "repository_file", type=Path, help="File with one Git URL per line."
    )
    _add_analysis_args(analyse_parser, default_workers=4)

    return parser


def _dispatch(args: argparse.Namespace) -> int:
    command = str(args.command)
    if command == "scan":
        config = _config_from_args(args)
        scan, _executions = execute_scan(config, args, compare_with_previous=False)
        path = LocalStorage(config.output_dir).save_current_scan(scan)
        print(f"Saved scan result to {path}")
        return _threshold_exit_code(config, scan)
    if command == "report":
        return command_report(args)
    if command == "compare":
        return command_compare(args)
    if command == "send-slack":
        return command_send_slack(args)
    if command == "run":
        return command_run(args)
    if command == "web":
        return command_web(args)
    if command == "worker":
        return command_worker(args)
    if command == "web-cleanup":
        return command_web_cleanup(args)
    if command == "beta-status":
        return command_beta_status(args)
    if command == "beta-recent-scans":
        return command_beta_recent_scans(args)
    if command == "beta-failed-scans":
        return command_beta_failed_scans(args)
    if command == "beta-pause-instructions":
        return command_beta_pause_instructions(args)
    if command == "feedback-export":
        return command_feedback_export(args)
    if command == "analyse-repo":
        return command_analyse_repo(args)
    if command == "analyse":
        return command_analyse(args)
    raise ValueError(f"unknown command: {command}")


def command_run(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    storage = LocalStorage(config.output_dir)
    previous = storage.load_previous_scan(args.previous_scan)
    scan, _executions = execute_scan(config, args, compare_with_previous=False)
    comparison = compare_scans(scan, previous)
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
    scan_path = storage.save_current_scan(scan)
    comparison_path = storage.save_comparison(comparison.to_dict())
    report_path = storage.save_report(report)
    print(f"Saved scan result to {scan_path}")
    print(f"Saved comparison summary to {comparison_path}")
    print(f"Saved report to {report_path}")

    if args.github_summary_file is not None:
        _append_github_summary(Path(args.github_summary_file), generate_job_summary(report))

    slack_result = send_slack_report_from_path(
        report_path,
        webhook_env_var=config.slack_webhook_environment_variable,
        enabled=config.slack_enabled,
    )
    print(slack_result.message)
    return _threshold_exit_code(config, scan)


def command_report(args: argparse.Namespace) -> int:
    scan = _load_scan(args.scan_file)
    previous = _load_scan(args.previous_scan) if args.previous_scan else None
    comparison = compare_scans(scan, previous)
    top_limit = args.top_findings or 3
    production_patterns: tuple[str, ...] = ("production", "prod", "live")
    if args.config:
        config = load_config(
            repository_path=Path("."),
            config_path=args.config,
            no_slack=True,
        )
        production_patterns = config.production_patterns
        top_limit = args.top_findings or config.top_findings
    report = generate_report(
        scan,
        comparison,
        production_patterns=production_patterns,
        top_limit=top_limit,
    )
    if args.output_file:
        _write_text(Path(args.output_file), report)
        print(f"Saved report to {args.output_file}")
    else:
        print(report)
    return 0


def command_compare(args: argparse.Namespace) -> int:
    current = _load_scan(args.current_scan)
    previous = _load_scan(args.previous_scan) if args.previous_scan else None
    comparison = compare_scans(current, previous)
    output = json.dumps(comparison.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.output_file:
        _write_text(Path(args.output_file), output)
        print(f"Saved comparison to {args.output_file}")
    else:
        print(output)
    return 0


def command_send_slack(args: argparse.Namespace) -> int:
    result = send_slack_report_from_path(
        Path(args.report_file),
        webhook_env_var=args.slack_webhook_env,
    )
    print(result.message)
    return 0 if result.sent or result.message.startswith("Slack skipped") else 1


def command_web(args: argparse.Namespace) -> int:
    config = _web_config_from_args(args)
    run_web_server(
        str(args.host),
        int(args.port),
        config,
    )
    return 0


def command_web_cleanup(args: argparse.Namespace) -> int:
    result = cleanup_web_storage(_web_config_from_args(args))
    print("DriftBeacon web cleanup complete.")
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


def command_worker(args: argparse.Namespace) -> int:
    worker = WebScanWorker(
        _web_config_from_args(args),
        _worker_config_from_args(args),
    )
    if bool(args.once):
        processed = worker.process_once()
        print("Processed one queued scan." if processed else "No queued scans.")
        return 0
    worker.run_forever()
    return 0


def command_beta_status(args: argparse.Namespace) -> int:
    config = _web_config_from_args(args)
    store = SQLiteScanStore(config.database_path)
    today = datetime.now(UTC).date().isoformat()
    usage = store.daily_submission_counts(today)
    events = store.event_counts_on(today)
    oldest = store.oldest_retained_report()
    worker_activity = store.worker_last_activity()
    print("DriftBeacon beta status")
    print(f"Accepting scans: {'yes' if config.beta.accepting_scans else 'no'}")
    print(f"Access mode: {config.beta.access_mode}")
    print(f"Queued scans: {store.count_queued_scans()}")
    print(f"Running scans: {store.count_running_scans()}")
    print(f"Completed today: {store.count_completed_scans_on(today)}")
    print(f"Failed today: {store.count_failed_scans_on(today)}")
    print(f"Accepted submissions today: {usage['accepted']}")
    print(f"Rejected today: {usage['rejected']}")
    print(f"Feedback submissions today: {store.count_feedback_on(today)}")
    print(
        "Private monitoring interest today: "
        f"{store.count_private_monitoring_interest_on(today)}"
    )
    print(f"Report views today: {events.get('report_viewed', 0)}")
    print(f"Sample report views today: {events.get('sample_report_viewed', 0)}")
    print(f"Disk usage: {_format_cli_bytes(_disk_usage(config.output_dir))}")
    print(f"Oldest retained report: {_age_text(oldest)}")
    print(f"Worker last activity: {_age_text(worker_activity)}")
    return 0


def command_beta_recent_scans(args: argparse.Namespace) -> int:
    config = _web_config_from_args(args)
    store = SQLiteScanStore(config.database_path)
    for state in store.recent_scans(limit=int(args.limit)):
        print(
            f"{state.created_at.isoformat()} {state.scan_id} {state.status} "
            f"{state.repository_label}"
        )
    return 0


def command_beta_failed_scans(args: argparse.Namespace) -> int:
    config = _web_config_from_args(args)
    store = SQLiteScanStore(config.database_path)
    for state in store.failed_scans(limit=int(args.limit)):
        message = state.safe_error_message or state.message
        timestamp = (
            state.completed_at.isoformat()
            if state.completed_at
            else state.updated_at.isoformat()
        )
        print(
            f"{timestamp} {state.scan_id} {state.repository_label} {message}"
        )
    return 0


def command_beta_pause_instructions(args: argparse.Namespace) -> int:
    _ = _web_config_from_args(args)
    print("Pause new public beta scans:")
    print("  set DRIFTBEACON_BETA_ACCEPTING_SCANS=false")
    print("  restart the web process")
    print("Resume public beta scans:")
    print("  set DRIFTBEACON_BETA_ACCEPTING_SCANS=true")
    print("  restart the web process")
    print("Existing completed report URLs remain accessible while submissions are paused.")
    return 0


def command_feedback_export(args: argparse.Namespace) -> int:
    config = _web_config_from_args(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.is_symlink():
        raise ValueError(f"refusing to write through symlink: {output}")
    store = SQLiteScanStore(config.database_path)
    rows = store.list_feedback(limit=500)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "feedback_id",
                "created_at",
                "scan_id",
                "helpfulness",
                "changed_priority",
                "difficult_to_understand",
                "private_monitoring_interest",
                "comment",
                "email",
                "consent_to_contact",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "feedback_id": row.feedback_id,
                    "created_at": row.created_at.isoformat(),
                    "scan_id": row.scan_id or "",
                    "helpfulness": row.helpfulness,
                    "changed_priority": row.changed_priority,
                    "difficult_to_understand": row.difficult_to_understand,
                    "private_monitoring_interest": row.private_monitoring_interest,
                    "comment": row.comment,
                    "email": row.email or "",
                    "consent_to_contact": row.consent_to_contact,
                }
            )
    print(f"Exported {len(rows)} feedback submissions to {output}")
    return 0


def _web_config_from_args(args: argparse.Namespace) -> WebConfig:
    base = WebConfig.from_environment()
    output_dir = Path(args.output_dir)
    return WebConfig(
        output_dir=output_dir,
        database_path=Path(
            os.environ.get("DRIFTBEACON_WEB_DATABASE", str(output_dir / "web.sqlite3"))
        ),
        report_dir=Path(
            os.environ.get("DRIFTBEACON_WEB_REPORT_DIR", str(output_dir / "reports"))
        ),
        working_dir=Path(
            os.environ.get(
                "DRIFTBEACON_SCAN_WORK_DIR",
                os.environ.get("DRIFTBEACON_WEB_WORK_DIR", str(output_dir / "work")),
            )
        ),
        max_concurrent_scans=int(getattr(args, "max_concurrent_scans", base.max_concurrent_scans)),
        max_queued_scans=base.max_queued_scans,
        max_scan_seconds=base.max_scan_seconds,
        scanner_timeout_seconds=int(getattr(args, "scanner_timeout", base.scanner_timeout_seconds)),
        clone_timeout_seconds=int(getattr(args, "clone_timeout", base.clone_timeout_seconds)),
        retention_days=base.retention_days,
        max_repository_files=base.max_repository_files,
        max_repository_bytes=base.max_repository_bytes,
        top_findings=base.top_findings,
        beta=base.beta,
    ).validate()


def _worker_config_from_args(args: argparse.Namespace) -> WorkerConfig:
    base = WorkerConfig.from_environment()
    return WorkerConfig(
        worker_id=str(getattr(args, "worker_id", None) or base.worker_id),
        poll_interval_seconds=float(
            getattr(args, "poll_interval", None) or base.poll_interval_seconds
        ),
        stale_seconds=base.stale_seconds,
    ).validate()


def command_analyse_repo(args: argparse.Namespace) -> int:
    return _run_repository_analysis([str(args.git_url)], args)


def command_analyse(args: argparse.Namespace) -> int:
    return _run_repository_analysis(read_repository_list(Path(args.repository_file)), args)


def _run_repository_analysis(git_urls: Sequence[str], args: argparse.Namespace) -> int:
    result = analyse_repositories(
        git_urls,
        AnalysisOptions(
            output_dir=Path(args.output_dir),
            workers=int(args.workers),
            keep=bool(args.keep),
            scanner_timeout_seconds=int(args.timeout),
            clone_timeout_seconds=int(args.clone_timeout),
            exclude_path_groups=tuple(getattr(args, "exclude_path_group", []) or ()),
        ),
    )
    print(f"Saved analysis summary CSV to {result.csv_path}")
    print(f"Saved analysis summary Markdown to {result.markdown_path}")
    print(f"Saved analysis summary JSON to {result.json_path}")
    for line in result.final_summary_lines():
        print(line)
    return 0


def execute_scan(
    config: Config,
    args: argparse.Namespace,
    *,
    compare_with_previous: bool = False,
) -> tuple[ScanResult, list[ScannerExecution]]:
    """Run or load scanner outputs and return a scan result."""

    return run_scan(
        config,
        timeout_seconds=int(args.timeout),
        checkov_json=Path(args.checkov_json) if getattr(args, "checkov_json", None) else None,
        trivy_json=Path(args.trivy_json) if getattr(args, "trivy_json", None) else None,
        compare_with_previous=compare_with_previous,
    )


def _config_from_args(args: argparse.Namespace) -> Config:
    return load_config(
        repository_path=getattr(args, "repository_path", None),
        output_dir=getattr(args, "output_dir", None),
        config_path=getattr(args, "config", None),
        no_slack=bool(getattr(args, "no_slack", False)),
        slack_webhook_env=getattr(args, "slack_webhook_env", None),
    )


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-path", type=Path, default=None, help="Repository to scan.")
    parser.add_argument(
        "--output-dir", type=Path, default=None, help="Directory for generated output."
    )
    parser.add_argument("--config", type=Path, default=None, help="Optional .driftbeacon.yml path.")
    parser.add_argument(
        "--no-slack", action="store_true", help="Skip Slack delivery even if configured."
    )
    parser.add_argument(
        "--slack-webhook-env",
        default=None,
        help="Environment variable containing Slack webhook URL.",
    )


def _add_scanner_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--checkov-json", type=Path, help="Load Checkov JSON instead of running checkov."
    )
    parser.add_argument("--trivy-json", type=Path, help="Load Trivy JSON instead of running trivy.")


def _add_analysis_args(parser: argparse.ArgumentParser, *, default_workers: int) -> None:
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".driftbeacon-analysis"),
        help="Directory for per-repository reports and analysis summaries.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help="Number of repositories to analyse in parallel.",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep temporary clones after analysis for debugging.",
    )
    parser.add_argument("--timeout", type=int, default=300, help="Scanner timeout in seconds.")
    parser.add_argument(
        "--clone-timeout",
        type=int,
        default=300,
        help="Git clone timeout in seconds per repository.",
    )
    parser.add_argument(
        "--exclude-path-group",
        action="append",
        choices=[
            "examples",
            "tests",
            "fixtures",
            "generated",
            "vendor",
            "third_party",
            "docs",
            "charts",
        ],
        default=[],
        help="Exclude a directory group from health scoring while preserving audit counts.",
    )


def _threshold_exit_code(config: Config, scan: ScanResult) -> int:
    if config.fail_on is None:
        return 0
    threshold_rank = SEVERITY_RANK[config.fail_on]
    exceeds_threshold = any(
        finding.status != "resolved" and SEVERITY_RANK[finding.severity] >= threshold_rank
        for finding in scan.findings
    )
    if exceeds_threshold:
        print(f"Failing because findings meet or exceed configured threshold: {config.fail_on}")
        return 2
    return 0


def _load_scan(path: Path | None) -> ScanResult:
    if path is None:
        raise ValueError("scan path is required")
    if path.is_symlink():
        raise ValueError(f"refusing to read symlinked scan file: {path}")
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"scan file must contain a JSON object: {path}")
    return ScanResult.from_dict(data)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing to write through symlink: {path}")
    path.write_text(text, encoding="utf-8")


def _append_github_summary(path: Path, summary: str) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(summary)
            if not summary.endswith("\n"):
                handle.write("\n")
    except OSError as exc:
        print(f"Could not write GitHub job summary: {exc}", file=sys.stderr)


def _github_summary_path() -> Path | None:
    value = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(value) if value else None


def _disk_usage(path: Path) -> int:
    root = path.expanduser()
    if not root.exists():
        return 0
    total = 0
    for item in root.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def _format_cli_bytes(value: int) -> str:
    if value >= 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024 * 1024):.1f} GB"
    if value >= 1024 * 1024:
        return f"{value / (1024 * 1024):.1f} MB"
    if value >= 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value} bytes"


def _age_text(value: datetime | None) -> str:
    if value is None:
        return "none"
    seconds = max(0, int((datetime.now(UTC) - value.astimezone(UTC)).total_seconds()))
    if seconds < 60:
        return f"{seconds} seconds ago"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} minutes ago"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} hours ago"
    days, hours = divmod(hours, 24)
    return f"{days} days ago"
