"""Command-line interface for DriftBeacon."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .comparison import compare_scans
from .config import Config, ConfigError, load_config
from .models import SEVERITY_RANK, ScannerStatus, ScanResult, active_findings
from .prioritise import prioritise_findings
from .reporting import generate_job_summary, generate_report
from .scanners import CheckovScanner, ScannerExecution, TrivyScanner
from .scoring import calculate_health_score
from .slack import send_slack_report
from .storage import LocalStorage, StorageError


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
            "  driftbeacon run --checkov-json examples/sample-checkov.json "
            "--trivy-json examples/sample-trivy.json --no-slack\n"
            "  driftbeacon send-slack --report-file .driftbeacon/report.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="driftbeacon 0.1.0")
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="{scan,report,compare,send-slack,run}",
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
        "send-slack", help="Send an existing Markdown report to Slack."
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

    slack_result = send_slack_report(
        report,
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
    report = Path(args.report_file).read_text(encoding="utf-8")
    result = send_slack_report(report, webhook_env_var=args.slack_webhook_env)
    print(result.message)
    return 0 if result.sent or result.message.startswith("Slack skipped") else 1


def execute_scan(
    config: Config,
    args: argparse.Namespace,
    *,
    compare_with_previous: bool = False,
) -> tuple[ScanResult, list[ScannerExecution]]:
    """Run or load scanner outputs and return a scan result."""

    started_at = datetime.now(UTC)
    executions: list[ScannerExecution] = []

    if config.checkov_enabled:
        checkov = CheckovScanner()
        if getattr(args, "checkov_json", None):
            executions.append(checkov.from_file(Path(args.checkov_json), config.repository_path))
        else:
            executions.append(
                checkov.run(config.repository_path, timeout_seconds=int(args.timeout))
            )
    else:
        executions.append(
            ScannerExecution(
                "checkov",
                ScannerStatus("checkov", "skipped", "disabled by configuration"),
                [],
            )
        )

    if config.trivy_enabled:
        trivy = TrivyScanner(secret_scanning=config.trivy_secret_scanning)
        if getattr(args, "trivy_json", None):
            executions.append(trivy.from_file(Path(args.trivy_json), config.repository_path))
        else:
            executions.append(trivy.run(config.repository_path, timeout_seconds=int(args.timeout)))
    else:
        executions.append(
            ScannerExecution(
                "trivy",
                ScannerStatus("trivy", "skipped", "disabled by configuration"),
                [],
            )
        )

    completed_at = datetime.now(UTC)
    findings = [finding for execution in executions for finding in execution.findings]
    for finding in findings:
        finding.first_seen = finding.first_seen or started_at
        finding.last_seen = completed_at
    repository, branch, commit_sha = detect_repository_metadata(config.repository_path)
    scanner_statuses = {execution.scanner: execution.status for execution in executions}
    scan = ScanResult(
        repository=repository,
        branch=branch,
        commit_sha=commit_sha,
        started_at=started_at,
        completed_at=completed_at,
        scanner_statuses=scanner_statuses,
        findings=findings,
        health_score=calculate_health_score(findings),
        summary={
            "active_findings": len(active_findings(findings)),
            "new_findings": len(findings),
            "recurring_findings": 0,
            "resolved_findings": 0,
            "severity_changes": 0,
        },
    )
    if compare_with_previous:
        compare_scans(scan, None)
    return scan, executions


def detect_repository_metadata(repository_path: Path) -> tuple[str, str, str]:
    """Detect repository name, branch, and commit SHA from GitHub Actions or Git."""

    repository = os.environ.get("GITHUB_REPOSITORY") or _git_remote_repository(repository_path)
    branch = os.environ.get("GITHUB_REF_NAME") or _git_output(
        repository_path, ["git", "rev-parse", "--abbrev-ref", "HEAD"]
    )
    commit_sha = os.environ.get("GITHUB_SHA") or _git_output(
        repository_path, ["git", "rev-parse", "HEAD"]
    )
    return (
        repository or repository_path.name,
        branch or "unknown",
        commit_sha or "unknown",
    )


def _git_remote_repository(repository_path: Path) -> str | None:
    remote = _git_output(repository_path, ["git", "config", "--get", "remote.origin.url"])
    if not remote:
        return None
    if remote.endswith(".git"):
        remote = remote[:-4]
    if remote.startswith("git@github.com:"):
        return remote.removeprefix("git@github.com:")
    if "github.com/" in remote:
        return remote.split("github.com/", 1)[1]
    return remote


def _git_output(repository_path: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            args,
            cwd=repository_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    output = completed.stdout.strip()
    return output or None


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
