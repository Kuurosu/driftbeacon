"""Slack webhook integration."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analysis_metrics import source_label
from .models import ScanResult
from .prioritise import prioritise_findings
from .redaction import escape_slack_text, redact_secrets
from .reporting import prioritised_finding_details
from .scoring import actionable_active_findings


@dataclass(frozen=True, slots=True)
class SlackResult:
    """Result of a Slack send attempt."""

    sent: bool
    message: str


@dataclass(frozen=True, slots=True)
class SlackPayloadBuild:
    """Slack payload plus compatibility-routing metadata."""

    payload: dict[str, object]
    warning: str | None = None


def build_slack_payload(report_markdown: str, *, max_text_chars: int = 2800) -> dict[str, object]:
    """Build a Slack Block Kit payload from Markdown compatibility input."""

    report_type = detect_markdown_report_type(report_markdown)
    if report_type == "repository":
        return _repository_payload_from_markdown(report_markdown, max_text_chars=max_text_chars)
    if report_type == "portfolio_summary":
        return _portfolio_payload_from_markdown(report_markdown, max_text_chars=max_text_chars)
    raise ValueError("Unsupported or unrecognised DriftBeacon report format.")


def build_slack_payload_from_path(
    report_path: Path,
    *,
    max_text_chars: int = 2800,
) -> SlackPayloadBuild:
    """Build a Slack payload from JSON when possible, with Markdown fallback."""

    if not report_path.exists():
        raise ValueError(f"DriftBeacon report file does not exist: {report_path}")
    if report_path.suffix.lower() == ".json":
        data = _load_json_report(report_path)
        return SlackPayloadBuild(
            _payload_from_json(
                data,
                comparison_data=_sibling_comparison_data(report_path),
                max_text_chars=max_text_chars,
            )
        )

    sibling = _sibling_json_report(report_path)
    if sibling is not None:
        data = _load_json_report(sibling)
        return SlackPayloadBuild(
            _payload_from_json(
                data,
                comparison_data=_sibling_comparison_data(sibling),
                max_text_chars=max_text_chars,
            )
        )

    markdown = report_path.read_text(encoding="utf-8")
    warning = "Warning: structured JSON not found; used Markdown compatibility fallback."
    return SlackPayloadBuild(build_slack_payload(markdown, max_text_chars=max_text_chars), warning)


def build_slack_payload_from_data(
    report_data: dict[str, Any],
    comparison_data: dict[str, Any] | None = None,
    *,
    max_text_chars: int = 2800,
) -> dict[str, object]:
    """Build a Slack payload from structured DriftBeacon report data."""

    return _payload_from_json(
        report_data,
        comparison_data=comparison_data,
        max_text_chars=max_text_chars,
    )


def send_slack_report(
    report_markdown: str,
    *,
    webhook_env_var: str = "SLACK_WEBHOOK_URL",
    enabled: bool = True,
    timeout_seconds: int = 10,
) -> SlackResult:
    """Send a Markdown report to Slack using an incoming webhook from the environment."""

    if not enabled:
        return SlackResult(sent=False, message="Slack sending disabled.")
    webhook_url = os.environ.get(webhook_env_var)
    if not webhook_url:
        return SlackResult(sent=False, message=f"Slack skipped: {webhook_env_var} is not set.")
    try:
        payload = build_slack_payload(report_markdown)
    except ValueError as exc:
        return SlackResult(sent=False, message=str(exc))
    return _post_slack_payload(payload, webhook_url, timeout_seconds=timeout_seconds)


def send_slack_report_from_path(
    report_path: Path,
    *,
    webhook_env_var: str = "SLACK_WEBHOOK_URL",
    enabled: bool = True,
    timeout_seconds: int = 10,
) -> SlackResult:
    """Send a report file to Slack, preferring sibling structured JSON."""

    if not enabled:
        return SlackResult(sent=False, message="Slack sending disabled.")
    try:
        built = build_slack_payload_from_path(report_path)
    except ValueError as exc:
        return SlackResult(sent=False, message=str(exc))
    webhook_url = os.environ.get(webhook_env_var)
    if not webhook_url:
        return SlackResult(sent=False, message=f"Slack skipped: {webhook_env_var} is not set.")
    result = _post_slack_payload(built.payload, webhook_url, timeout_seconds=timeout_seconds)
    if result.sent and built.warning:
        return SlackResult(sent=True, message=f"{result.message} {built.warning}")
    return result


def markdown_to_slack_summary(report_markdown: str, *, max_text_chars: int = 2800) -> str:
    """Convert DriftBeacon's Markdown report to readable Slack mrkdwn."""

    lines: list[str] = []
    for raw_line in report_markdown.splitlines():
        line = raw_line.rstrip()
        if not line:
            if lines and lines[-1] != "":
                lines.append("")
            continue
        converted = _convert_markdown_line(line)
        lines.append(escape_slack_text(converted))

    summary = "\n".join(lines).strip()
    return _truncate_preserving_lines(summary, max_text_chars)


def detect_json_report_type(data: dict[str, Any]) -> str | None:
    """Detect DriftBeacon report type from structured JSON shape."""

    explicit = data.get("report_type")
    if explicit in {"repository", "portfolio_summary"}:
        return str(explicit)
    metadata = data.get("metadata")
    if isinstance(metadata, dict) and (
        "repositories_requested" in metadata
        or "successful_scans" in metadata
        or "failed_scans" in metadata
    ):
        return "portfolio_summary"
    if "repository_results" in data or "aggregate_statistics" in data:
        return "portfolio_summary"
    if {"repository", "branch", "commit_sha", "findings", "scanner_statuses"}.issubset(
        data.keys()
    ):
        return "repository"
    return None


def detect_markdown_report_type(report_markdown: str) -> str | None:
    """Detect DriftBeacon report type from Markdown fallback shape."""

    if "DriftBeacon Repository Analysis Summary" in report_markdown and (
        "## Leaderboard" in report_markdown or "## Executive summary" in report_markdown
    ):
        return "portfolio_summary"
    if (
        "# DriftBeacon Report" in report_markdown or "# DriftBeacon Weekly" in report_markdown
    ) and _extract_field(report_markdown, "Repository"):
        return "repository"
    if "## Leaderboard" in report_markdown and "Repositories requested" in report_markdown:
        return "portfolio_summary"
    return None


def _payload_from_json(
    data: dict[str, Any],
    *,
    comparison_data: dict[str, Any] | None,
    max_text_chars: int,
) -> dict[str, object]:
    report_type = detect_json_report_type(data)
    if report_type == "repository":
        return _repository_payload_from_json(
            data,
            comparison_data=comparison_data,
            max_text_chars=max_text_chars,
        )
    if report_type == "portfolio_summary":
        return _portfolio_payload_from_json(data, max_text_chars=max_text_chars)
    raise ValueError("Unsupported or unrecognised DriftBeacon report format.")


def _repository_payload_from_json(
    data: dict[str, Any],
    *,
    comparison_data: dict[str, Any] | None,
    max_text_chars: int,
) -> dict[str, object]:
    scan = ScanResult.from_dict(data)
    summary = scan.summary
    has_baseline = _has_baseline(summary, comparison_data)
    active_count = summary.get("active_findings", len(actionable_active_findings(scan.findings)))
    fallback = (
        f"DriftBeacon report for {scan.repository}: "
        f"{_health_text(scan.health_score, summary)}"
    )
    priorities = prioritise_findings(scan.findings, limit=3)
    priority_text = _repository_priority_text(
        [
            prioritised_finding_details(item, has_baseline=has_baseline)
            for item in priorities
        ],
        max_text_chars=1400,
    )
    scanner_text = _scanner_status_text_from_scan(scan, max_text_chars=1200)
    resolved_text = _resolved_text_from_comparison(comparison_data, max_text_chars=900)
    summary_text = "\n".join(
        [
            f"*Repository:* {escape_slack_text(scan.repository)}",
            f"*Branch:* {escape_slack_text(scan.branch)}",
            f"*Commit:* {escape_slack_text(scan.commit_sha[:12])}",
            f"*Overall Health:* {escape_slack_text(_health_text(scan.health_score, summary))}",
            f"*Production Health:* {escape_slack_text(_production_health_text(summary))}",
            f"*Trend:* {escape_slack_text(_trend_text(summary, comparison_data))}",
            f"*Active findings:* {active_count}",
            f"*New:* {_summary_count(summary, 'new_findings')}",
            f"*Resolved:* {_summary_count(summary, 'resolved_findings')}",
            f"*Recurring:* {_summary_count(summary, 'recurring_findings')}",
            f"*Severity changes:* {_summary_count(summary, 'severity_changes')}",
        ]
    )
    return _make_payload(
        title="DriftBeacon Repository Report",
        fallback=fallback,
        blocks=[
            summary_text,
            priority_text,
            scanner_text,
            resolved_text,
        ],
        max_text_chars=max_text_chars,
    )


def _repository_payload_from_markdown(
    report_markdown: str,
    *,
    max_text_chars: int,
) -> dict[str, object]:
    summary = _repository_summary_from_markdown(report_markdown)
    priorities = _extract_priorities(report_markdown)
    scanner_status = _build_scanner_status_text(report_markdown, max_text_chars=1200)
    resolved = _build_resolved_text_from_markdown(report_markdown, max_text_chars=900)
    return _make_payload(
        title="DriftBeacon Repository Report",
        fallback=f"DriftBeacon report for {summary.get('Repository', 'repository')}",
        blocks=[
            "\n".join(f"*{key}:* {escape_slack_text(value)}" for key, value in summary.items()),
            _repository_priority_text(priorities, max_text_chars=1400),
            scanner_status,
            resolved,
        ],
        max_text_chars=max_text_chars,
    )


def _portfolio_payload_from_json(
    data: dict[str, Any],
    *,
    max_text_chars: int,
) -> dict[str, object]:
    metadata = _dict(data.get("metadata"))
    stats = _dict(data.get("aggregate_statistics"))
    repos = [item for item in data.get("repository_results", []) if isinstance(item, dict)]
    scanner_issues = [item for item in data.get("scanner_issues", []) if isinstance(item, dict)]
    failures = [item for item in data.get("failure_details", []) if isinstance(item, dict)]
    successful_default = len([repo for repo in repos if repo.get("status") == "success"])
    scanner_error_default = len(scanner_issues)
    run_type = _run_type_label(str(metadata.get("scan_mode", "unknown")))
    summary_lines = [
        f"*Scan date:* {escape_slack_text(str(metadata.get('scan_date', 'unknown')))}",
        f"*Run type:* {escape_slack_text(run_type)}",
        f"*Repositories requested:* {metadata.get('repositories_requested', len(repos))}",
        f"*Successful:* {metadata.get('successful_scans', successful_default)}",
        f"*Failed:* {metadata.get('failed_scans', len(failures))}",
        f"*Scored:* {stats.get('scored_repositories', _count_scored(repos))}",
        f"*Unscored:* {stats.get('unscored_repositories', _count_unscored(repos))}",
        f"*Average health:* {stats.get('average_health_score', 'unknown')}",
        f"*Median health:* {stats.get('median_health_score', 'unknown')}",
        f"*Repositories with scanner errors:* "
        f"{stats.get('repositories_with_scanner_errors', scanner_error_default)}",
        f"*Total actionable findings:* {stats.get('total_actionable_findings', 'unknown')}",
    ]
    return _make_payload(
        title="DriftBeacon Portfolio Summary",
        fallback="DriftBeacon portfolio summary",
        blocks=[
            "\n".join(summary_lines),
            _portfolio_attention_text(repos),
            _portfolio_best_production_text(repos),
            _portfolio_common_findings_text(data),
            _portfolio_scanner_issues_text(scanner_issues, repos, failures),
        ],
        max_text_chars=max_text_chars,
    )


def _portfolio_payload_from_markdown(
    report_markdown: str,
    *,
    max_text_chars: int,
) -> dict[str, object]:
    fields = {
        "Scan date": _extract_field(report_markdown, "Scan date") or "unknown",
        "Repositories requested": _extract_field(report_markdown, "Repositories requested")
        or "unknown",
        "Successful": _extract_field(report_markdown, "Successful scans") or "unknown",
        "Failed": _extract_field(report_markdown, "Failed scans") or "unknown",
        "Scored": _extract_field(report_markdown, "Scored repositories") or "unknown",
        "Unscored": _extract_field(report_markdown, "Unscored repositories") or "unknown",
        "Run type": _extract_field(report_markdown, "Run type") or "unknown",
    }
    executive = _extract_section_list(report_markdown, "Executive summary")
    leaderboard = _extract_markdown_table_rows(report_markdown, "Leaderboard", limit=3)
    scanner_issues = _extract_markdown_table_rows(report_markdown, "Scanner issues", limit=5)
    blocks = [
        "\n".join(f"*{key}:* {escape_slack_text(value)}" for key, value in fields.items()),
        "*Overall portfolio health*\n"
        + "\n".join(escape_slack_text(item) for item in executive[:6]),
        "*Repositories requiring attention*\n"
        + ("\n".join(escape_slack_text(row) for row in leaderboard) or "No scored repositories."),
        "*Scanner issues*\n"
        + (
            "\n".join(escape_slack_text(row) for row in scanner_issues)
            or "No scanner issues recorded."
        ),
    ]
    return _make_payload(
        title="DriftBeacon Portfolio Summary",
        fallback="DriftBeacon portfolio summary",
        blocks=blocks,
        max_text_chars=max_text_chars,
    )


def _make_payload(
    *,
    title: str,
    fallback: str,
    blocks: list[str],
    max_text_chars: int,
) -> dict[str, object]:
    slack_blocks: list[dict[str, object]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title, "emoji": False},
        }
    ]
    for index, block in enumerate(blocks):
        text = _truncate_preserving_lines(block.strip(), max_text_chars)
        if not text:
            continue
        if index > 0:
            slack_blocks.append({"type": "divider"})
        slack_blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
    slack_blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Full Markdown/JSON report is available as a GitHub Actions artifact.",
                }
            ],
        }
    )
    return {"text": redact_secrets(fallback), "blocks": slack_blocks}


def _post_slack_payload(
    payload: dict[str, object],
    webhook_url: str,
    *,
    timeout_seconds: int,
) -> SlackResult:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if 200 <= response.status < 300:
                return SlackResult(sent=True, message="Slack report sent.")
            return SlackResult(sent=False, message=f"Slack returned HTTP {response.status}.")
    except urllib.error.URLError as exc:
        return SlackResult(sent=False, message=f"Slack send failed: {redact_secrets(str(exc))}")


def _repository_summary_from_markdown(report_markdown: str) -> dict[str, str]:
    return {
        "Repository": _extract_field(report_markdown, "Repository") or "unknown",
        "Branch": _extract_field(report_markdown, "Branch") or "unknown",
        "Commit": _extract_field(report_markdown, "Commit") or "unknown",
        "Overall Health": _extract_field(report_markdown, "Health score") or "unknown",
        "Production Health": _extract_field(report_markdown, "Production Health") or "Not scored",
        "Trend": _extract_field(report_markdown, "Trend") or "unknown",
        "Active findings": _extract_field(report_markdown, "Active findings") or "unknown",
    }


def _repository_priority_text(
    priorities: list[dict[str, str]],
    *,
    max_text_chars: int,
) -> str:
    if not priorities:
        return "*Top priorities:*\nNo active findings were detected."
    lines = ["*Top priorities:*"]
    for index, item in enumerate(priorities[:3], start=1):
        lines.extend(
            [
                f"{index}. *{escape_slack_text(item.get('title', 'Unknown finding'))}*",
                f"   Rule: {escape_slack_text(item.get('rule_id', 'unknown'))}",
                f"   Severity: {escape_slack_text(item.get('severity', 'unknown'))}",
                f"   Location: {escape_slack_text(item.get('location', 'Unknown location'))}",
                f"   Directory group: {escape_slack_text(item.get('directory_group', 'unknown'))}",
                f"   Source: {escape_slack_text(item.get('finding_source', 'unknown'))}",
                f"   Status: {escape_slack_text(item.get('status', 'unknown'))}",
                "   Why this matters: "
                f"{escape_slack_text(item.get('why', 'No explanation available.'))}",
                "   Recommended action: "
                f"{escape_slack_text(_truncate(item.get('action', 'Review the finding.'), 320))}",
            ]
        )
    return _truncate_preserving_lines("\n".join(lines), max_text_chars)


def _scanner_status_text_from_scan(scan: ScanResult, *, max_text_chars: int) -> str:
    if not scan.scanner_statuses:
        return "*Scanner status:*\nNo scanner status was recorded."
    lines = ["*Scanner status:*"]
    for status in scan.scanner_statuses.values():
        lines.append(
            f"- *{escape_slack_text(status.name.capitalize())}:* "
            f"{escape_slack_text(status.status.capitalize())}: "
            f"{escape_slack_text(_truncate(status.message, 220))}"
        )
    return _truncate_preserving_lines("\n".join(lines), max_text_chars)


def _build_scanner_status_text(report_markdown: str, *, max_text_chars: int) -> str:
    statuses = _extract_section_list(report_markdown, "Scanner status")
    if not statuses:
        return "*Scanner status:*\nNo scanner status was recorded."
    lines = ["*Scanner status:*"]
    for status in statuses[:4]:
        cleaned = status.removeprefix("- ").strip()
        name, separator, detail = cleaned.partition(":")
        if separator:
            lines.append(f"- *{escape_slack_text(name)}:* {escape_slack_text(detail.strip())}")
        else:
            lines.append(f"- {escape_slack_text(cleaned)}")
    return _truncate_preserving_lines("\n".join(lines), max_text_chars)


def _resolved_text_from_comparison(
    comparison_data: dict[str, Any] | None,
    *,
    max_text_chars: int,
) -> str:
    resolved = _comparison_findings(comparison_data, "resolved_findings")
    if not resolved:
        return "*Recently resolved:*\nNo recently resolved findings."
    lines = ["*Recently resolved:*"]
    for finding in resolved[:5]:
        severity = str(finding.get("severity", "unknown")).capitalize()
        title = str(finding.get("title", "Unknown finding"))
        lines.append(
            f"- {escape_slack_text(severity)}: {escape_slack_text(title)} "
            f"({escape_slack_text(_finding_location(finding))})"
        )
    return _truncate_preserving_lines("\n".join(lines), max_text_chars)


def _build_resolved_text_from_markdown(report_markdown: str, *, max_text_chars: int) -> str:
    resolved = _extract_section_list(report_markdown, "Recently resolved")
    if not resolved:
        return "*Recently resolved:*\nNo recently resolved findings."
    return _truncate_preserving_lines(
        "*Recently resolved:*\n" + "\n".join(escape_slack_text(item) for item in resolved[:5]),
        max_text_chars,
    )


def _portfolio_attention_text(repos: list[dict[str, Any]]) -> str:
    candidates = [repo for repo in repos if repo.get("status") == "success"]
    ranked = sorted(
        candidates,
        key=lambda repo: (
            _nullable_score(repo.get("production_health_score")),
            _nullable_score(repo.get("health_score")),
            str(repo.get("repository", "")),
        ),
    )
    lines = ["*Repositories requiring attention:*"]
    if not ranked:
        lines.append("No scored repositories.")
        return "\n".join(lines)
    for index, repo in enumerate(ranked[:3], start=1):
        lines.append(f"{index}. *{escape_slack_text(str(repo.get('repository', 'unknown')))}*")
        lines.append(
            f"   Overall Health: {escape_slack_text(_repo_health_grade(repo, production=False))}"
        )
        lines.append(
            f"   Production Health: {escape_slack_text(_repo_health_grade(repo, production=True))}"
        )
        lines.append(
            "   Production findings: "
            f"{repo.get('production_critical_findings', 0)} Critical, "
            f"{repo.get('production_high_findings', 0)} High, "
            f"{repo.get('production_medium_findings', 0)} Medium, "
            f"{repo.get('production_low_findings', 0)} Low"
        )
        coverage = _coverage_label(str(repo.get("coverage_state", "unknown")))
        lines.append(f"   Coverage: {escape_slack_text(coverage)}")
        lines.append(f"   Main concern: {escape_slack_text(_main_concern(repo))}")
    return "\n".join(lines)


def _portfolio_best_production_text(repos: list[dict[str, Any]]) -> str:
    candidates = [
        repo
        for repo in repos
        if repo.get("status") == "success" and isinstance(repo.get("production_health_score"), int)
    ]
    ranked = sorted(
        candidates,
        key=lambda repo: (
            -int(repo.get("production_health_score", 0)),
            -int(repo.get("health_score", 0) or 0),
            str(repo.get("repository", "")),
        ),
    )
    lines = ["*Best production health:*"]
    if not ranked:
        lines.append("No repositories had a production score.")
        return "\n".join(lines)
    for index, repo in enumerate(ranked[:3], start=1):
        lines.append(
            f"{index}. {escape_slack_text(str(repo.get('repository', 'unknown')))} — "
            f"{escape_slack_text(_repo_health_grade(repo, production=True))}"
        )
    return "\n".join(lines)


def _portfolio_common_findings_text(data: dict[str, Any]) -> str:
    common = [item for item in data.get("common_findings", []) if isinstance(item, dict)]
    lines = ["*Most common risks:*"]
    if not common:
        lines.append("No common actionable findings recorded.")
        return "\n".join(lines)
    for finding in common[:5]:
        lines.append(
            f"- {escape_slack_text(str(finding.get('title', 'Unknown finding')))} — "
            f"{finding.get('total_occurrences', 0)} occurrences"
        )
    return "\n".join(lines)


def _portfolio_scanner_issues_text(
    scanner_issues: list[dict[str, Any]],
    repos: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> str:
    by_scanner = Counter(str(issue.get("scanner", "unknown")) for issue in scanner_issues)
    partial = sum(1 for repo in repos if repo.get("coverage_state") == "partial_coverage")
    lines = ["*Scanner issues:*"]
    if by_scanner:
        for scanner, count in sorted(by_scanner.items()):
            lines.append(f"- {count} {escape_slack_text(scanner.capitalize())} issues")
    else:
        lines.append("- No scanner failures recorded.")
    lines.append(f"- {partial} repositories have partial coverage")
    lines.append(f"- {len(failures)} repositories could not be processed")
    return "\n".join(lines)


def _main_concern(repo: dict[str, Any]) -> str:
    if repo.get("coverage_state") == "partial_coverage":
        return "Partial scanner coverage may make this score incomplete."
    breakdown = repo.get("finding_source_breakdown")
    if isinstance(breakdown, dict) and breakdown:
        source, row = max(
            breakdown.items(),
            key=lambda item: item[1].get("total_actionable", 0)
            if isinstance(item[1], dict)
            else 0,
        )
        return f"{source_label(str(source))} dominate this repository's findings."
    return "Review the highest-severity production and overall findings first."


def _repo_health_grade(repo: dict[str, Any], *, production: bool) -> str:
    score_key = "production_health_score" if production else "health_score"
    grade_key = "production_grade" if production else "grade"
    provisional_key = "production_grade_provisional" if production else "grade_provisional"
    score = repo.get(score_key)
    if not isinstance(score, int):
        return "Not scored/N/A"
    grade = str(repo.get(grade_key) or _grade(score))
    if repo.get(provisional_key) is True and grade != "N/A":
        grade += "*"
    return f"{score}/{grade}"


def _health_text(score: int | None, summary: dict[str, Any]) -> str:
    if score is None:
        return "Not scored"
    grade = _grade(score)
    if summary.get("grade_provisional") is True and grade != "N/A":
        grade += "*"
    return f"{score}/100 ({grade})"


def _production_health_text(summary: dict[str, Any]) -> str:
    score = summary.get("production_health_score")
    if not isinstance(score, int):
        return "Not scored"
    grade = str(summary.get("production_grade") or _grade(score))
    if summary.get("production_grade_provisional") is True and grade != "N/A":
        grade += "*"
    return f"{score}/100 ({grade})"


def _trend_text(summary: dict[str, Any], comparison_data: dict[str, Any] | None) -> str:
    if str(summary.get("score_formula_changed", "false")) == "true":
        return "health model changed"
    comparison_data = comparison_data or {}
    initial = summary.get("baseline_status") == "initial_baseline"
    if comparison_data.get("has_baseline") is False or initial:
        return "first scan"
    delta = comparison_data.get("health_score_change")
    if isinstance(delta, int):
        if delta > 0:
            return f"up {delta} points"
        if delta < 0:
            return f"down {abs(delta)} points"
        return "unchanged"
    return "unknown"


def _has_baseline(summary: dict[str, Any], comparison_data: dict[str, Any] | None) -> bool:
    if comparison_data and isinstance(comparison_data.get("has_baseline"), bool):
        return bool(comparison_data["has_baseline"])
    return summary.get("baseline_status") == "comparison_scan"


def _summary_count(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key)
    return value if isinstance(value, int) else 0


def _comparison_findings(
    comparison_data: dict[str, Any] | None,
    key: str,
) -> list[dict[str, Any]]:
    if not comparison_data:
        return []
    value = comparison_data.get(key)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _finding_location(finding: dict[str, Any]) -> str:
    path = finding.get("file_path")
    line = finding.get("line_start")
    if path and line:
        return f"{path}:{line}"
    return str(path or finding.get("resource") or "Unknown")


def _load_json_report(report_path: Path) -> dict[str, Any]:
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed DriftBeacon JSON report: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError("Unsupported or unrecognised DriftBeacon report format.")
    return data


def _sibling_json_report(report_path: Path) -> Path | None:
    candidates: list[Path] = []
    if report_path.name == "analysis-summary.md":
        candidates.append(report_path.with_name("analysis-summary.json"))
    if report_path.name == "report.md":
        candidates.append(report_path.with_name("current-scan.json"))
    candidates.append(report_path.with_suffix(".json"))
    return next((candidate for candidate in candidates if candidate.exists()), None)


def _sibling_comparison_data(report_path: Path) -> dict[str, Any] | None:
    candidate = report_path.with_name("comparison-summary.json")
    if not candidate.exists():
        return None
    try:
        return _load_json_report(candidate)
    except ValueError:
        return None


def _extract_field(report_markdown: str, label: str) -> str | None:
    bold_prefix = f"**{label}:**"
    plain_prefix = f"{label}:"
    for line in report_markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith(bold_prefix):
            value = stripped.removeprefix(bold_prefix).strip()
            return _strip_inline_markdown(value)
        if stripped.startswith(plain_prefix):
            value = stripped.removeprefix(plain_prefix).strip()
            return _strip_inline_markdown(value)
    return None


def _extract_priorities(report_markdown: str) -> list[dict[str, str]]:
    priorities: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in report_markdown.splitlines():
        stripped = line.strip()
        if re.match(r"^### \d+\. ", stripped):
            if current is not None:
                priorities.append(current)
            current = {"title": _strip_inline_markdown(re.sub(r"^### \d+\. ", "", stripped))}
            continue
        if current is None:
            continue
        for label, key in (
            ("Rule ID", "rule_id"),
            ("Location", "location"),
            ("Directory group", "directory_group"),
            ("Finding source", "finding_source"),
            ("Why", "why"),
            ("Action", "action"),
            ("Status", "status"),
        ):
            prefix = f"**{label}:**"
            if stripped.startswith(prefix):
                current[key] = _strip_inline_markdown(stripped.removeprefix(prefix).strip())
        if stripped.startswith("**Severity:**"):
            severity = stripped.removeprefix("**Severity:**").strip().split("|", 1)[0].strip()
            current["severity"] = _strip_inline_markdown(severity)
    if current is not None:
        priorities.append(current)
    return priorities


def _extract_section_list(report_markdown: str, heading: str) -> list[str]:
    lines: list[str] = []
    inside = False
    for line in report_markdown.splitlines():
        stripped = line.strip()
        if stripped == f"## {heading}":
            inside = True
            continue
        if inside and stripped.startswith("## "):
            break
        if inside and stripped.startswith("- "):
            lines.append(stripped)
    return lines


def _extract_markdown_table_rows(
    report_markdown: str,
    heading: str,
    *,
    limit: int,
) -> list[str]:
    rows: list[str] = []
    inside = False
    for line in report_markdown.splitlines():
        stripped = line.strip()
        if stripped == f"## {heading}":
            inside = True
            continue
        if inside and stripped.startswith("## "):
            break
        if not inside or not stripped.startswith("|") or "---" in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and cells[0].lower() in {"rank", "repository"}:
            continue
        rows.append(" — ".join(cells[:6]))
        if len(rows) >= limit:
            break
    return rows


def _strip_inline_markdown(value: str) -> str:
    stripped = value.strip()
    stripped = re.sub(r"\s{2,}$", "", stripped)
    stripped = stripped.replace("`", "")
    stripped = re.sub(r"\*\*([^*]+?)\*\*", r"\1", stripped)
    return stripped


def _convert_markdown_line(line: str) -> str:
    stripped = line.strip()
    for prefix in ("### ", "## ", "# "):
        if stripped.startswith(prefix):
            return f"*{stripped.removeprefix(prefix)}*"
    stripped = re.sub(r"\*\*([^*]+?):\*\*", r"*\1:*", stripped)
    return re.sub(r"\*\*([^*]+?)\*\*", r"*\1*", stripped)


def _truncate_preserving_lines(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    marker = "\n\n_Report truncated. Full report is available as an artifact._"
    return value[: max(0, limit - len(marker))].rstrip() + marker


def _truncate(value: str | None, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _grade(score: int | None) -> str:
    if score is None:
        return "N/A"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _nullable_score(value: object) -> int:
    return value if isinstance(value, int) else 101


def _coverage_label(value: str) -> str:
    return {
        "complete_coverage": "Complete",
        "partial_coverage": "Partial",
        "not_scored_no_supported_files": "Not scored",
        "not_scored_all_scanners_failed": "Not scored",
    }.get(value, value)


def _run_type_label(value: str) -> str:
    return {
        "initial_baseline": "Initial baseline",
        "comparison_scan": "Comparison scan",
    }.get(value, value)


def _count_scored(repos: list[dict[str, Any]]) -> int:
    return sum(1 for repo in repos if isinstance(repo.get("health_score"), int))


def _count_unscored(repos: list[dict[str, Any]]) -> int:
    return sum(
        1
        for repo in repos
        if repo.get("status") == "success" and repo.get("health_score") is None
    )


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
