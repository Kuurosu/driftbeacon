"""Slack webhook integration."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from .redaction import escape_slack_text, redact_secrets


@dataclass(frozen=True, slots=True)
class SlackResult:
    """Result of a Slack send attempt."""

    sent: bool
    message: str


def build_slack_payload(report_markdown: str, *, max_text_chars: int = 2800) -> dict[str, object]:
    """Build a short Slack Block Kit payload from a Markdown report."""

    repository = _extract_field(report_markdown, "Repository") or "unknown repository"
    health = _extract_field(report_markdown, "Health score") or "unknown"
    summary = _build_summary_text(report_markdown, max_text_chars=max_text_chars)
    priorities = _build_priority_text(report_markdown, max_text_chars=1400)
    scanner_status = _build_scanner_status_text(report_markdown, max_text_chars=1200)
    return {
        "text": f"DriftBeacon report for {redact_secrets(repository)}: health {health}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "DriftBeacon report",
                    "emoji": False,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": priorities,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": scanner_status,
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Full Markdown report is available as a GitHub Actions artifact.",
                    }
                ],
            },
        ],
    }


def send_slack_report(
    report_markdown: str,
    *,
    webhook_env_var: str = "SLACK_WEBHOOK_URL",
    enabled: bool = True,
    timeout_seconds: int = 10,
) -> SlackResult:
    """Send a report to Slack using an incoming webhook from the environment."""

    if not enabled:
        return SlackResult(sent=False, message="Slack sending disabled.")
    webhook_url = os.environ.get(webhook_env_var)
    if not webhook_url:
        return SlackResult(sent=False, message=f"Slack skipped: {webhook_env_var} is not set.")

    payload = json.dumps(build_slack_payload(report_markdown)).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
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


def _build_summary_text(report_markdown: str, *, max_text_chars: int) -> str:
    fields = {
        "Repository": _extract_field(report_markdown, "Repository") or "unknown",
        "Branch": _extract_field(report_markdown, "Branch") or "unknown",
        "Health": _extract_field(report_markdown, "Health score") or "unknown",
        "Trend": _extract_field(report_markdown, "Trend") or "unknown",
        "Active findings": _extract_field(report_markdown, "Active findings") or "unknown",
    }
    lines = [f"*{label}:* {escape_slack_text(value)}" for label, value in fields.items()]
    return _truncate_preserving_lines("\n".join(lines), max_text_chars)


def _build_priority_text(report_markdown: str, *, max_text_chars: int) -> str:
    priorities = _extract_priorities(report_markdown)
    if not priorities:
        return "*Top priorities:*\nNo active findings were detected."
    lines = ["*Top priorities:*"]
    for index, item in enumerate(priorities[:3], start=1):
        title = escape_slack_text(item.get("title", "Unknown finding"))
        severity = escape_slack_text(item.get("severity", "unknown"))
        location = escape_slack_text(item.get("location", "Unknown location"))
        lines.append(f"{index}. *{title}* ({severity})")
        lines.append(f"   {location}")
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


def _extract_field(report_markdown: str, label: str) -> str | None:
    prefix = f"**{label}:**"
    for line in report_markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            value = stripped.removeprefix(prefix).strip()
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
            current = {"title": re.sub(r"^### \d+\. ", "", stripped)}
            continue
        if current is None:
            continue
        if stripped.startswith("**Severity:**"):
            severity = stripped.removeprefix("**Severity:**").strip().split("|", 1)[0].strip()
            current["severity"] = _strip_inline_markdown(severity)
        elif stripped.startswith("**Location:**"):
            current["location"] = _strip_inline_markdown(
                stripped.removeprefix("**Location:**").strip()
            )
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
