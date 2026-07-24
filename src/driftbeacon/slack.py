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

    summary = markdown_to_slack_summary(report_markdown, max_text_chars=max_text_chars)
    return {
        "text": "DriftBeacon weekly operational report",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary,
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
