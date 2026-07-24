"""Secret redaction helpers used before persistence, reporting, and Slack delivery."""

from __future__ import annotations

import html
import re

REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)"
        r"(\s*[:=]\s*)(['\"]?)[^'\"\s]+"
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
)


def redact_secrets(value: str | None) -> str:
    """Redact common token and secret shapes from untrusted scanner text."""

    if value is None:
        return ""
    redacted = value
    for pattern in REDACTION_PATTERNS:
        if pattern.pattern.lower().startswith("(?i)\\b(password"):
            redacted = pattern.sub(r"\1\2<redacted>", redacted)
        elif pattern.pattern.lower().startswith("(?i)\\b(bearer"):
            redacted = pattern.sub(r"\1<redacted>", redacted)
        else:
            redacted = pattern.sub("<redacted>", redacted)
    return redacted


def escape_slack_text(value: str | None) -> str:
    """Redact and HTML-escape text before using it in Slack mrkdwn."""

    return html.escape(redact_secrets(value), quote=False)


def truncate(value: str, limit: int) -> str:
    """Return a single-line string clipped to a readable length."""

    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 1)].rstrip() + "..."
