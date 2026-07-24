from __future__ import annotations

import json

from driftbeacon.redaction import redact_secrets
from driftbeacon.slack import build_slack_payload, markdown_to_slack_summary, send_slack_report


def test_slack_payload_redacts_and_escapes_untrusted_text() -> None:
    payload = build_slack_payload(
        "# DriftBeacon Report\n"
        "**Repository:** <bad> password=secret-value https://hooks.slack.com/services/T/B/C  \n"
        "**Health score:** 90/100 (unchanged)  \n"
        "**Trend:** unchanged\n"
    )

    encoded = json.dumps(payload)
    assert "secret-value" not in encoded
    assert "hooks.slack.com" not in encoded
    assert "&lt;bad&gt;" in encoded


def test_slack_payload_uses_digest_blocks() -> None:
    payload = build_slack_payload(
        "# DriftBeacon Report\n"
        "**Repository:** driftbeacon-mvp  \n"
        "**Branch:** main  \n"
        "**Health score:** 12/100 (down 8 points)  \n"
        "**Active findings:** 6  \n"
        "**Trend:** 2 new findings, 3 recurring findings, 1 resolved finding\n"
        "## Fix these first\n"
        "### 1. AWS Access Key ID\n"
        "**Severity:** Critical | **Category:** secret  \n"
        "**Location:** terraform/secrets.tf:4  \n"
        "## Scanner status\n"
        "- Checkov: Success: loaded 3 findings from JSON\n"
        "- Trivy: Success: loaded 3 findings from JSON\n"
    )

    blocks = payload["blocks"]  # type: ignore[assignment]
    assert blocks[0]["type"] == "header"  # type: ignore[index]
    assert "Top priorities" in blocks[3]["text"]["text"]  # type: ignore[index]
    assert "AWS Access Key ID" in blocks[3]["text"]["text"]  # type: ignore[index]
    assert "Scanner status" in blocks[4]["text"]["text"]  # type: ignore[index]


def test_markdown_to_slack_summary_preserves_report_shape() -> None:
    summary = markdown_to_slack_summary(
        "# DriftBeacon Weekly\n"
        "**Repository:** driftbeacon-mvp  \n"
        "## Fix these first\n"
        "### 1. AWS Access Key ID\n"
        "- 1 resolved finding\n"
    )

    assert summary.splitlines() == [
        "*DriftBeacon Weekly*",
        "*Repository:* driftbeacon-mvp",
        "*Fix these first*",
        "*1. AWS Access Key ID*",
        "- 1 resolved finding",
    ]


def test_slack_send_skips_when_webhook_missing(monkeypatch: object) -> None:
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)  # type: ignore[attr-defined]

    result = send_slack_report("hello")

    assert result.sent is False
    assert result.message == "Slack skipped: SLACK_WEBHOOK_URL is not set."


def test_redaction_removes_obvious_secret_shapes() -> None:
    redacted = redact_secrets("token=abc12345678901234567890 AKIA1234567890ABCDEF")

    assert "abc12345678901234567890" not in redacted
    assert "AKIA1234567890ABCDEF" not in redacted
