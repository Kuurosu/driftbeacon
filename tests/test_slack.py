from __future__ import annotations

from driftbeacon.redaction import redact_secrets
from driftbeacon.slack import build_slack_payload, markdown_to_slack_summary, send_slack_report


def test_slack_payload_redacts_and_escapes_untrusted_text() -> None:
    payload = build_slack_payload(
        "# Report\npassword=secret-value\nhttps://hooks.slack.com/services/T/B/C\n<bad>"
    )

    text = payload["blocks"][0]["text"]["text"]  # type: ignore[index]
    assert "secret-value" not in text
    assert "hooks.slack.com" not in text
    assert "&lt;bad&gt;" in text
    assert "\n" in text


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
