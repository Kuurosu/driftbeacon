"""Configuration loading and validation."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from .models import VALID_SEVERITIES, Severity

DEFAULT_PRODUCTION_PATTERNS = ("production", "prod", "live")


class ConfigError(ValueError):
    """Raised when DriftBeacon configuration is invalid."""


@dataclass(slots=True)
class Config:
    """Runtime configuration for DriftBeacon."""

    repository_path: Path = Path(".")
    output_dir: Path = Path(".driftbeacon")
    checkov_enabled: bool = True
    trivy_enabled: bool = True
    trivy_secret_scanning: bool = False
    top_findings: int = 3
    fail_on: Severity | None = None
    production_patterns: tuple[str, ...] = field(
        default_factory=lambda: DEFAULT_PRODUCTION_PATTERNS
    )
    slack_enabled: bool = True
    slack_webhook_environment_variable: str = "SLACK_WEBHOOK_URL"

    def validate(self) -> Config:
        if not self.repository_path.exists() or not self.repository_path.is_dir():
            raise ConfigError(
                f"repository_path does not exist or is not a directory: {self.repository_path}"
            )
        if self.repository_path.is_symlink():
            raise ConfigError("repository_path must not be a symlink")
        if self.top_findings < 1:
            raise ConfigError("report.top_findings must be at least 1")
        if self.fail_on is not None and self.fail_on not in VALID_SEVERITIES:
            raise ConfigError(f"thresholds.fail_on must be one of: {', '.join(VALID_SEVERITIES)}")
        if not self.slack_webhook_environment_variable:
            raise ConfigError("slack.webhook_environment_variable must not be empty")
        if self.output_dir.exists() and self.output_dir.is_symlink():
            raise ConfigError("output_dir must not be a symlink")
        return self


def load_config(
    *,
    repository_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    config_path: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    no_slack: bool = False,
    slack_webhook_env: str | None = None,
) -> Config:
    """Load configuration from defaults, optional YAML, environment, and CLI overrides."""

    environment = env or os.environ
    config = Config()

    if repository_path is not None:
        config.repository_path = Path(repository_path)

    file_path = _discover_config_path(config.repository_path, config_path)
    if file_path is not None:
        parsed = parse_simple_yaml(file_path.read_text(encoding="utf-8"))
        _apply_mapping(config, parsed)

    _apply_environment(config, environment)

    if repository_path is not None:
        config.repository_path = Path(repository_path)
    if output_dir is not None:
        config.output_dir = Path(output_dir)
    if slack_webhook_env is not None:
        config.slack_webhook_environment_variable = slack_webhook_env
    if no_slack:
        config.slack_enabled = False

    config.repository_path = config.repository_path.expanduser().resolve()
    if not config.output_dir.is_absolute():
        config.output_dir = config.repository_path / config.output_dir
    config.output_dir = config.output_dir.expanduser().resolve()
    return config.validate()


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the limited YAML subset used by `.driftbeacon.yml`.

    PyYAML is intentionally not required. This parser supports nested mappings,
    booleans, integers, nulls, quoted/unquoted strings, and simple lists.
    """

    lines = _prepare_yaml_lines(text)
    index = 0

    def parse_mapping(indent: int) -> dict[str, Any]:
        nonlocal index
        result: dict[str, Any] = {}
        while index < len(lines):
            line_indent, content = lines[index]
            if line_indent < indent:
                break
            if line_indent > indent:
                raise ConfigError(f"unexpected indentation near: {content}")
            if content.startswith("- "):
                raise ConfigError("top-level lists are not supported in DriftBeacon config")
            key, separator, raw_value = content.partition(":")
            if not separator or not key.strip():
                raise ConfigError(f"invalid configuration line: {content}")
            key = key.strip()
            raw_value = raw_value.strip()
            index += 1
            if raw_value:
                result[key] = _parse_scalar(raw_value)
                continue
            if index >= len(lines) or lines[index][0] <= line_indent:
                result[key] = {}
                continue
            child_indent = lines[index][0]
            if lines[index][1].startswith("- "):
                result[key] = parse_list(child_indent)
            else:
                result[key] = parse_mapping(child_indent)
        return result

    def parse_list(indent: int) -> list[Any]:
        nonlocal index
        values: list[Any] = []
        while index < len(lines):
            line_indent, content = lines[index]
            if line_indent < indent:
                break
            if line_indent != indent or not content.startswith("- "):
                raise ConfigError(f"invalid list item near: {content}")
            values.append(_parse_scalar(content[2:].strip()))
            index += 1
        return values

    return parse_mapping(0)


def _discover_config_path(repository_path: Path, config_path: str | Path | None) -> Path | None:
    if config_path is not None:
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"config file does not exist: {path}")
        return path
    default_path = repository_path / ".driftbeacon.yml"
    if default_path.exists():
        return default_path
    return None


def _apply_mapping(config: Config, data: dict[str, Any]) -> None:
    if "repository_path" in data:
        config.repository_path = Path(str(data["repository_path"]))
    if "output_dir" in data:
        config.output_dir = Path(str(data["output_dir"]))

    scanners = _mapping(data.get("scanners"))
    checkov = _mapping(scanners.get("checkov"))
    trivy = _mapping(scanners.get("trivy"))
    if "enabled" in checkov:
        config.checkov_enabled = _bool(checkov["enabled"], "scanners.checkov.enabled")
    if "enabled" in trivy:
        config.trivy_enabled = _bool(trivy["enabled"], "scanners.trivy.enabled")
    if "secret_scanning" in trivy:
        config.trivy_secret_scanning = _bool(
            trivy["secret_scanning"], "scanners.trivy.secret_scanning"
        )

    report = _mapping(data.get("report"))
    if "top_findings" in report:
        config.top_findings = _int(report["top_findings"], "report.top_findings")

    thresholds = _mapping(data.get("thresholds"))
    if "fail_on" in thresholds:
        value = thresholds["fail_on"]
        config.fail_on = None if value is None else cast(Severity, str(value).lower())

    paths = _mapping(data.get("paths"))
    patterns = paths.get("production_patterns")
    if patterns is not None:
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            raise ConfigError("paths.production_patterns must be a list of strings")
        config.production_patterns = tuple(
            item.strip().lower() for item in patterns if item.strip()
        )

    slack = _mapping(data.get("slack"))
    if "enabled" in slack:
        config.slack_enabled = _bool(slack["enabled"], "slack.enabled")
    if "webhook_environment_variable" in slack:
        config.slack_webhook_environment_variable = str(slack["webhook_environment_variable"])


def _apply_environment(config: Config, env: Mapping[str, str]) -> None:
    if env.get("DRIFTBEACON_REPOSITORY_PATH"):
        config.repository_path = Path(env["DRIFTBEACON_REPOSITORY_PATH"])
    if env.get("DRIFTBEACON_OUTPUT_DIR"):
        config.output_dir = Path(env["DRIFTBEACON_OUTPUT_DIR"])
    if env.get("DRIFTBEACON_CHECKOV_ENABLED"):
        config.checkov_enabled = _env_bool(env["DRIFTBEACON_CHECKOV_ENABLED"])
    if env.get("DRIFTBEACON_TRIVY_ENABLED"):
        config.trivy_enabled = _env_bool(env["DRIFTBEACON_TRIVY_ENABLED"])
    if env.get("DRIFTBEACON_TRIVY_SECRET_SCANNING"):
        config.trivy_secret_scanning = _env_bool(env["DRIFTBEACON_TRIVY_SECRET_SCANNING"])
    if env.get("DRIFTBEACON_TOP_FINDINGS"):
        config.top_findings = _int(env["DRIFTBEACON_TOP_FINDINGS"], "DRIFTBEACON_TOP_FINDINGS")
    if env.get("DRIFTBEACON_FAIL_ON"):
        fail_on = env["DRIFTBEACON_FAIL_ON"].strip().lower()
        config.fail_on = None if fail_on in {"", "none", "off"} else cast(Severity, fail_on)


def _prepare_yaml_lines(text: str) -> list[tuple[int, str]]:
    prepared: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        without_comments = _strip_comment(raw_line).rstrip()
        if not without_comments.strip():
            continue
        indent = len(without_comments) - len(without_comments.lstrip(" "))
        if "\t" in without_comments[:indent]:
            raise ConfigError("tabs are not supported for indentation")
        prepared.append((indent, without_comments.strip()))
    return prepared


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _parse_scalar(value: str) -> Any:
    cleaned = value.strip()
    lowered = cleaned.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ):
        return cleaned[1:-1]
    if cleaned.isdigit() or (cleaned.startswith("-") and cleaned[1:].isdigit()):
        return int(cleaned)
    return cleaned


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _bool(value: object, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "on", "1"}:
            return True
        if lowered in {"false", "no", "off", "0"}:
            return False
    raise ConfigError(f"{field_name} must be a boolean")


def _env_bool(value: str) -> bool:
    return value.strip().lower() in {"true", "yes", "on", "1"}


def _int(value: object, field_name: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    raise ConfigError(f"{field_name} must be an integer")
