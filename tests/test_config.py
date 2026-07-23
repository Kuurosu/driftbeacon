from __future__ import annotations

import pytest

from DriftBeacon.config import ConfigError, load_config, parse_simple_yaml


def test_config_parses_expected_yaml_shape(tmp_path: object) -> None:
    repo = tmp_path  # type: ignore[assignment]
    config_file = repo / ".DriftBeacon.yml"
    config_file.write_text(
        """
output_dir: .custom
scanners:
  checkov:
    enabled: true
  trivy:
    enabled: true
    secret_scanning: false
report:
  top_findings: 4
thresholds:
  fail_on: critical
paths:
  production_patterns:
    - production
    - live
slack:
  enabled: false
  webhook_environment_variable: SLACK_WEBHOOK_URL
""",
        encoding="utf-8",
    )

    config = load_config(repository_path=repo, config_path=config_file)

    assert config.output_dir.name == ".custom"
    assert config.top_findings == 4
    assert config.fail_on == "critical"
    assert config.production_patterns == ("production", "live")
    assert config.slack_enabled is False


def test_invalid_config_fails_clearly(tmp_path: object) -> None:
    config_file = tmp_path / ".DriftBeacon.yml"  # type: ignore[operator]
    config_file.write_text("report:\n  top_findings: 0\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="top_findings"):
        load_config(repository_path=tmp_path, config_path=config_file)


def test_yaml_parser_rejects_bad_indentation() -> None:
    with pytest.raises(ConfigError):
        parse_simple_yaml("report:\n    top_findings: 3\n  bad: true\n")
