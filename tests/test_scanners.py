from __future__ import annotations

from pathlib import Path

from driftbeacon.models import ScannerStatus
from driftbeacon.scanners import checkov as checkov_module
from driftbeacon.scanners import trivy as trivy_module
from driftbeacon.scanners.base import safe_walk
from driftbeacon.scanners.checkov import execution_from_json_output


def test_scanner_failure_for_malformed_json(tmp_path: object) -> None:
    execution = execution_from_json_output("{not valid json", tmp_path)  # type: ignore[arg-type]

    assert execution.status.status == "failed"
    assert "malformed JSON" in execution.status.message
    assert execution.findings == []


def test_safe_walk_skips_driftbeacon_generated_directories(tmp_path: Path) -> None:
    generated = tmp_path / ".driftbeacon-demo"
    generated.mkdir()
    (generated / "state.json").write_text("{}", encoding="utf-8")
    source = tmp_path / "main.tf"
    source.write_text('resource "aws_s3_bucket" "demo" {}', encoding="utf-8")

    walked = {path.relative_to(tmp_path).as_posix() for path in safe_walk(tmp_path)}

    assert "main.tf" in walked
    assert ".driftbeacon-demo/state.json" not in walked


def test_checkov_command_skips_generated_directories(
    tmp_path: Path, monkeypatch: object
) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "demo" {}', encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_run_subprocess(
        args: list[str], **_kwargs: object
    ) -> tuple[str, str, int, ScannerStatus, float]:
        captured["args"] = args
        return (
            '{"results":{"failed_checks":[]}}',
            "",
            0,
            ScannerStatus("checkov", "success", "scanner completed"),
            0.1,
        )

    monkeypatch.setattr(checkov_module, "executable_exists", lambda _name: True)  # type: ignore[attr-defined]
    monkeypatch.setattr(checkov_module, "run_subprocess", fake_run_subprocess)  # type: ignore[attr-defined]

    checkov_module.CheckovScanner().run(tmp_path)

    assert "--skip-download" in captured["args"]
    assert ".driftbeacon" in captured["args"]


def test_trivy_command_skips_generated_directories(tmp_path: Path, monkeypatch: object) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_run_subprocess(
        args: list[str], **_kwargs: object
    ) -> tuple[str, str, int, ScannerStatus, float]:
        captured["args"] = args
        return (
            '{"Results":[]}',
            "",
            0,
            ScannerStatus("trivy", "success", "scanner completed"),
            0.1,
        )

    monkeypatch.setattr(trivy_module, "executable_exists", lambda _name: True)  # type: ignore[attr-defined]
    monkeypatch.setattr(trivy_module, "run_subprocess", fake_run_subprocess)  # type: ignore[attr-defined]

    trivy_module.TrivyScanner().run(tmp_path)

    assert "--skip-check-update" in captured["args"]
    assert ".driftbeacon" in captured["args"]
