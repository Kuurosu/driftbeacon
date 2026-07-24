from __future__ import annotations

from driftbeacon.scanners.checkov import execution_from_json_output


def test_scanner_failure_for_malformed_json(tmp_path: object) -> None:
    execution = execution_from_json_output("{not valid json", tmp_path)  # type: ignore[arg-type]

    assert execution.status.status == "failed"
    assert "malformed JSON" in execution.status.message
    assert execution.findings == []
