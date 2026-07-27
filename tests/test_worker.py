from __future__ import annotations

from pathlib import Path

from test_web import _fake_runner, _web_config

from driftbeacon.web import (
    FileReportStore,
    PublicGitHubRepositoryProvider,
    WebConfig,
    WebScanArtifacts,
    WebScanFailure,
    WebScanService,
)
from driftbeacon.worker import WebScanWorker, WorkerConfig


def _worker_config() -> WorkerConfig:
    return WorkerConfig(worker_id="test-worker", poll_interval_seconds=0.1, stale_seconds=60)


def test_worker_processes_one_queued_scan_and_stores_report(tmp_path: Path) -> None:
    config = _web_config(tmp_path)
    service = WebScanService(config)
    submitted = service.submit("https://github.com/owner/repo")
    worker = WebScanWorker(config, _worker_config(), runner=_fake_runner)

    assert worker.process_once() is True

    state = service.get(submitted.scan_id)
    assert state is not None
    assert state.status == "completed"
    assert state.worker_id == "test-worker"
    assert state.report_reference == submitted.scan_id
    assert service.report_store.load(submitted.scan_id) is not None
    assert not (config.working_dir / submitted.scan_id).exists()


def test_worker_once_processes_at_most_one_scan(tmp_path: Path) -> None:
    config = _web_config(tmp_path)
    service = WebScanService(config)
    first = service.submit("https://github.com/owner/one")
    second = service.submit("https://github.com/owner/two")
    worker = WebScanWorker(config, _worker_config(), runner=_fake_runner)

    assert worker.process_once() is True

    first_state = service.get(first.scan_id)
    second_state = service.get(second.scan_id)
    assert first_state is not None
    assert second_state is not None
    assert first_state.status == "completed"
    assert second_state.status == "queued"


def test_worker_failed_clone_records_safe_error_and_cleans_workspace(tmp_path: Path) -> None:
    def failing_runner(
        scan_id: str,
        repository_url: str,
        output_dir: Path,
        _config: WebConfig,
        _provider: PublicGitHubRepositoryProvider,
        _report_store: FileReportStore,
        _progress: object,
    ) -> WebScanArtifacts:
        output_dir.mkdir(parents=True, exist_ok=True)
        _ = scan_id, repository_url
        raise WebScanFailure(
            "clone_timeout",
            "Git clone exceeded the public demo time limit.",
            detail="/private/tmp/workspace token=secret",
        )

    config = _web_config(tmp_path)
    service = WebScanService(config)
    submitted = service.submit("https://github.com/owner/repo")
    worker = WebScanWorker(config, _worker_config(), runner=failing_runner)

    assert worker.process_once() is True

    state = service.get(submitted.scan_id)
    assert state is not None
    assert state.status == "failed"
    assert state.error_code == "clone_timeout"
    assert state.safe_error_message == "Git clone exceeded the public demo time limit."
    assert not (config.working_dir / submitted.scan_id).exists()


def test_worker_returns_false_when_no_scan_is_queued(tmp_path: Path) -> None:
    worker = WebScanWorker(_web_config(tmp_path), _worker_config(), runner=_fake_runner)

    assert worker.process_once() is False
