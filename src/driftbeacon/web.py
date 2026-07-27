"""Public web scan MVP for DriftBeacon."""

# ruff: noqa: E501

from __future__ import annotations

import html
import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse
from wsgiref.simple_server import make_server
from wsgiref.types import StartResponse, WSGIEnvironment

from .analysis import clone_repository, detect_supported_infrastructure_files
from .comparison import compare_scans
from .config import load_config
from .models import ComparisonSummary, Finding, ScanResult
from .prioritise import prioritise_findings
from .redaction import redact_secrets
from .reporting import generate_report, prioritised_finding_details
from .scanners.base import safe_walk
from .storage import LocalStorage

ScanStatus = Literal["queued", "cloning", "scanning", "rendering", "completed", "failed"]
AnalyticsProperties = dict[str, str | int | float | bool | None]
AnalyticsRecorder = Callable[[str, AnalyticsProperties], None]

_GITHUB_OWNER_REPO = re.compile(r"^[A-Za-z0-9_.-]+$")
_SCAN_ID = re.compile(r"^[a-f0-9]{12}$")


@dataclass(frozen=True, slots=True)
class WebConfig:
    """Configuration for the public web scan MVP."""

    output_dir: Path = Path(".driftbeacon-web")
    max_concurrent_scans: int = 2
    scanner_timeout_seconds: int = 300
    clone_timeout_seconds: int = 120
    scan_retention_seconds: int = 86_400
    scans_per_hour: int = 10
    max_repository_files: int = 8_000
    max_repository_bytes: int = 150 * 1024 * 1024
    top_findings: int = 3

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> WebConfig:
        source = env or dict(os.environ)
        return cls(
            output_dir=Path(source.get("DRIFTBEACON_WEB_OUTPUT_DIR", ".driftbeacon-web")),
            max_concurrent_scans=_env_int(source, "DRIFTBEACON_WEB_MAX_CONCURRENT_SCANS", 2),
            scanner_timeout_seconds=_env_int(source, "DRIFTBEACON_WEB_SCANNER_TIMEOUT", 300),
            clone_timeout_seconds=_env_int(source, "DRIFTBEACON_WEB_CLONE_TIMEOUT", 120),
            scan_retention_seconds=_env_int(source, "DRIFTBEACON_WEB_RETENTION_SECONDS", 86_400),
            scans_per_hour=_env_int(source, "DRIFTBEACON_WEB_SCANS_PER_HOUR", 10),
            max_repository_files=_env_int(source, "DRIFTBEACON_WEB_MAX_REPOSITORY_FILES", 8_000),
            max_repository_bytes=_env_int(
                source,
                "DRIFTBEACON_WEB_MAX_REPOSITORY_BYTES",
                150 * 1024 * 1024,
            ),
            top_findings=_env_int(source, "DRIFTBEACON_WEB_TOP_FINDINGS", 3),
        ).validate()

    def validate(self) -> WebConfig:
        if self.max_concurrent_scans < 1:
            raise ValueError("web max_concurrent_scans must be at least 1")
        if self.scanner_timeout_seconds < 1 or self.clone_timeout_seconds < 1:
            raise ValueError("web timeouts must be at least 1 second")
        if self.scan_retention_seconds < 60:
            raise ValueError("web scan_retention_seconds must be at least 60")
        if self.scans_per_hour < 1:
            raise ValueError("web scans_per_hour must be at least 1")
        if self.max_repository_files < 1:
            raise ValueError("web max_repository_files must be at least 1")
        if self.max_repository_bytes < 1:
            raise ValueError("web max_repository_bytes must be at least 1")
        if self.top_findings < 1:
            raise ValueError("web top_findings must be at least 1")
        if self.output_dir.exists() and self.output_dir.is_symlink():
            raise ValueError("web output_dir must not be a symlink")
        return self


@dataclass(slots=True)
class WebScanState:
    """In-memory and serializable status for one public web scan."""

    scan_id: str
    repository_url: str
    status: ScanStatus
    message: str
    progress: int
    created_at: datetime
    updated_at: datetime
    client_id: str
    repository: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    report_path: Path | None = None
    scan_path: Path | None = None
    comparison_path: Path | None = None
    web_report_path: Path | None = None
    error: str | None = None

    @property
    def done(self) -> bool:
        return self.status in {"completed", "failed"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "repository_url": self.repository_url,
            "status": self.status,
            "message": self.message,
            "progress": self.progress,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "repository": self.repository,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "report_url": f"/scans/{self.scan_id}" if self.status == "completed" else None,
            "markdown_url": f"/scans/{self.scan_id}/report.md"
            if self.report_path is not None
            else None,
            "json_url": f"/scans/{self.scan_id}/current-scan.json"
            if self.scan_path is not None
            else None,
            "comparison_url": f"/scans/{self.scan_id}/comparison-summary.json"
            if self.comparison_path is not None
            else None,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class WebScanArtifacts:
    """Files and metadata produced by one web scan."""

    repository: str
    branch: str
    commit_sha: str
    report_path: Path
    scan_path: Path
    comparison_path: Path
    web_report_path: Path


class NoOpAnalytics:
    """No-op analytics boundary for the public MVP."""

    def record(self, event: str, properties: AnalyticsProperties) -> None:
        _ = event, properties


class PublicGitHubRepositoryProvider:
    """Validate and clone public GitHub repositories."""

    def normalise_url(self, repository_url: str) -> str:
        return normalise_public_github_url(repository_url)

    def clone(self, repository_url: str, clone_path: Path, *, timeout_seconds: int) -> None:
        clone_repository(repository_url, clone_path, timeout_seconds=timeout_seconds)


ScanRunner = Callable[
    [str, str, Path, WebConfig, PublicGitHubRepositoryProvider, Callable[[ScanStatus, str, int], None]],
    WebScanArtifacts,
]


class WebScanService:
    """Background scan coordinator used by the WSGI routes."""

    def __init__(
        self,
        config: WebConfig | None = None,
        *,
        analytics: NoOpAnalytics | None = None,
        provider: PublicGitHubRepositoryProvider | None = None,
        runner: ScanRunner | None = None,
        synchronous: bool = False,
    ) -> None:
        self.config = (config or WebConfig.from_environment()).validate()
        self.output_dir = self.config.output_dir.expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.output_dir.is_symlink():
            raise ValueError("web output_dir must not be a symlink")
        self.scan_root = self.output_dir / "scans"
        self.scan_root.mkdir(parents=True, exist_ok=True)
        self.analytics = analytics or NoOpAnalytics()
        self.provider = provider or PublicGitHubRepositoryProvider()
        self.runner = runner or run_public_repository_scan
        self.synchronous = synchronous
        self._lock = threading.Lock()
        self._scans: dict[str, WebScanState] = {}
        self._submissions: dict[str, list[float]] = defaultdict(list)
        self._semaphore = threading.BoundedSemaphore(self.config.max_concurrent_scans)

    def submit(self, repository_url: str, *, client_id: str = "anonymous") -> WebScanState:
        normalised_url = self.provider.normalise_url(repository_url)
        self._enforce_rate_limit(client_id)
        self.cleanup_old_scans()
        scan_id = uuid.uuid4().hex[:12]
        now = datetime.now(UTC)
        state = WebScanState(
            scan_id=scan_id,
            repository_url=normalised_url,
            status="queued",
            message="Queued for analysis.",
            progress=5,
            created_at=now,
            updated_at=now,
            client_id=client_id,
        )
        with self._lock:
            self._scans[scan_id] = state
        self.analytics.record("scan_submitted", {"scan_id": scan_id})
        if self.synchronous:
            self._run(scan_id, normalised_url)
        else:
            thread = threading.Thread(
                target=self._run,
                args=(scan_id, normalised_url),
                name=f"driftbeacon-scan-{scan_id}",
                daemon=True,
            )
            thread.start()
        return self.get(scan_id) or state

    def get(self, scan_id: str) -> WebScanState | None:
        if not _SCAN_ID.match(scan_id):
            return None
        with self._lock:
            return self._scans.get(scan_id)

    def cleanup_old_scans(self) -> None:
        cutoff = time.time() - self.config.scan_retention_seconds
        for path in self.scan_root.iterdir() if self.scan_root.exists() else []:
            try:
                if not path.is_dir() or path.is_symlink() or path.stat().st_mtime >= cutoff:
                    continue
                shutil.rmtree(path, ignore_errors=True)
            except OSError:
                continue

    def _run(self, scan_id: str, repository_url: str) -> None:
        with self._semaphore:
            try:
                self.analytics.record("scan_started", {"scan_id": scan_id})
                artifacts = self.runner(
                    scan_id,
                    repository_url,
                    self.scan_root / scan_id,
                    self.config,
                    self.provider,
                    lambda status, message, progress: self._update(
                        scan_id,
                        status,
                        message,
                        progress,
                    ),
                )
            except Exception as exc:
                self._update(
                    scan_id,
                    "failed",
                    "Scan failed.",
                    100,
                    error=redact_secrets(str(exc)),
                )
                self.analytics.record("scan_failed", {"scan_id": scan_id})
                return
            self._update(
                scan_id,
                "completed",
                "Report ready.",
                100,
                repository=artifacts.repository,
                branch=artifacts.branch,
                commit_sha=artifacts.commit_sha,
                report_path=artifacts.report_path,
                scan_path=artifacts.scan_path,
                comparison_path=artifacts.comparison_path,
                web_report_path=artifacts.web_report_path,
            )
            self.analytics.record("scan_completed", {"scan_id": scan_id})

    def _update(
        self,
        scan_id: str,
        status: ScanStatus,
        message: str,
        progress: int,
        *,
        repository: str | None = None,
        branch: str | None = None,
        commit_sha: str | None = None,
        report_path: Path | None = None,
        scan_path: Path | None = None,
        comparison_path: Path | None = None,
        web_report_path: Path | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            state = self._scans[scan_id]
            state.status = status
            state.message = message
            state.progress = max(0, min(100, progress))
            state.updated_at = datetime.now(UTC)
            state.repository = repository or state.repository
            state.branch = branch or state.branch
            state.commit_sha = commit_sha or state.commit_sha
            state.report_path = report_path or state.report_path
            state.scan_path = scan_path or state.scan_path
            state.comparison_path = comparison_path or state.comparison_path
            state.web_report_path = web_report_path or state.web_report_path
            state.error = error or state.error

    def _enforce_rate_limit(self, client_id: str) -> None:
        now = time.time()
        window_start = now - 3600
        submissions = [
            timestamp for timestamp in self._submissions[client_id] if timestamp >= window_start
        ]
        if len(submissions) >= self.config.scans_per_hour:
            self.analytics.record("scan_rejected", {"reason": "rate_limit"})
            raise ValueError("Too many scans from this client. Please try again later.")
        submissions.append(now)
        self._submissions[client_id] = submissions


class DriftBeaconWebApp:
    """Small WSGI application for the public web MVP."""

    def __init__(self, service: WebScanService | None = None) -> None:
        self.service = service or WebScanService()

    def __call__(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        try:
            if method == "GET" and path == "/":
                self.service.analytics.record("landing_page_viewed", {})
                return self._html(start_response, render_home_page())
            if method == "POST" and path == "/scans":
                return self._submit(environ, start_response)
            if method == "GET" and path.startswith("/api/scans/"):
                return self._api_scan(path, start_response)
            if method == "GET" and path.startswith("/scans/"):
                return self._scan_page(path, start_response)
        except ValueError as exc:
            return self._html(start_response, render_home_page(error=str(exc)), status="400 Bad Request")
        return self._html(start_response, render_not_found_page(), status="404 Not Found")

    def _submit(
        self,
        environ: WSGIEnvironment,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        if length > 4096:
            raise ValueError("Submission is too large.")
        body = environ["wsgi.input"].read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        repository_url = (form.get("repository_url") or [""])[0].strip()
        client_id = str(environ.get("REMOTE_ADDR") or "anonymous")
        try:
            state = self.service.submit(repository_url, client_id=client_id)
        except ValueError as exc:
            self.service.analytics.record("scan_rejected", {"reason": "validation"})
            return self._html(
                start_response,
                render_home_page(error=str(exc), repository_url=repository_url),
                status="400 Bad Request",
            )
        start_response("303 See Other", [("Location", f"/scans/{state.scan_id}")])
        return [b""]

    def _api_scan(self, path: str, start_response: StartResponse) -> Iterable[bytes]:
        scan_id = path.removeprefix("/api/scans/").strip("/")
        state = self.service.get(scan_id)
        if state is None:
            start_response("404 Not Found", [("Content-Type", "application/json")])
            return [b'{"error":"scan not found"}']
        payload = json.dumps(state.to_dict(), sort_keys=True).encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
            ],
        )
        return [payload]

    def _scan_page(self, path: str, start_response: StartResponse) -> Iterable[bytes]:
        parts = [part for part in path.split("/") if part]
        if len(parts) < 2:
            return self._html(start_response, render_not_found_page(), status="404 Not Found")
        scan_id = parts[1]
        state = self.service.get(scan_id)
        if state is None:
            return self._html(start_response, render_not_found_page(), status="404 Not Found")
        if len(parts) == 3:
            return self._artifact(parts[2], state, start_response)
        if state.status != "completed":
            return self._html(start_response, render_progress_page(state))
        if state.web_report_path and state.web_report_path.exists():
            self.service.analytics.record("report_viewed", {"scan_id": scan_id})
            return self._html(start_response, state.web_report_path.read_text(encoding="utf-8"))
        return self._html(
            start_response,
            render_error_page("The scan completed, but the web report could not be loaded."),
            status="500 Internal Server Error",
        )

    def _artifact(
        self,
        artifact: str,
        state: WebScanState,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        mapping = {
            "report.md": (state.report_path, "text/markdown; charset=utf-8"),
            "current-scan.json": (state.scan_path, "application/json; charset=utf-8"),
            "comparison-summary.json": (
                state.comparison_path,
                "application/json; charset=utf-8",
            ),
        }
        target, content_type = mapping.get(artifact, (None, "text/plain"))
        if target is None or not target.exists():
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"artifact not found"]
        start_response("200 OK", [("Content-Type", content_type)])
        return [target.read_bytes()]

    def _html(
        self,
        start_response: StartResponse,
        body: str,
        *,
        status: str = "200 OK",
    ) -> Iterable[bytes]:
        payload = body.encode("utf-8")
        start_response(
            status,
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(payload))),
                ("Cache-Control", "no-store"),
            ],
        )
        return [payload]


def create_app(service: WebScanService | None = None) -> DriftBeaconWebApp:
    """Create the public web MVP application."""

    return DriftBeaconWebApp(service)


def run_web_server(host: str, port: int, config: WebConfig | None = None) -> None:
    """Run the local public web scan MVP."""

    app = create_app(WebScanService(config))
    with make_server(host, port, app) as server:
        print(f"DriftBeacon web listening on http://{host}:{port}")
        server.serve_forever()


def run_public_repository_scan(
    scan_id: str,
    repository_url: str,
    output_dir: Path,
    config: WebConfig,
    provider: PublicGitHubRepositoryProvider,
    progress: Callable[[ScanStatus, str, int], None],
) -> WebScanArtifacts:
    """Clone a public repository and run the shared DriftBeacon analysis engine."""

    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise ValueError("scan output directory must not be a symlink")
    temp_root = Path(tempfile.mkdtemp(prefix="driftbeacon-web-"))
    clone_path = temp_root / "repository"
    try:
        progress("cloning", "Cloning public GitHub repository.", 20)
        provider.clone(repository_url, clone_path, timeout_seconds=config.clone_timeout_seconds)
        _enforce_repository_limits(clone_path, config)
        supported = detect_supported_infrastructure_files(clone_path)
        if not supported:
            progress("scanning", "No supported infrastructure files found; recording coverage.", 45)
        else:
            progress("scanning", f"Detected {len(supported)} supported files. Running scanners.", 45)
        scan_config = load_config(
            repository_path=clone_path,
            output_dir=output_dir,
            no_slack=True,
        )
        scan, _executions = run_scan_with_engine(
            scan_config,
            timeout_seconds=config.scanner_timeout_seconds,
        )
        comparison = compare_scans(scan, None)
        top_items = prioritise_findings(
            scan.findings,
            limit=config.top_findings,
            production_patterns=scan_config.production_patterns,
        )
        progress("rendering", "Rendering report.", 85)
        markdown_report = generate_report(
            scan,
            comparison,
            top_items=top_items,
            production_patterns=scan_config.production_patterns,
            top_limit=config.top_findings,
        )
        storage = LocalStorage(output_dir)
        scan_path = storage.save_current_scan(scan)
        comparison_path = storage.save_comparison(comparison.to_dict())
        report_path = storage.save_report(markdown_report)
        web_report_path = storage.save_report(
            render_repository_report_page(scan, comparison),
            filename="web-report.html",
        )
        _write_state_file(
            output_dir,
            {
                "scan_id": scan_id,
                "repository_url": repository_url,
                "repository": scan.repository,
                "branch": scan.branch,
                "commit_sha": scan.commit_sha,
                "completed_at": datetime.now(UTC).isoformat(),
            },
        )
        return WebScanArtifacts(
            repository=scan.repository,
            branch=scan.branch,
            commit_sha=scan.commit_sha,
            report_path=report_path,
            scan_path=scan_path,
            comparison_path=comparison_path,
            web_report_path=web_report_path,
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def run_scan_with_engine(scan_config: Any, *, timeout_seconds: int) -> tuple[ScanResult, list[Any]]:
    """Isolated import boundary for tests and future worker implementations."""

    from .scan import run_scan

    return run_scan(scan_config, timeout_seconds=timeout_seconds)


def normalise_public_github_url(repository_url: str) -> str:
    """Validate and normalize an HTTPS public GitHub repository URL."""

    raw = repository_url.strip()
    if not raw:
        raise ValueError("Paste a public GitHub repository URL.")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError("Only HTTPS GitHub repository URLs are supported in the public MVP.")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Repository URLs must not include credentials, query strings or fragments.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("Use a repository URL such as https://github.com/owner/repo.")
    owner, repo = parts
    repo = repo.removesuffix(".git")
    if not owner or not repo or not _GITHUB_OWNER_REPO.match(owner) or not _GITHUB_OWNER_REPO.match(repo):
        raise ValueError("GitHub owner and repository names contain unsupported characters.")
    return f"https://github.com/{owner}/{repo}.git"


def render_home_page(*, error: str | None = None, repository_url: str = "") -> str:
    """Render the acquisition homepage."""

    error_html = (
        f'<p class="alert" role="alert">{_escape(error)}</p>'
        if error is not None
        else ""
    )
    return _page(
        "Know exactly what to fix next to reduce production risk",
        f"""
        <main>
          <section class="hero">
            <p class="eyebrow">Production-risk prioritisation for public repositories</p>
            <h1>Know exactly what to fix next to reduce production risk.</h1>
            <p class="lead"><strong>Paste a public GitHub repository</strong> and receive a
            prioritised Production Health report.</p>
            <p class="lead">DriftBeacon analyses infrastructure and dependency findings, removes
            test and example noise, and turns the remaining production risks into a prioritised
            engineering action plan.</p>
            <form class="scan-form" method="post" action="/scans">
              <label for="repository_url">Public GitHub repository URL</label>
              <div class="form-row">
                <input id="repository_url" name="repository_url" type="url"
                  placeholder="https://github.com/owner/repository"
                  value="{_escape(repository_url)}" required>
                <button type="submit">Analyse repository</button>
              </div>
              {error_html}
            </form>
          </section>

          <section class="band">
            <h2>How it works</h2>
            <div class="steps">
              <article><strong>1. Paste a repository</strong><span>No workflow file or install in
              the scanned repository.</span></article>
              <article><strong>2. DriftBeacon analyses it</strong><span>Checkov and Trivy findings
              are normalised, deduplicated and separated by production relevance.</span></article>
              <article><strong>3. Review what to fix first</strong><span>The report leads with
              Production Health and ranked engineering actions.</span></article>
            </div>
          </section>

          <section class="split">
            <div>
              <h2>Different from ordinary scanners</h2>
              <p>Ordinary scanners tell you everything they found. DriftBeacon helps you decide
              what your team should fix next.</p>
            </div>
            <div>
              <h2>Continuous monitoring later</h2>
              <p>Private repository monitoring, scheduled scans, saved history and team workflows
              are planned paid capabilities. Billing is not part of this public MVP.</p>
            </div>
          </section>

          <section class="methodology-note">
            <h2>What Production Health means</h2>
            <p>Production Health is a prioritisation and trend metric based on findings detected by
            completed scanners. It does not prove that a repository or production environment is
            secure.</p>
          </section>
        </main>
        """,
    )


def render_progress_page(state: WebScanState) -> str:
    """Render queued/running/failed scan states."""

    failure = (
        f"<p class=\"alert\" role=\"alert\">{_escape(state.error or state.message)}</p>"
        if state.status == "failed"
        else ""
    )
    polling = (
        """
        <script>
          async function pollScan() {
            const response = await fetch(window.location.pathname.replace('/scans/', '/api/scans/'));
            if (!response.ok) return;
            const data = await response.json();
            document.querySelector('[data-status]').textContent = data.status;
            document.querySelector('[data-message]').textContent = data.message;
            document.querySelector('progress').value = data.progress;
            if (data.status === 'completed' || data.status === 'failed') {
              window.location.reload();
            }
          }
          setInterval(pollScan, 2000);
        </script>
        """
        if state.status not in {"completed", "failed"}
        else ""
    )
    return _page(
        "DriftBeacon scan progress",
        f"""
        <main class="narrow">
          <a class="back-link" href="/">Start another scan</a>
          <section class="panel">
            <p class="eyebrow">Repository analysis</p>
            <h1>{_escape(state.repository_url)}</h1>
            <dl class="status-grid">
              <div><dt>Status</dt><dd data-status>{_escape(state.status)}</dd></div>
              <div><dt>Message</dt><dd data-message>{_escape(state.message)}</dd></div>
            </dl>
            <progress max="100" value="{state.progress}"></progress>
            {failure}
          </section>
        </main>
        {polling}
        """,
    )


def render_repository_report_page(scan: ScanResult, comparison: ComparisonSummary) -> str:
    """Render a web report that emphasizes Production Health and next actions."""

    summary = scan.summary
    top_items = prioritise_findings(_web_priority_candidates(scan.findings), limit=3)
    priority_cards = "\n".join(
        _priority_card(index, item, comparison.has_baseline)
        for index, item in enumerate(top_items, start=1)
    ) or '<p class="empty">No active findings were detected by completed scanners.</p>'
    scanner_status = "\n".join(
        f"<li><strong>{_escape(status.name.capitalize())}:</strong> "
        f"{_escape(status.status.capitalize())} - {_escape(status.message)}</li>"
        for status in scan.scanner_statuses.values()
    ) or "<li>No scanner status was recorded.</li>"
    source_rows = _breakdown_rows(summary.get("finding_source_breakdown"))
    group_rows = _breakdown_rows(summary.get("directory_group_breakdown"))
    production_health = _score_text(summary.get("production_health_score"))
    production_grade = _grade_text(summary.get("production_grade"))
    overall_health = _score_text(scan.health_score)
    overall_grade = _grade_text(_grade_for_score(scan.health_score))
    provisional = " Provisional grade." if summary.get("production_grade_provisional") is True else ""
    return _page(
        f"DriftBeacon report for {scan.repository}",
        f"""
        <main>
          <a class="back-link" href="/">Analyse another repository</a>
          <section class="report-status">
            <h1>{_escape(scan.repository)}</h1>
            <dl class="status-grid">
              <div><dt>Branch</dt><dd>{_escape(scan.branch)}</dd></div>
              <div><dt>Commit</dt><dd>{_escape(scan.commit_sha[:12])}</dd></div>
              <div><dt>Scan date</dt><dd>{_escape(_date_text(scan.completed_at))}</dd></div>
              <div><dt>Baseline</dt><dd>{_escape(_baseline_text(comparison))}</dd></div>
              <div><dt>Scanner coverage</dt><dd>{_escape(_coverage_text(summary))}</dd></div>
            </dl>
          </section>

          <section class="health-focus">
            <div>
              <p class="eyebrow">Primary metric</p>
              <h2>Production Health</h2>
              <p class="score">{_escape(production_health)}</p>
              <p class="grade">Grade {_escape(production_grade)}{_escape(provisional)}</p>
              <p>{_escape(str(summary.get("production_score_reason", "No production score reason recorded.")))}</p>
            </div>
            <aside>
              <h2>Overall Health</h2>
              <p class="support-score">{_escape(overall_health)} / Grade {_escape(overall_grade)}</p>
              <p>Overall Health includes all analysed actionable findings. Production Health is
              shown first because this report is designed to prioritise production risk.</p>
            </aside>
          </section>

          <section class="methodology-note">
            <h2>Methodology</h2>
            <p>Production Health is a prioritisation and trend metric based on findings detected by
            completed scanners. It does not prove that a repository or production environment is
            secure. Path classification is heuristic and should be reviewed.</p>
          </section>

          <section>
            <h2>What to fix next</h2>
            <p class="unavailable">This web report shows production-relevant findings first when
            they exist, then applies DriftBeacon's shared prioritisation and explanation logic.</p>
            <div class="priority-list">{priority_cards}</div>
          </section>

          <section class="impact">
            <h2>Expected impact</h2>
            <p>Current production-relevant actionable findings: <strong>{summary.get("production_actionable_findings", 0)}</strong>.</p>
            <p>Projected risk reduction, estimated effort and projected Production Health are
            unavailable in this MVP because remediation-impact simulation has not been implemented.
            DriftBeacon will only show those values after they are calculated from the real scoring
            model.</p>
          </section>

          <section class="evidence">
            <h2>Supporting evidence</h2>
            <div class="evidence-grid">
              <article>
                <h3>Severity distribution</h3>
                <ul>
                  <li>Critical: {summary.get("production_critical_findings", 0)} production / {_severity_count(scan, "critical")} total</li>
                  <li>High: {summary.get("production_high_findings", 0)} production / {_severity_count(scan, "high")} total</li>
                  <li>Medium: {summary.get("production_medium_findings", 0)} production / {_severity_count(scan, "medium")} total</li>
                  <li>Low: {summary.get("production_low_findings", 0)} production / {_severity_count(scan, "low")} total</li>
                </ul>
              </article>
              <article>
                <h3>Finding sources</h3>
                {_table(source_rows, "Source")}
              </article>
              <article>
                <h3>Directory groups</h3>
                {_table(group_rows, "Directory group")}
              </article>
              <article>
                <h3>Scanner status</h3>
                <ul>{scanner_status}</ul>
              </article>
            </div>
          </section>
        </main>
        """,
    )


def render_error_page(message: str) -> str:
    return _page("DriftBeacon error", f"<main class=\"narrow\"><p class=\"alert\">{_escape(message)}</p></main>")


def render_not_found_page() -> str:
    return _page("Not found", '<main class="narrow"><h1>Not found</h1></main>')


def _priority_card(index: int, item: Any, has_baseline: bool) -> str:
    details = prioritised_finding_details(item, has_baseline=has_baseline)
    production_relevance = (
        "Production path" if details["directory_group"] == "production" else details["directory_group"]
    )
    return f"""
    <article class="priority-card">
      <p class="eyebrow">Priority {index}</p>
      <h3>{_escape(details["title"])}</h3>
      <dl>
        <div><dt>Severity</dt><dd>{_escape(details["severity"])}</dd></div>
        <div><dt>Production relevance</dt><dd>{_escape(production_relevance)}</dd></div>
        <div><dt>Location</dt><dd>{_escape(details["location"])}</dd></div>
        <div><dt>Finding source</dt><dd>{_escape(details["finding_source"])}</dd></div>
        <div><dt>Status</dt><dd>{_escape(details["status"])}</dd></div>
        <div><dt>Confidence</dt><dd>Scanner-reported finding</dd></div>
      </dl>
      <p><strong>Why it matters:</strong> {_escape(details["why"])}</p>
      <p><strong>Recommended action:</strong> {_escape(details["action"])}</p>
      <p class="unavailable">Estimated effort, projected risk reduction, projected Production
      Health and related findings resolved are unavailable until impact simulation is implemented.</p>
    </article>
    """


def _web_priority_candidates(findings: list[Finding]) -> list[Finding]:
    active = [finding for finding in findings if finding.status != "resolved"]
    production = [finding for finding in active if finding.directory_group == "production"]
    return production or active


def _enforce_repository_limits(repository_path: Path, config: WebConfig) -> None:
    files = safe_walk(repository_path)
    if len(files) > config.max_repository_files:
        raise ValueError(
            f"repository exceeds the public MVP file limit of {config.max_repository_files}"
        )
    total = 0
    for path in files:
        try:
            total += path.stat().st_size
        except OSError:
            continue
        if total > config.max_repository_bytes:
            limit_mb = round(config.max_repository_bytes / (1024 * 1024))
            raise ValueError(f"repository exceeds the public MVP size limit of {limit_mb} MB")


def _write_state_file(output_dir: Path, data: dict[str, Any]) -> None:
    path = output_dir / "scan-state.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _breakdown_rows(raw: object) -> list[tuple[str, int, int, int, int, int]]:
    if not isinstance(raw, dict):
        return []
    rows: list[tuple[str, int, int, int, int, int]] = []
    for key, value in sorted(raw.items()):
        if isinstance(value, dict):
            rows.append(
                (
                    str(key).replace("_", " ").title(),
                    _int_value(value.get("critical")),
                    _int_value(value.get("high")),
                    _int_value(value.get("medium")),
                    _int_value(value.get("low")),
                    _int_value(value.get("total_actionable")),
                )
            )
    return rows


def _table(rows: list[tuple[str, int, int, int, int, int]], label: str) -> str:
    if not rows:
        return "<p>No findings recorded.</p>"
    body = "\n".join(
        f"<tr><td>{_escape(name)}</td><td>{critical}</td><td>{high}</td>"
        f"<td>{medium}</td><td>{low}</td><td>{total}</td></tr>"
        for name, critical, high, medium, low, total in rows
    )
    return f"""
    <table>
      <thead><tr><th>{_escape(label)}</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(title)} - DriftBeacon</title>
  <style>{_css()}</style>
</head>
<body>
  <header class="site-header"><a href="/">DriftBeacon</a><span>Production Health reports</span></header>
  {body}
</body>
</html>
"""


def _css() -> str:
    return """
    :root { color-scheme: light; --ink:#17201a; --muted:#5a675f; --line:#d8dfd9;
      --paper:#f8faf7; --panel:#ffffff; --accent:#176b56; --accent-2:#b04428; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color:var(--ink); background:var(--paper); line-height:1.5; }
    .site-header { display:flex; justify-content:space-between; align-items:center; padding:18px clamp(18px,4vw,48px);
      border-bottom:1px solid var(--line); background:#fff; }
    .site-header a { color:var(--ink); text-decoration:none; font-weight:800; }
    .site-header span, .eyebrow, dt { color:var(--muted); font-size:0.86rem; }
    main { max-width:1120px; margin:0 auto; padding:34px clamp(18px,4vw,48px) 64px; }
    .narrow { max-width:760px; }
    .hero { padding:52px 0 38px; max-width:850px; }
    h1 { font-size:clamp(2.2rem,5vw,4.7rem); line-height:1; margin:10px 0 18px; letter-spacing:0; }
    h2 { font-size:1.55rem; margin:0 0 14px; }
    h3 { margin:0 0 12px; font-size:1.08rem; }
    .lead { font-size:1.2rem; max-width:760px; color:#2d3a33; }
    .scan-form { margin-top:28px; }
    label { display:block; font-weight:700; margin-bottom:8px; }
    .form-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:10px; max-width:760px; }
    input { width:100%; min-height:46px; border:1px solid var(--line); border-radius:8px; padding:0 14px; font:inherit; }
    button { min-height:46px; border:0; border-radius:8px; padding:0 18px; font-weight:800; color:#fff; background:var(--accent); cursor:pointer; }
    .band, .split, .methodology-note, .panel, .report-status, .health-focus, .impact, .evidence {
      border-top:1px solid var(--line); padding:28px 0; }
    .steps, .split, .health-focus, .evidence-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:18px; }
    .split, .health-focus { grid-template-columns:1fr 1fr; }
    article, .health-focus aside, .health-focus > div { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; }
    .steps article span { display:block; color:var(--muted); margin-top:6px; }
    .status-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin:18px 0 0; }
    .status-grid div { border:1px solid var(--line); border-radius:8px; padding:12px; background:#fff; }
    dd { margin:4px 0 0; font-weight:750; overflow-wrap:anywhere; }
    progress { width:100%; height:18px; margin-top:18px; }
    .score { font-size:4.2rem; line-height:1; font-weight:900; margin:8px 0; color:var(--accent); }
    .support-score { font-size:1.55rem; font-weight:800; }
    .grade { font-weight:800; color:var(--accent-2); }
    .priority-list { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }
    .priority-card dl { display:grid; gap:8px; margin:12px 0; }
    .priority-card dl div { border-top:1px solid var(--line); padding-top:8px; }
    .unavailable, .empty { color:var(--muted); font-size:0.92rem; }
    .alert { border:1px solid #c65a42; background:#fff0ec; color:#7b2718; border-radius:8px; padding:12px; }
    .back-link { color:var(--accent); font-weight:800; text-decoration:none; }
    table { width:100%; border-collapse:collapse; font-size:0.9rem; }
    th, td { text-align:left; border-bottom:1px solid var(--line); padding:7px 5px; vertical-align:top; }
    @media (max-width:850px) {
      .form-row, .steps, .split, .health-focus, .priority-list, .evidence-grid, .status-grid { grid-template-columns:1fr; }
      h1 { font-size:2.4rem; }
      .score { font-size:3.2rem; }
      .site-header { align-items:flex-start; gap:8px; flex-direction:column; }
    }
    """


def _score_text(score: object) -> str:
    return f"{score}/100" if isinstance(score, int) else "Not scored"


def _grade_text(grade: object) -> str:
    return str(grade or "N/A")


def _grade_for_score(score: int | None) -> str:
    if score is None:
        return "N/A"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _coverage_text(summary: dict[str, Any]) -> str:
    coverage = str(summary.get("production_coverage_state") or summary.get("coverage_state", "unknown"))
    labels = {
        "complete_coverage": "Complete",
        "partial_coverage": "Partial coverage",
        "not_scored_no_supported_files": "Not scored: no supported files",
        "not_scored_all_scanners_failed": "Not scored: scanners failed",
    }
    return labels.get(coverage, coverage)


def _baseline_text(comparison: ComparisonSummary) -> str:
    if not comparison.has_baseline:
        return "Initial baseline"
    if comparison.health_score_change is None:
        return "Comparison available"
    if comparison.health_score_change > 0:
        return f"Overall Health up {comparison.health_score_change} points"
    if comparison.health_score_change < 0:
        return f"Overall Health down {abs(comparison.health_score_change)} points"
    return "Overall Health unchanged"


def _date_text(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "unknown"


def _severity_count(scan: ScanResult, severity: str) -> int:
    return sum(1 for finding in scan.findings if finding.status != "resolved" and finding.severity == severity)


def _int_value(value: object) -> int:
    return value if isinstance(value, int) else 0


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc
