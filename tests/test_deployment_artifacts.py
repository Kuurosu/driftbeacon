from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_dockerfile_runs_as_non_root_and_installs_scanners() -> None:
    dockerfile = _read("Dockerfile")

    assert "FROM python:3.12.8-slim-bookworm" in dockerfile
    assert "checkov==${CHECKOV_VERSION}" in dockerfile
    assert "TRIVY_VERSION=0.72.0" in dockerfile
    assert "HOME=/tmp" in dockerfile
    assert "USER driftbeacon" in dockerfile
    assert "SLACK_WEBHOOK_URL" not in dockerfile
    assert "COPY . ." not in dockerfile


def test_compose_separates_web_worker_proxy_and_cleanup() -> None:
    compose = _read("docker-compose.yml")

    assert "web:" in compose
    assert 'command: ["web"' in compose
    assert "worker:" in compose
    assert 'command: ["worker"]' in compose
    assert "proxy:" in compose
    assert "cleanup:" in compose
    assert 'command: ["web-cleanup"' in compose
    assert "DRIFTBEACON_WEB_DATABASE: /data/web.sqlite3" in compose
    assert "DRIFTBEACON_WEB_REPORT_DIR: /data/reports" in compose
    assert "DRIFTBEACON_SCAN_WORK_DIR: /work/scans" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "read_only: true" in compose


def test_worker_has_no_published_ports() -> None:
    compose = _read("docker-compose.yml")
    worker_section = compose.split("  worker:", 1)[1].split("  proxy:", 1)[0]

    assert "ports:" not in worker_section
    assert "Docker socket" not in worker_section


def test_proxy_only_routes_to_web_service() -> None:
    caddyfile = _read("deploy/Caddyfile")

    assert "reverse_proxy web:8080" in caddyfile
    assert "worker" not in caddyfile
    assert "request_body" in caddyfile
    assert "max_size 8KB" in caddyfile
    assert "X-Content-Type-Options" in caddyfile


def test_deployment_docs_avoid_production_readiness_claims() -> None:
    docs = _read("docs/deployment-single-instance.md").lower()

    assert "not production-ready" in docs
    assert "not a complete sandbox" in docs
    assert "aws lightsail" in docs
    assert "ec2" in docs
    assert "rollback" in docs
    assert "sqlite's backup api" in docs
