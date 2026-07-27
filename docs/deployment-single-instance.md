# DriftBeacon Single-Instance Demo Deployment

This guide prepares DriftBeacon for a controlled public demonstration on one host. It is suitable for invited testers, low scan concurrency, one administrator and easy rollback. It is not production-ready, high availability, or complete isolation from malicious repositories.

## 1. Architecture Overview

```text
Internet
  |
  v
Caddy HTTPS reverse proxy
  |
  v
DriftBeacon web container
  |
  v
SQLite job store and report directory on a persistent host volume
  |
  v
DriftBeacon worker container
  |
  v
Temporary per-scan workspace
```

The web process validates public GitHub URLs, creates queued jobs, reads scan state, renders reports and serves safe downloads. It does not clone repositories or run scanners.

The worker process atomically claims queued scans from SQLite, clones the repository into a generated temporary workspace, runs Checkov and Trivy, writes `report.json` and `report.md`, marks the scan terminal and removes the temporary workspace.

## 2. Security Assumptions

- Submitted repositories are untrusted.
- DriftBeacon performs static analysis only.
- The worker does not run `terraform init`, `terraform plan`, `npm install`, `pip install`, `make`, repository scripts or Git hooks.
- Docker hardening reduces risk but is not a complete sandbox.
- Public report URLs are shareable, not private. Anyone with the link can view the report until retention expiry.
- Reports may contain findings from public repositories. Treat generated reports as public-demo data.

## 3. Host Sizing

Start with at least:

- 2 vCPU
- 4 GiB RAM
- 40 GiB SSD
- Ubuntu LTS or another Docker-supported Linux distribution

This is a starting estimate, not a capacity guarantee. Actual memory, CPU and disk needs depend heavily on repository size and scanner behavior.

## 4. AWS Host Options

Preferred simple option: AWS Lightsail instance.

- Predictable monthly pricing model.
- Simple static IP and firewall.
- Simple snapshots.
- Good fit for a one-host controlled demo.

Alternative: a small EC2 instance with an EBS volume.

- More flexible IAM, networking and storage.
- Easier migration path toward a larger AWS architecture.
- Prefer an encrypted EBS volume.
- Enforce IMDSv2 if an instance profile is attached.

Do not attach broad AWS credentials to this host. The worker does not need AWS credentials for public GitHub scans.

## 5. Required Ports

- `80/tcp` for HTTP to HTTPS redirects and ACME validation.
- `443/tcp` for HTTPS.
- Optional `22/tcp` from your admin IP only, or use a managed access method such as Session Manager on EC2.

Do not expose the worker container. Do not expose SQLite, `/data`, `/data/reports`, `/work` or Docker socket access.

## 6. DNS Setup

Create an `A` record for your demo domain, for example:

```text
driftbeacon.example.com -> <public-instance-ip>
```

For local Compose testing, use the default `DRIFTBEACON_SITE_ADDRESS=http://localhost:8080`.

## 7. Docker Prerequisites

Install Docker Engine and the Docker Compose plugin on the host. Verify:

```sh
docker version
docker compose version
```

## 8. Environment Configuration

Copy the example environment file:

```sh
cp .env.example .env
```

For a real demo host, edit:

```sh
DRIFTBEACON_SITE_ADDRESS=driftbeacon.example.com
DRIFTBEACON_WEB_RETENTION_DAYS=7
DRIFTBEACON_WEB_MAX_QUEUED_SCANS=10
DRIFTBEACON_WEB_MAX_SCAN_SECONDS=300
DRIFTBEACON_WEB_MAX_REPOSITORY_BYTES=157286400
DRIFTBEACON_WEB_MAX_REPOSITORY_FILES=8000
DRIFTBEACON_WORKER_POLL_SECONDS=2
DRIFTBEACON_WORKER_STALE_SECONDS=600
```

Do not put secrets, private keys or certificates in `.env`.

## 9. Build

```sh
docker compose build
```

The image installs DriftBeacon, Checkov and a pinned Trivy binary. It runs as a non-root user.

## 10. Start Services

```sh
docker compose up -d
docker compose ps
```

Expected services:

- `proxy`: public HTTPS entrypoint.
- `web`: WSGI app, no scanner execution.
- `worker`: queue consumer, no published ports.

## 11. HTTPS Configuration

Caddy terminates HTTPS when `DRIFTBEACON_SITE_ADDRESS` is a real domain that resolves to the host. Caddy also redirects HTTP to HTTPS for normal domain deployments.

For local testing, the default site address is `http://localhost:8080`.

## 12. Health Checks

```sh
curl -fsS http://127.0.0.1:8080/health/live
curl -fsS http://127.0.0.1:8080/health/ready
```

Readiness checks SQLite schema access and report-store writability. It does not depend on GitHub availability.

## 13. Submit A Test Scan

```sh
DRIFTBEACON_SMOKE_BASE_URL=http://127.0.0.1:8080 \
DRIFTBEACON_SMOKE_REPOSITORY=https://github.com/Kuurosu/driftbeacon \
./scripts/smoke-web.sh
```

The script checks liveness, readiness, submission, terminal status, HTML, Markdown, JSON and obvious internal path leakage.

## 14. Logs

```sh
docker compose logs -f proxy
docker compose logs -f web
docker compose logs -f worker
```

Worker logs include service name, worker ID, scan ID, status transitions, duration and safe failure codes. Logs must not include repository source contents, environment variables, tokens or raw scanner output by default.

## 15. Cleanup

Run cleanup once per day. With Compose:

```sh
docker compose run --rm cleanup
```

Host cron example:

```cron
17 3 * * * cd /opt/driftbeacon && docker compose run --rm cleanup
```

Cleanup is idempotent. It expires old reports, removes stored report JSON/Markdown and removes abandoned work directories.

## 16. Basic Monitoring

Use:

```sh
docker compose ps
docker compose logs --tail=200 web
docker compose logs --tail=200 worker
docker system df
docker volume ls
```

SQLite contains queued, running and failed scan counts. Query from a maintenance shell only:

```sh
docker compose exec web python - <<'PY'
from driftbeacon.web import WebConfig
from driftbeacon.web_storage import SQLiteScanStore
store = SQLiteScanStore(WebConfig.from_environment().database_path)
print({"queued": store.count_queued_scans(), "running": store.count_running_scans()})
PY
```

Do not expose these operational details publicly without authentication.

## 17. Backup

Back up:

- `.env`
- SQLite database
- report directory

Use SQLite's backup API through the container:

```sh
mkdir -p backups
docker compose exec web python - <<'PY'
import sqlite3
from pathlib import Path
source = sqlite3.connect("/data/web.sqlite3")
Path("/data/backups").mkdir(exist_ok=True)
target = sqlite3.connect("/data/backups/web-backup.sqlite3")
source.backup(target)
target.close()
source.close()
PY
docker cp "$(docker compose ps -q web)":/data/backups/web-backup.sqlite3 backups/web-backup.sqlite3
docker run --rm -v driftbeacon_driftbeacon-data:/data -v "$PWD/backups":/backup alpine \
  tar -C /data -czf /backup/reports-backup.tgz reports
cp .env backups/env-backup
```

Do not blindly copy a live SQLite file while writes may be happening.

## 18. Restore

Stop services before restore:

```sh
docker compose down
```

Restore the SQLite backup and reports into the persistent volume, then restart:

```sh
docker run --rm -v driftbeacon_driftbeacon-data:/data -v "$PWD/backups":/backup alpine sh -c \
  "cp /backup/web-backup.sqlite3 /data/web.sqlite3 && tar -C /data -xzf /backup/reports-backup.tgz"
docker compose up -d
curl -fsS http://127.0.0.1:8080/health/ready
```

Reports are disposable for the demo if you choose not to preserve them. Document that decision before inviting testers.

## 19. Update

```sh
git fetch origin
git checkout main
git pull --ff-only
docker compose build
docker compose up -d
curl -fsS http://127.0.0.1:8080/health/ready
./scripts/smoke-web.sh
```

## 20. Rollback

```sh
git checkout <previous-known-good-commit>
docker compose build
docker compose up -d
curl -fsS http://127.0.0.1:8080/health/ready
```

If a future database migration is not backward-compatible, restore a compatible database backup before rollback. Current web schema migrations are versioned.

## 21. Disk-Space Management

Watch Docker volumes and logs:

```sh
docker system df
docker compose logs --tail=100 worker
docker compose run --rm cleanup
```

Reduce retention or repository limits if disk pressure appears.

## 22. Known Limitations

- Single host only.
- SQLite/filesystem persistence only.
- One worker is the default operating model.
- No accounts, billing, GitHub App, private repositories or subscriptions.
- No high availability, autoscaling or multi-region deployment.
- No complete sandbox guarantee for malicious repositories.
- Docker Compose resource controls vary by host platform.

## 23. Residual Security Risks

Scanning untrusted repositories can stress parser code, scanner tools, CPU, memory and disk. The worker is non-root, constrained and separated from the web process, but it still has outbound network access and executes external scanner binaries against untrusted files.

Shut down the demo if:

- disk usage grows unexpectedly;
- worker failures spike;
- scanner behavior changes;
- the host shows unusual CPU, memory or network activity;
- public links contain data you do not want shared.

## 24. Stop The Demo

```sh
docker compose down
```

To remove all local persistent demo data:

```sh
docker compose down -v
```

Only run `down -v` after taking any backup you intend to keep.
