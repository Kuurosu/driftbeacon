# Build Notes

## Architectural Decisions

- Built DriftBeacon as a Python 3.12 package with an argparse CLI and no runtime dependencies.
- Kept scanner execution in adapters under `src/driftbeacon/scanners/`.
- Used Checkov and Trivy as external scanners; unit tests use fixture JSON and do not require those tools.
- Normalized all scanner findings into one typed `Finding` dataclass with stable fingerprints.
- Fingerprints use scanner, rule ID, file path, resource, and line number. They do not use timestamps.
- Kept scoring and prioritisation deterministic. No external AI API is used.
- Implemented local filesystem storage behind a small `LocalStorage` abstraction.
- Used GitHub Actions cache as the free MVP history store, with artifacts for reports and scan state.
- Made Slack optional and environment-driven so webhook values are never stored in config files.
- Added a small YAML-subset parser to avoid adding PyYAML as a runtime dependency.
- Exposed a single `driftbeacon` console script to avoid case-only script collisions on macOS filesystems.
- Hardened `scripts/install-local.sh` so it moves a broken `.venv` aside and recreates it when pip cannot cleanly uninstall an old editable install.
- Converted Markdown reports into Slack Block Kit digests with summary, top priorities, scanner status, and artifact context.
- Made `make run-sample` and the local `driftbeacon` launcher run directly from `src/` so local commands do not depend on editable-install `.pth` behavior.
- Added safe intentionally insecure demo infrastructure with Terraform, Docker, Kubernetes, and CloudFormation fixtures.
- Captured real Checkov and Trivy JSON under `examples/scans/`.
- Updated scoring to use weighted findings with a diminishing-returns curve so noisy repositories still show trend deltas.
- Added Repository Analysis Mode for cloning and scanning one public Git repository or a bulk text file of repositories.

## Commands Executed

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
.venv/bin/driftbeacon --help
.venv/bin/driftbeacon run --help
make test
make lint
make typecheck
make run-sample
.venv/bin/python -m driftbeacon scan --repository-path /private/tmp/driftbeacon-mvp --output-dir /private/tmp/driftbeacon-mvp/.driftbeacon-missing-scanners
checkov -d examples/demo-infrastructure -o json --quiet --skip-download
trivy fs --format json --scanners misconfig,secret --quiet --skip-check-update examples/demo-infrastructure
driftbeacon analyse-repo /private/tmp/driftbeacon-analysis-e2e.*/source --output-dir /private/tmp/driftbeacon-analysis-e2e.*/single --timeout 30 --clone-timeout 30
driftbeacon analyse /private/tmp/driftbeacon-analysis-e2e.*/repos.txt --output-dir /private/tmp/driftbeacon-analysis-e2e.*/bulk --workers 2 --timeout 30 --clone-timeout 30
```

## Tests Run

- `python -m pytest`: 31 passed.
- `ruff check .`: passed.
- `mypy src`: passed for 19 source files.
- `make test`: passed.
- `make lint`: passed.
- `make typecheck`: passed.
- `make run-sample`: generated `.driftbeacon-sample/report.md`, `current-scan.json`, and `comparison-summary.json`.
- CLI help verified for the root command and `run` command.
- Missing scanner handling verified locally. Checkov and Trivy were recorded as `skipped` when no executables were available.
- Checkov demo validation captured 52 failed checks.
- Trivy demo validation captured 41 misconfigurations.
- Historical comparison captured 18 new findings, 90 recurring findings, 3 resolved findings, and a 1 point health score increase.
- Slack Block Kit payload validated locally from `examples/scans/driftbeacon-history-report.md`.
- Repository Analysis Mode validated locally with a successful cloned Git repository and a failing repository entry.

## Known Limitations

- GitHub Actions cache is not durable storage and may be evicted.
- Secret redaction is best effort.
- The bundled config parser supports the documented `.driftbeacon.yml` shape, not arbitrary YAML.
- Scanner integration tests are not included because the MVP unit suite must not require local Checkov or Trivy installs.
- The workflows install Checkov and Trivy at run time, so first runs depend on public package availability.
- Local scans without Git metadata show repository name from the folder and `unknown` branch/commit.
- The demo infrastructure is intentionally invalid or guarded against accidental deployment, but it remains syntactically parseable for static scanners.
- Repository Analysis Mode requires local `git` and network access for public repository URLs.

## Recommended Next Steps

- Add a small integration test job that runs against a fixture repository with Checkov and Trivy installed.
- Decide whether to keep GitHub Actions cache or move history to a dedicated branch, S3, or PostgreSQL.
- Add optional PR annotations once write-safe GitHub App permissions exist.
- Add SARIF export if GitHub code scanning becomes part of the product path.
- Build provider-specific enrichers later, starting with AWS account context and cost-change signals.
