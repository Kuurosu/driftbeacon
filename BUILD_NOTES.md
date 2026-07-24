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
- Converted Markdown reports into Slack-native `mrkdwn` summaries so Slack messages keep readable line breaks.
- Made `make run-sample` and the local `driftbeacon` launcher run directly from `src/` so local commands do not depend on editable-install `.pth` behavior.

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
```

## Tests Run

- `python -m pytest`: 19 passed.
- `ruff check .`: passed.
- `mypy src`: passed.
- `make test`: 19 passed.
- `make lint`: passed.
- `make typecheck`: passed.
- `make run-sample`: generated `.driftbeacon-sample/report.md`, `current-scan.json`, and `comparison-summary.json`.
- CLI help verified for the root command and `run` command.
- Missing scanner handling verified locally. Checkov and Trivy were recorded as `skipped` when no executables were available.

## Known Limitations

- GitHub Actions cache is not durable storage and may be evicted.
- Secret redaction is best effort.
- The bundled config parser supports the documented `.driftbeacon.yml` shape, not arbitrary YAML.
- Scanner integration tests are not included because the MVP unit suite must not require local Checkov or Trivy installs.
- The workflows install Checkov and Trivy at run time, so first runs depend on public package availability.
- Local scans without Git metadata show repository name from the folder and `unknown` branch/commit.

## Recommended Next Steps

- Add a small integration test job that runs against a fixture repository with Checkov and Trivy installed.
- Decide whether to keep GitHub Actions cache or move history to a dedicated branch, S3, or PostgreSQL.
- Add optional PR annotations once write-safe GitHub App permissions exist.
- Add SARIF export if GitHub code scanning becomes part of the product path.
- Build provider-specific enrichers later, starting with AWS account context and cost-change signals.
