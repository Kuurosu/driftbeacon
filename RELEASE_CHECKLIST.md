# Release Checklist

Status date: 2026-07-24

## Validation

- [x] `python -m pytest` passed: 71 tests.
- [x] `ruff check .` passed.
- [x] `mypy src` passed: 20 source files.
- [x] `make run-sample` passed and generated `.driftbeacon-sample/report.md`.
- [x] `driftbeacon --help` passed from the installed local CLI.
- [x] `driftbeacon analyse-repo` validated against a local Git repository clone.
- [x] `driftbeacon analyse` validated with one successful local Git repository and one failed repository.
- [x] Repository Analysis Mode smoke-tested against five public GitHub repositories with scanner issue attribution verified.
- [x] Checkov validated against `examples/demo-infrastructure/`: 52 failed checks captured.
- [x] Trivy validated against `examples/demo-infrastructure/`: 41 misconfigurations captured.
- [x] Historical comparison validated with new, recurring, resolved, and health score delta states.

## Workflow Readiness

- [x] Weekly workflow inspected for artifacts, cache restore/save, read-only permissions, timeout, branch-specific history, Slack secret handling, and job summary output.
- [x] Pull request workflow inspected for path filters, read-only permissions, timeout, artifact upload, job summary output, and no Slack secret exposure.
- [x] Workflows require only GitHub Actions, Python packages, Checkov, Trivy, and an optional Slack webhook.

## Demo Artifacts

- [x] Safe intentionally insecure demo infrastructure exists in `examples/demo-infrastructure/`.
- [x] Scanner JSON captures exist in `examples/scans/checkov-demo.json` and `examples/scans/trivy-demo.json`.
- [x] First-scan DriftBeacon output exists in `examples/scans/driftbeacon-demo-report.md`.
- [x] Historical DriftBeacon output exists in `examples/scans/driftbeacon-history-report.md`.
- [x] Slack Block Kit payload validated locally from the historical report.

## Known Limitations

- GitHub Actions cache is practical for an MVP but not durable historical storage.
- Checkov and Trivy coverage, false positives, and network availability are inherited external dependencies.
- Local scanner integration tests are not part of the default unit suite.
- DriftBeacon does not yet emit SARIF, PR annotations, or hosted dashboards.
- Repository Analysis Mode clones public repositories locally and does not yet integrate with hosted repository inventory APIs.
- Secret redaction is best effort.

## Roadmap

- Add a CI integration job that installs Checkov and Trivy and scans the demo infrastructure.
- Add SARIF export for GitHub code scanning.
- Add optional PR annotations once write-safe permissions are designed.
- Add a durable history backend such as S3, PostgreSQL, or a dedicated repository branch.
- Add provider-aware enrichment for ownership, blast radius, and remediation context.
