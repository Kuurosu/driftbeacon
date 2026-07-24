# DriftBeacon

DriftBeacon is an operational intelligence layer for small infrastructure and DevOps teams.

The MVP connects repository scanners to a deterministic weekly Markdown report. It normalizes noisy Checkov and Trivy output, compares the current scan with the previous run, ranks the three most important issues, calculates a simple health score, and optionally posts a concise digest to Slack.

It is intentionally not a hosted SaaS, chatbot, dashboard, database-backed platform, or AWS deployment. It runs for free in GitHub Actions or locally.

## What The MVP Does

- Runs through GitHub Actions on a weekly schedule or pull request changes.
- Scans Terraform, CloudFormation, Kubernetes YAML, Dockerfiles, dependency manifests, misconfigurations, vulnerabilities, and optional secret findings.
- Uses Checkov and Trivy instead of recreating scanners.
- Normalizes scanner output into one `Finding` model.
- Tracks new, recurring, resolved, and severity-changed findings.
- Calculates a 0 to 100 infrastructure health score.
- Produces a concise Markdown report and stores JSON scan state.
- Posts a short Slack summary when `SLACK_WEBHOOK_URL` is configured.
- Works locally, including a sample run that does not require scanners.
- Includes safe, intentionally insecure demo infrastructure and captured scanner output for public demos.

## Architecture

```text
GitHub Actions or local CLI
        |
        v
Scanner adapters: Checkov, Trivy
        |
        v
Normalization: common Finding model and stable fingerprints
        |
        v
Comparison: new, recurring, resolved, severity changes
        |
        v
Scoring and prioritisation
        |
        v
Markdown report, JSON state, optional Slack webhook
```

The local storage backend writes generated files to `.driftbeacon/`. The storage interface is small enough to replace later with S3, PostgreSQL, or another history store.

## Five-Minute Local Setup

Requirements:

- Python 3.12
- Git
- macOS with zsh or Linux shell
- Optional: Checkov and Trivy for real repository scanning

Install DriftBeacon:

```sh
git clone https://github.com/Kuurosu/driftbeacon.git
cd driftbeacon
./scripts/install-local.sh
. .venv/bin/activate
driftbeacon --help
```

Run the sample report without installing scanners:

```sh
make run-sample
open .driftbeacon-sample/report.md
```

Run against the current repository:

```sh
driftbeacon run \
  --repository-path . \
  --output-dir .driftbeacon \
  --previous-scan .driftbeacon/previous-scan.json
```

## Scanner Setup

For real scans, install Checkov and Trivy:

```sh
python -m pip install checkov
brew install trivy
```

On Linux, install Trivy using the official package instructions for your distribution.

Missing scanners do not crash DriftBeacon. They are recorded as `skipped` in the scan JSON and report so the team can see what coverage was unavailable.

## CLI Reference

```sh
driftbeacon scan
driftbeacon report
driftbeacon compare
driftbeacon send-slack
driftbeacon run
driftbeacon analyse-repo
driftbeacon analyse
```

Full workflow:

```sh
driftbeacon run \
  --repository-path . \
  --output-dir .driftbeacon \
  --previous-scan .driftbeacon/previous-scan.json \
  --slack-webhook-env SLACK_WEBHOOK_URL
```

Use fixture JSON instead of running scanners:

```sh
driftbeacon run \
  --repository-path . \
  --output-dir .driftbeacon-sample \
  --previous-scan examples/previous-scan.json \
  --checkov-json examples/sample-checkov.json \
  --trivy-json examples/sample-trivy.json \
  --no-slack
```

Analyse public Git repositories without manually cloning them:

```sh
driftbeacon analyse-repo https://github.com/example/infrastructure.git
```

Analyse many repositories in parallel:

```sh
cat > repos.txt <<'EOF'
https://github.com/example/terraform-platform.git
https://github.com/example/kubernetes-services.git
EOF

driftbeacon analyse repos.txt --workers 4
```

Repository analysis can exclude noisy directory groups from health scoring while preserving audit counts:

```sh
driftbeacon analyse repos.txt \
  --exclude-path-group examples \
  --exclude-path-group fixtures
```

Repository analysis mode:

- Clones each repository into a temporary directory.
- Detects supported infrastructure, Docker, Kubernetes, CloudFormation, Terraform, and dependency files.
- Runs the same Checkov and Trivy scanner adapters used by `driftbeacon run`.
- Writes per-repository `current-scan.json`, `comparison-summary.json`, and `report.md`.
- Writes `analysis-summary.csv`, `analysis-summary.md`, and `analysis-summary.json`.
- Prints progress such as `[12/50] Scanning terraform-aws-vpc...`.
- Prints a one-line result per repository with health score or an explicit not-scored reason.
- Continues when one repository fails.
- Deletes temporary clones unless `--keep` is passed.
- Uses `owner--repo` output directories so repositories with the same name do not collide.
- Reuses an existing per-repository `current-scan.json` in the output directory as the comparison baseline.

By default, analysis output is written to `.driftbeacon-analysis/`:

```text
.driftbeacon-analysis/
  analysis-summary.csv
  analysis-summary.md
  analysis-summary.json
  repository-a/
    current-scan.json
    comparison-summary.json
    report.md
```

The first analysis run is an initial baseline, so the summary shows `Total Findings` rather than treating everything as newly introduced. Later runs against the same output directory show `New`, `Resolved`, and `Recurring` columns. The Markdown summary ranks only repositories with valid scores, labels partial coverage, and keeps unscored repositories in a separate section. The CSV contains one row per repository, including failed repositories and their error message. The JSON summary schema is version `2.0` and has stable top-level fields:

- `metadata`
- `aggregate_statistics`
- `severity_totals`
- `scanner_coverage`
- `scanner_issues`
- `finding_source_breakdown`
- `directory_group_breakdown`
- `top_directories`
- `top_files`
- `common_findings`
- `failure_details`
- `raw_vs_deduplicated_counts`
- `repository_results`

Each repository row includes `health_score`, `grade`, `grade_provisional`, `score_state`, `coverage_state`, `score_reason`, `production_health_score`, `production_grade`, `production_grade_provisional`, `production_score_state`, `production_score_reason`, `production_actionable_findings`, `production_critical_findings`, `production_high_findings`, `production_medium_findings`, `production_low_findings`, `supported_files_scanned`, `affected_supported_files`, `affected_file_percentage`, `findings_per_100_supported_files`, `findings_per_affected_file`, `repository_category`, `category_confidence`, `category_evidence`, `scanner_results`, `finding_source_breakdown`, `directory_group_breakdown`, `excluded_finding_counts`, and `score_formula_version`.

Repository analysis is useful for research and triage, but compare repositories carefully. The summary includes repository category, supported file count, affected file count, and findings per 100 supported files because a large Terraform provider, a small module, and a guide repository are not directly comparable by raw finding count. Findings per 100 supported files is a density, not a percentage, and can exceed 100 when one file has multiple findings.

## GitHub Installation

Copy the included workflows into your repository:

```text
.github/workflows/driftbeacon-weekly.yml
.github/workflows/driftbeacon-pr.yml
```

The weekly workflow:

- Runs every Monday at 08:00 UTC.
- Supports manual `workflow_dispatch`.
- Installs Python, DriftBeacon, Checkov, and Trivy.
- Uses pip caching to keep repeated runs fast.
- Restores the previous scan using GitHub Actions cache.
- Uploads `report.md`, `current-scan.json`, and `comparison-summary.json` as artifacts.
- Writes the Markdown report to the GitHub Actions job summary.
- Sends Slack only when the `SLACK_WEBHOOK_URL` secret exists.

The pull request workflow:

- Runs only when infrastructure, Docker, dependency, config, source, or test files change.
- Uploads artifacts and writes the concise report to the job summary.
- Does not use Slack secrets and is safe for forked pull requests.

GitHub Actions cache is a practical free MVP history store, but caches are not guaranteed permanent. The storage interface is intentionally ready for a stronger backend later.

## Slack Setup

Create an incoming webhook in Slack, then add it as a GitHub Actions secret:

```text
Repository Settings -> Secrets and variables -> Actions -> New repository secret
Name: SLACK_WEBHOOK_URL
Value: https://hooks.slack.com/services/...
```

For local testing:

```sh
cp .env.example .env
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
driftbeacon send-slack --report-file .driftbeacon-sample/report.md
```

Never commit `.env` or a real webhook URL. DriftBeacon redacts common webhook and token patterns before reporting errors.

## Configuration

Configuration can come from command-line flags, environment variables, or an optional `.driftbeacon.yml`.

Example:

```yaml
repository_path: .
output_dir: .driftbeacon
scanners:
  checkov:
    enabled: true
  trivy:
    enabled: true
    secret_scanning: false
report:
  top_findings: 3
thresholds:
  fail_on: null
paths:
  production_patterns:
    - production
    - prod
    - live
slack:
  enabled: true
  webhook_environment_variable: SLACK_WEBHOOK_URL
```

Supported environment variables:

- `DRIFTBEACON_REPOSITORY_PATH`
- `DRIFTBEACON_OUTPUT_DIR`
- `DRIFTBEACON_CHECKOV_ENABLED`
- `DRIFTBEACON_TRIVY_ENABLED`
- `DRIFTBEACON_TRIVY_SECRET_SCANNING`
- `DRIFTBEACON_TOP_FINDINGS`
- `DRIFTBEACON_FAIL_ON`
- `SLACK_WEBHOOK_URL`

`thresholds.fail_on` may be `critical`, `high`, `medium`, `low`, `info`, `unknown`, or `null`. When set, DriftBeacon exits with code `2` if an active finding meets or exceeds the threshold.

## Example Report

See `examples/sample-report.md`, or regenerate it:

```sh
make run-sample
cat .driftbeacon-sample/report.md
```

For a real scanner-backed demo, see:

- `examples/demo-infrastructure/` for safe intentionally insecure infrastructure.
- `examples/scans/checkov-demo.json` and `examples/scans/trivy-demo.json` for captured scanner output.
- `examples/scans/driftbeacon-demo-report.md` for a first-scan report.
- `examples/scans/driftbeacon-history-report.md` for new, recurring, resolved, and health delta states.

Nothing under `examples/demo-infrastructure/` should be deployed. The Terraform module requires an impossible Terraform version as a guardrail.

## Health Score

DriftBeacon health formula version `driftbeacon-health-v2` uses weighted risk and exponential decay:

```text
weighted_risk =
    critical_count * 12
  + high_count * 5
  + medium_count * 2
  + low_count * 1

health = round(100 * exp(-weighted_risk / 80))
```

The curve is continuous and monotonic: more actionable findings never improve health. DriftBeacon reserves exact `0` for extreme weighted risk (`weighted_risk >= 1000`); serious but non-extreme repositories can still rank above one another.

Informational findings, unknown-severity findings, passed checks, skipped scanners, scanner-error records, resolved findings, and exact duplicate fingerprints do not reduce the score. First-scan baseline status does not affect the score; a finding is not penalized just because there is no previous scan yet.

A repository is scored only when DriftBeacon has meaningful coverage. Zero supported files is `not_scored_no_supported_files`, not healthy. If all applicable scanners fail, the repository is `not_scored_all_scanners_failed`. If one applicable scanner succeeds and another fails, the repository is scored with `partial_coverage` and the report warns that the score may be incomplete. Markdown grades for partial coverage are marked with an asterisk, such as `A*`; JSON and CSV keep the raw grade and set `grade_provisional`.

Overall Health includes all analysed actionable findings. Production Health uses the same `driftbeacon-health-v2` formula but includes only deduplicated actionable findings from paths classified as `production`. Test, fixture, example, generated, vendored, third-party, docs, charts, and unknown paths are not counted in Production Health. Production Health can be unavailable even when Overall Health is valid, and it does not prove deployed infrastructure is safe. Path classification is heuristic and should be reviewed.

Checkov community JSON does not always include native severity. When severity is missing or unrecognized, DriftBeacon records the finding as `unknown` for audit visibility and ignores it in health scoring by default rather than silently promoting it to high risk.

The report trend compares the current score with the previous scan score only when both scans used the same score formula version. If the formula changed, DriftBeacon still compares finding identity but does not present raw score movement as directly comparable.

## Prioritisation

DriftBeacon does not simply sort by severity. Each active finding receives a transparent priority score from:

- Severity.
- New versus recurring status.
- Production-like path patterns such as `production`, `prod`, and `live`.
- Category, with secrets, IAM, vulnerabilities, and network exposure weighted higher.
- Recurrence age.
- Blast radius language such as wildcard, admin, public, internet, cluster, account, or global.
- Availability of remediation or documentation.

The top three findings are shown as "Fix these first" with a short reason.

## Developer Commands

```sh
make install
make test
make lint
make typecheck
make format
make run-sample
make clean
```

## Troubleshooting

Checkov or Trivy says skipped:

```sh
which checkov
which trivy
```

Install the missing scanner, or use `--checkov-json` and `--trivy-json` for fixture-driven runs.

No previous baseline:

The first scan establishes the baseline. Reports do not describe first-scan findings as newly introduced. The weekly workflow stores the current scan in cache for the next run.

Slack did not send:

```sh
echo "$SLACK_WEBHOOK_URL"
driftbeacon send-slack --report-file .driftbeacon/report.md
```

Do not print the actual webhook value in shared logs.

Invalid config:

Run:

```sh
driftbeacon run --config .driftbeacon.yml --no-slack
```

The parser supports the documented YAML shape and fails clearly for invalid booleans, paths, thresholds, and report counts.

## Security Considerations

- Slack webhook URLs are read only from environment variables.
- Webhook URLs and obvious secrets are redacted from scanner text and Slack payloads.
- Scanner subprocesses use argument arrays, not shell strings.
- Scanner execution uses timeouts.
- Repository walking does not follow symlinks and skips generated directories.
- driftbeacon refuses symlinked scan/config output paths where practical.
- GitHub workflows use read-only repository permissions.
- PR workflows do not expose Slack secrets.
- Artifacts include only generated driftbeacon reports and JSON state, not the whole repository.

Limitations:

- Redaction is best effort and cannot guarantee detection of every secret format.
- Checkov and Trivy are external tools. Their coverage and false positives are inherited.
- GitHub Actions cache is not permanent historical storage.
- The MVP does not authenticate users, host dashboards, or ingest cloud accounts directly.

## Planned Future Development

- GitHub App installation.
- Multiple repositories and organisations.
- AWS account ingestion.
- Certificate expiry discovery.
- AWS cost-change detection.
- Jira and Microsoft Teams integrations.
- Natural-language operational queries.
- PostgreSQL event storage.
- S3 report storage.
- Hosted multi-tenant SaaS with authentication and billing.
- Automated remediation approval workflows.
