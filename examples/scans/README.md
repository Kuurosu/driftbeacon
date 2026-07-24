# DriftBeacon Scan Artifacts

This directory contains captured scanner and DriftBeacon outputs used for demos and tests.

The files are safe to commit. They were generated from intentionally insecure example infrastructure under `examples/demo-infrastructure/` and from a temporary modified copy used to prove historical comparison.

## Scanner Captures

- `checkov-demo.json`: Checkov JSON output for `examples/demo-infrastructure/`.
- `trivy-demo.json`: Trivy misconfiguration JSON output for `examples/demo-infrastructure/`.

These captures prove Checkov and Trivy detect the intentionally unsafe Terraform, Docker, Kubernetes, and CloudFormation examples.

## DriftBeacon Demo Output

- `driftbeacon-demo-current-scan.json`: normalized first-scan findings.
- `driftbeacon-demo-comparison-summary.json`: first-scan comparison summary.
- `driftbeacon-demo-report.md`: generated CTO-readable Markdown report.

## Historical Comparison Output

- `driftbeacon-history-baseline-scan.json`: previous scan from the baseline demo infrastructure.
- `driftbeacon-history-current-scan.json`: current scan after a temporary change.
- `driftbeacon-history-comparison-summary.json`: new, recurring, resolved, and trend summary.
- `driftbeacon-history-report.md`: Markdown report for the current historical run.

For the historical scenario, a temp copy fixed EBS volume encryption, introduced a public RDS database, and left existing network exposure unchanged. That proves DriftBeacon reports resolved, new, recurring, and health score delta states without making the committed demo infrastructure deployable.
