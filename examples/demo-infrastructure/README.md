# DriftBeacon Demo Infrastructure

This directory contains intentionally insecure infrastructure examples for DriftBeacon scanner demos.

Do not deploy these files.

They exist only to generate realistic Checkov and Trivy findings during local and GitHub Actions validation. The examples intentionally include public network exposure, public storage, unencrypted storage, wildcard IAM permissions, insecure container settings, and privileged Kubernetes workloads.

Safety guardrails:

- The Terraform root module requires an impossible Terraform version so `terraform init`, `plan`, and `apply` cannot proceed accidentally.
- No real account IDs, credentials, domains, or secret values are included.
- The Dockerfile uses an invalid demo registry so accidental image builds cannot pull a base image.
- The Kubernetes Pod name is intentionally invalid so `kubectl apply` fails validation.
- The CloudFormation template contains a rule that cannot be satisfied, so stack creation is blocked.

Run a demo scan from the repository root:

```sh
driftbeacon run \
  --repository-path examples/demo-infrastructure \
  --output-dir .driftbeacon-demo \
  --no-slack
```

Capture scanner JSON for repeatable demos:

```sh
checkov -d examples/demo-infrastructure -o json --quiet --skip-download \
  --skip-path .driftbeacon > examples/scans/checkov-demo.json

trivy fs --format json --scanners misconfig,secret --quiet --skip-check-update \
  --skip-dirs .driftbeacon examples/demo-infrastructure > examples/scans/trivy-demo.json
```

Saved example outputs live in `examples/scans/`.
