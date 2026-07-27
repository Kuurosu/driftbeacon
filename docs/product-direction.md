# DriftBeacon Product Direction

DriftBeacon is evolving from a security-scanner wrapper into a Production Health and engineering-risk prioritisation platform.

## Value Proposition

Know exactly what to fix next to reduce production risk.

Expanded:

DriftBeacon turns thousands of infrastructure, dependency and configuration findings into a prioritised engineering plan showing what to fix, why it matters, how much risk it removes when the model can support that, and how Production Health is changing over time.

## Product Principles

- DriftBeacon helps engineering teams decide what to work on next.
- Scanner output is an input, not the product.
- Production Health is the primary metric for production-relevant risk prioritisation.
- Overall Health remains useful context, but should not visually dominate product surfaces.
- Reports must explain why a finding matters and what action is recommended.
- Estimated effort, projected risk reduction and projected health must only appear when a trustworthy model exists.
- Presentation formats must reuse shared ranking and explanation logic.
- DriftBeacon must not claim that a repository or production environment is secure.

## Production Health

Production Health is a prioritisation and trend metric based on findings detected by completed scanners and classified as production-relevant.

Production Health does not prove that a repository or production environment is secure. It depends on scanner coverage, path classification, finding normalisation and the transparent DriftBeacon scoring model.

Current implementation:

- uses the existing health scoring formula;
- evaluates production-classified findings separately;
- marks grades provisional when scanner coverage is partial;
- keeps methodology and limitations visible in reports.

Out of scope for the current task:

- changing the scoring formula;
- creating new arbitrary weights for marketing claims;
- claiming causal health movement without comparison data.

## Execution Models

DriftBeacon should support three execution methods that share the same analysis engine.

### Public Web SaaS

Current MVP direction:

- user opens DriftBeacon;
- user pastes one public GitHub repository URL;
- DriftBeacon clones the repository into an isolated temporary directory;
- DriftBeacon runs the shared analysis engine;
- user receives a web report focused on Production Health and what to fix next.

No login, billing, private repositories or scheduled scans are included in the public web MVP.

### GitHub App

Planned primary paid monitoring path:

- GitHub organisation connection;
- repository selection;
- short-lived GitHub App installation tokens;
- private repository scanning;
- scheduled scans and webhook-triggered updates.

Do not design around users pasting long-lived personal access tokens into the website.

### GitHub Action

Existing advanced customer-controlled execution path:

- pull-request scanning;
- weekly or manual scans;
- reports and JSON artifacts inside customer CI/CD;
- no source-code movement outside the customer's environment.

## Product Layers

- Scanner layer: runs Checkov, Trivy and future scanners.
- Normalisation layer: converts raw scanner output into DriftBeacon findings.
- Context layer: classifies production paths, examples, tests, fixtures, generated files, vendor paths, docs and similar context.
- Risk layer: scores severity, production relevance, recurrence, scanner coverage and blast-radius indicators where supported.
- Effort layer: planned future estimates for fix complexity and likely implementation effort.
- Prioritisation layer: decides what should be fixed first.
- Presentation layer: web, Slack, Markdown, JSON, CSV and future exports.

Presentation layers must not invent their own ranking or explanations.

## Engineering Action Plans

The current product already has ranked findings and recommended actions. The planned Engineering Action Plan expands each priority with structured fields:

- priority;
- finding title;
- risk summary;
- affected production path;
- recommended fix;
- confidence;
- estimated complexity;
- estimated effort;
- expected risk reduction;
- projected Production Health;
- related findings likely to be resolved;
- dependencies or prerequisites.

Current MVP behavior:

- shows priority, severity, production relevance, location, why it matters and recommended action;
- labels effort and projected impact as unavailable rather than inventing values.

## Risk Reduction Simulation

Planned approach:

1. Copy the finding set.
2. Mark selected findings as hypothetically resolved.
3. Re-run the existing scoring model.
4. Compare current and projected Overall Health and Production Health.

DriftBeacon must not approximate projected health by adding arbitrary points.

## Risk Clusters

Planned risk clusters should group findings that likely share one underlying fix, such as one vulnerable dependency producing many CVEs or one shared Terraform module creating issues across repositories.

This is planned work. Do not build an unreliable clustering algorithm solely to claim the feature exists.

## Ask DriftBeacon Boundaries

Ask DriftBeacon is a future paid capability that should answer questions over structured scan, comparison, scoring and prioritisation data.

It must not send unfiltered scanner output blindly to an AI model. Structured findings, comparisons, rankings, scoring and explanations remain the source of truth.

## Benchmarking Privacy Constraints

Future benchmarking must be:

- statistically meaningful;
- aggregated;
- anonymised;
- opt-in where appropriate;
- protected from reverse identification;
- separated between public and private repository data;
- documented clearly.

Do not use private customer source code or finding details for public benchmarking without explicit permission.

## Current MVP Scope

Implemented in this phase:

- local public web scan MVP;
- public GitHub URL validation;
- background scan execution;
- structured status polling;
- Production Health-first web report;
- SQLite-backed scan metadata;
- shareable report URLs that survive process restarts until expiry;
- filesystem-backed structured report JSON and Markdown downloads;
- retention cleanup with expired-report tombstones;
- startup recovery for interrupted queued or running scans;
- no-op analytics boundary;
- configurable scan limits.

Explicitly out of scope:

- Stripe;
- accounts;
- GitHub OAuth or GitHub App;
- private repository access;
- scheduled scans;
- organisation dashboards;
- Teams or Jira integration;
- effort estimation;
- projected health simulation;
- risk clusters;
- AI assistant;
- benchmarking;
- SSO or enterprise deployment.

Deployment notes:

- The current web persistence model is intended for local development, a single-instance public demo and controlled early public testing.
- Do not run multiple web instances against the same local SQLite database and filesystem report directory.
- This model is not high availability and is not designed for large-scale untrusted scanning.
