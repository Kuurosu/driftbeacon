# DriftBeacon Roadmap

This roadmap separates current MVP scope from planned product capabilities.

## Phase 1: Public Web Scan MVP

Current implementation target:

- public landing page;
- GitHub URL submission;
- HTTPS GitHub-only validation;
- queued background scan;
- scan progress and status polling;
- completed web report;
- repository metadata;
- Overall Health;
- Production Health;
- What to fix next;
- existing explanations and recommended actions;
- scanner status and coverage;
- safe failure handling;
- basic rate limiting;
- concurrency controls;
- temporary directory cleanup.

No login, billing, private repositories or scheduled scans.

## Phase 2: Product Validation

Before building substantial billing or organisation functionality:

- allow users to share reports;
- instrument consent-aware anonymous product analytics;
- record conversion events;
- collect optional feedback;
- interview DevOps engineers, platform engineers and engineering managers;
- determine whether reports change prioritisation decisions;
- test pricing language;
- validate demand for continuous monitoring.

Validation question:

If this report arrived every Monday, would it change what your team worked on that week?

Potential events:

- `landing_page_viewed`;
- `scan_submitted`;
- `scan_rejected`;
- `scan_started`;
- `scan_completed`;
- `scan_failed`;
- `report_viewed`;
- `report_shared`;
- `signup_interest_clicked`;
- `pricing_viewed`.

The current code includes a no-op analytics boundary. It does not send events to a third-party analytics provider.

## Phase 3: Accounts and Saved History

Planned:

- user accounts;
- saved scans;
- repository ownership;
- scan history;
- trend charts;
- retention policies;
- dashboard;
- free-tier limits.

## Phase 4: GitHub App

Planned:

- GitHub App authentication;
- private repositories;
- organisation installation;
- repository selection;
- short-lived installation tokens;
- scheduled scans;
- webhook-driven updates;
- branch selection;
- default-branch scanning.

Do not use long-lived personal access tokens for private repository monitoring.

## Phase 5: Paid Plans

Planned:

- Stripe Checkout;
- Stripe Billing Portal;
- subscription state;
- plan entitlements;
- usage tracking;
- scan quotas;
- repository limits;
- retention limits;
- trial handling;
- failed-payment handling;
- cancellation;
- webhook verification;
- invoice history.

Billing is not implemented in the current MVP.

## Phase 6: Engineering Action Plans

Planned:

- estimated fix complexity;
- risk-reduction simulation;
- projected health;
- risk clusters;
- sprint-sized action plans;
- related-finding reduction;
- weekly prioritisation.

Impact simulation must reuse the real scoring model by marking selected findings hypothetically resolved and recalculating health.

## Phase 7: Organisation Intelligence

Planned:

- portfolio trends;
- team ownership;
- repository comparisons;
- cross-repository risk clusters;
- remediation performance;
- mean time to remediation;
- policy exceptions;
- organisation-level action plans.

## Phase 8: Ask DriftBeacon

Planned only after structured product data is mature.

Ask DriftBeacon should reason over structured scan history, prioritisation data, comparisons, scoring and explanations. It should not send unfiltered scanner output blindly to an AI model.

## Explicitly Out Of Scope For The Current MVP

- Stripe or checkout flows;
- subscription enforcement;
- user accounts;
- GitHub OAuth;
- GitHub App;
- private repository access;
- scheduled scans;
- organisation dashboards;
- Teams integration;
- Jira integration;
- projected health simulation;
- effort estimation;
- risk clusters;
- AI assistant;
- benchmarking;
- SSO;
- enterprise deployment;
- multi-tenant production infrastructure.
