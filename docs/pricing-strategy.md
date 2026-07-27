# Pricing Strategy

Pricing is proposed product strategy, not implemented billing behavior.

The current public web MVP does not enforce paid plans, collect payment, create accounts or limit features by plan name. Runtime scan limits are configurable abuse-prevention controls, not subscription entitlements.

## Monetisation Principles

- The free tier should demonstrate report quality and prioritisation value.
- Paid boundaries should map to persistent, recurring and organisational value.
- Do not charge for arbitrary cosmetic features.
- Clear paid boundaries are public to private repositories, manual to scheduled scans, snapshot to history, single repository to portfolio, individual to team workflows, and current state to risk-reduction simulation.

## Proposed Plans

### Free

Suggested price: £0

Purpose: demonstrate value and attract individual users.

Proposed features:

- public repositories only;
- one repository per scan;
- limited scans per day;
- manual scans;
- initial-baseline report;
- Overall Health;
- Production Health;
- top prioritised findings;
- basic explanations;
- limited report retention;
- no private repository access;
- no scheduled scans;
- no team features.

Possible limits:

- 3 public scans per day;
- 7-day report retention.

### Pro

Suggested starting price: £19 per month or £190 per year.

Target customer: individual developers, consultants and small infrastructure teams.

Proposed features:

- public repositories;
- private repositories through the GitHub App;
- up to 5 monitored repositories;
- scheduled weekly scans;
- scan history;
- Production Health trends;
- comparison reports;
- new and resolved findings;
- Slack notifications;
- longer report retention;
- downloadable Markdown and JSON reports;
- Engineering Action Plans;
- basic projected-risk reduction when the simulation model is ready.

### Team

Suggested starting price: £79 per month or £790 per year.

Target customer: small and medium engineering, platform and DevOps teams.

Proposed features:

- up to 25 monitored repositories;
- GitHub organisation connection;
- organisation dashboard;
- portfolio health;
- scheduled scans;
- Slack notifications;
- future Microsoft Teams integration;
- repository ownership;
- team members;
- trend history;
- prioritised weekly action plan;
- portfolio-level risk clusters;
- repository comparisons;
- shared reports;
- longer retention;
- future Jira integration;
- role-based access controls;
- future pull-request comments.

### Business

Suggested starting price: £199 per month or £1,990 per year.

Target customer: larger platform teams and growing software companies.

Proposed features:

- up to 100 monitored repositories;
- multiple GitHub organisations;
- daily scheduled scans;
- advanced portfolio reporting;
- custom notification rules;
- longer history and retention;
- API access;
- webhooks;
- Jira integration when implemented;
- risk-cluster analysis;
- projected remediation impact;
- custom policy configuration;
- team and repository ownership mapping;
- audit logs;
- priority support;
- Ask DriftBeacon usage allowance when implemented.

### Enterprise

Suggested pricing: custom.

Proposed features:

- more than 100 repositories;
- negotiated scan capacity;
- SSO and SAML;
- SCIM;
- custom retention;
- regional data residency;
- dedicated or isolated workers;
- customer-managed deployment options;
- self-hosted execution;
- custom scanner integrations;
- custom policies;
- audit and compliance support;
- service-level agreement;
- onboarding assistance;
- premium support;
- procurement and invoicing;
- custom security review.

## Future Entitlement Approach

Plan enforcement must be centralised and capability-based. Do not scatter plan-name checks throughout routes, templates or workers.

Potential future entitlement fields:

- `max_monitored_repositories`;
- `daily_scan_limit`;
- `private_repositories_enabled`;
- `scheduled_scans_enabled`;
- `portfolio_dashboard_enabled`;
- `retention_days`;
- `api_access_enabled`;
- `team_members_limit`.

The current MVP uses `WebConfig` for operational controls such as concurrency, scan rate, clone timeout, scanner timeout, repository file limits and retention. Those controls are not paid-plan enforcement.
