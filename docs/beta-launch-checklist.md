# DriftBeacon beta launch checklist

This checklist is for a controlled public beta. It is not a production-readiness claim.

## Before launch

- Deploy the current known-good commit.
- Configure the domain and HTTPS.
- Choose `DRIFTBEACON_BETA_ACCESS_MODE=invite` or `open`.
- Generate beta access codes if invite mode is enabled.
- Set `DRIFTBEACON_RATE_LIMIT_SECRET` to a long random value.
- Configure daily scan, repository size, file count and retention limits.
- Verify no AWS or host credentials are mounted into the worker.
- Verify the worker runs as a non-root user.
- Verify `/health/live` and `/health/ready`.
- Run a small test scan.
- View `/sample-report`.
- Verify report Markdown and JSON downloads.
- Submit anonymous feedback.
- Submit private-monitoring interest with a consenting test email.
- Run `driftbeacon beta-status`.
- Export feedback to a local ignored CSV file.
- Verify retention cleanup.
- Verify backups.
- Confirm disk free space.
- Test `DRIFTBEACON_BETA_ACCEPTING_SCANS=false`.
- Test invalid, private, oversized and unsupported-target repositories.

## During beta

- Review queue length and failed scans daily.
- Review disk usage daily.
- Run or verify retention cleanup.
- Inspect feedback exports locally.
- Contact users only when they gave consent.
- Keep scan limits conservative.
- Pause scans if failures or resource use become unsafe.

## Stop conditions

Pause new scans when:

- disk space becomes low;
- the worker repeatedly crashes;
- the queue grows beyond expected limits;
- scan isolation appears compromised;
- unexpected costs occur;
- reports expose sensitive internal information;
- abuse becomes persistent.

## Success signals

Record:

- number of testers;
- scans completed;
- repeat testers;
- report views;
- feedback response rate;
- percentage saying the report changed prioritisation;
- private-monitoring interest;
- users willing to discuss paid monitoring.

## Verification commands

```sh
python -m pytest
ruff check .
mypy src
make run-sample
driftbeacon --help
driftbeacon analyse --help
driftbeacon web --help
driftbeacon worker --help
driftbeacon web-cleanup --help
driftbeacon beta-status --help
driftbeacon feedback-export --help
docker compose config
```

Docker build and Compose smoke testing also need a running Docker daemon:

```sh
docker compose build
docker compose up -d
docker compose ps
```
