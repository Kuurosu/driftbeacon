FROM python:3.12.8-slim-bookworm AS trivy

ARG TRIVY_VERSION=0.72.0
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) trivy_arch="64bit" ;; \
      arm64) trivy_arch="ARM64" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
      -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    trivy --version


FROM python:3.12.8-slim-bookworm AS runtime

ARG CHECKOV_VERSION=3.3.8

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    DRIFTBEACON_WEB_DATABASE=/data/web.sqlite3 \
    DRIFTBEACON_WEB_REPORT_DIR=/data/reports \
    DRIFTBEACON_SCAN_WORK_DIR=/work/scans

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system driftbeacon \
    && useradd --system --gid driftbeacon --home-dir /app --create-home driftbeacon

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . "checkov==${CHECKOV_VERSION}" \
    && python -m pip check \
    && mkdir -p /data/reports /work/scans \
    && chown -R driftbeacon:driftbeacon /app /data /work

USER driftbeacon

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=5).read()" || exit 1

ENTRYPOINT ["driftbeacon"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080", "--output-dir", "/data"]
