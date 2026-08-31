FROM debian:bookworm-slim AS security-tools

ARG GITLEAKS_VERSION=8.30.1
ARG TRUFFLEHOG_VERSION=3.97.1
ARG OSV_SCANNER_VERSION=2.5.1
ARG SYFT_VERSION=1.51.1
ARG GRYPE_VERSION=0.118.0
ARG TRIVY_VERSION=0.74.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /downloads /out

RUN set -eux; \
    fetch_tar() { \
      owner="$1"; project="$2"; tag="$3"; archive="$4"; checksums="$5"; binary="$6"; \
      base="https://github.com/${owner}/${project}/releases/download/${tag}"; \
      curl -fsSL --retry 3 -o "/downloads/${archive}" "${base}/${archive}"; \
      curl -fsSL --retry 3 -o "/downloads/${checksums}" "${base}/${checksums}"; \
      cd /downloads; grep "  ${archive}$" "${checksums}" | sha256sum -c -; \
      tar -xzf "${archive}" -C /downloads; \
      install -m 0755 "/downloads/${binary}" "/out/${binary}"; \
    }; \
    fetch_tar gitleaks gitleaks "v${GITLEAKS_VERSION}" \
      "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      "gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks; \
    fetch_tar trufflesecurity trufflehog "v${TRUFFLEHOG_VERSION}" \
      "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
      "trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" trufflehog; \
    fetch_tar anchore syft "v${SYFT_VERSION}" \
      "syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
      "syft_${SYFT_VERSION}_checksums.txt" syft; \
    fetch_tar anchore grype "v${GRYPE_VERSION}" \
      "grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
      "grype_${GRYPE_VERSION}_checksums.txt" grype; \
    fetch_tar aquasecurity trivy "v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      "trivy_${TRIVY_VERSION}_checksums.txt" trivy; \
    subfinder_version="2.16.0"; \
    subfinder_archive="subfinder_${subfinder_version}_linux_amd64.zip"; \
    subfinder_base="https://github.com/projectdiscovery/subfinder/releases/download/v${subfinder_version}"; \
    curl -fsSL --retry 3 -o "/downloads/${subfinder_archive}" \
      "${subfinder_base}/${subfinder_archive}"; \
    curl -fsSL --retry 3 -o /downloads/subfinder-checksums.txt \
      "${subfinder_base}/subfinder_${subfinder_version}_checksums.txt"; \
    cd /downloads; grep "  ${subfinder_archive}$" subfinder-checksums.txt | sha256sum -c -; \
    unzip -j -q "${subfinder_archive}" subfinder -d /out; chmod 0755 /out/subfinder; \
    osv_base="https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}"; \
    curl -fsSL --retry 3 -o /downloads/osv-scanner_linux_amd64 \
      "${osv_base}/osv-scanner_linux_amd64"; \
    curl -fsSL --retry 3 -o /downloads/osv-scanner_SHA256SUMS \
      "${osv_base}/osv-scanner_SHA256SUMS"; \
    cd /downloads; grep '  osv-scanner_linux_amd64$' osv-scanner_SHA256SUMS | sha256sum -c -; \
    install -m 0755 /downloads/osv-scanner_linux_amd64 /out/osv-scanner

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Pull fixed Debian security packages into the immutable release image instead
# of relying on the moving base tag to have been republished already.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends clamav git yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[dev]" \
    "checkov==3.3.16" \
    "dnstwist==20250130" \
    "maigret==0.6.5" \
    "semgrep==1.175.0"
COPY --from=security-tools /out/ /usr/local/bin/
COPY tests ./tests

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/quarantine /data/clamav-db \
    && chown -R appuser:appuser /data
USER appuser
EXPOSE 8000
CMD ["uvicorn", "intel_platform.main:app", "--host", "0.0.0.0", "--port", "8000"]
