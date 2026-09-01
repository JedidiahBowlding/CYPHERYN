FROM debian:bookworm-slim AS security-tools

ARG TRUFFLEHOG_VERSION=3.97.1
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
    fetch_tar trufflesecurity trufflehog "v${TRUFFLEHOG_VERSION}" \
      "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
      "trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" trufflehog; \
    fetch_tar aquasecurity trivy "v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      "trivy_${TRIVY_VERSION}_checksums.txt" trivy; \
    true

# The newest upstream release binaries can lag newly fixed Go stdlib/module
# advisories. Rebuild the affected tools from their immutable release commits
# with the patched compiler and dependency floors instead of suppressing a
# reachable High/Critical container finding.
FROM golang:1.26.6-bookworm AS patched-security-tools

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /src /out

COPY --from=security-tools /out/trivy /out/trivy
COPY --from=security-tools /out/trufflehog /out/trufflehog
COPY build_patched_go_tool.sh /usr/local/bin/build-patched-go-tool

RUN sh /usr/local/bin/build-patched-go-tool gitleaks gitleaks/gitleaks \
      83d9cd684c87d95d656c1458ef04895a7f1cbd8e .
RUN sh /usr/local/bin/build-patched-go-tool grype anchore/grype \
      756eb9a24f7beeafb6871a24e943e8a3ae210695 ./cmd/grype
RUN sh /usr/local/bin/build-patched-go-tool osv-scanner google/osv-scanner \
      c84fa4568f2526d0333e9a914ea8a0a5f74ad68b ./cmd/osv-scanner
RUN sh /usr/local/bin/build-patched-go-tool subfinder projectdiscovery/subfinder \
      b360529eebcd29345e44b3a9da3b2b0c04a13ff2 ./cmd/subfinder
RUN sh /usr/local/bin/build-patched-go-tool syft anchore/syft \
      91a0032987d91b7411b52f6f5c185c5e7f775495 ./cmd/syft

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
COPY --from=patched-security-tools /out/ /usr/local/bin/
COPY tests ./tests

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/quarantine /data/clamav-db \
    && chown -R appuser:appuser /data
USER appuser
EXPOSE 8000
CMD ["uvicorn", "intel_platform.main:app", "--host", "0.0.0.0", "--port", "8000"]
