FROM debian:bookworm-slim AS downloader

ARG SUBFINDER_VERSION=2.16.0
ARG HTTPX_VERSION=1.11.0
ARG NAABU_VERSION=2.6.1
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=10.4.8
ARG NUCLEI_TEMPLATES_COMMIT=e5f19e6144135e107962bb943231413796fd7fe7
ARG NUCLEI_TEMPLATES_SHA256=0dc334333848bd189a589247d6f4eed0d0f9cb9956c00cc45c569630817aaf43
ARG KATANA_VERSION=1.7.0
ARG RUSTSCAN_VERSION=2.4.1
ARG RUSTSCAN_SHA256=f3a4365d939e3b81f25ba8c37852ce9ac9e938c3cc882c5b3e6fff6152c740be
ARG NIKTO_VERSION=2.6.1
ARG NIKTO_SHA256=d1ca1acb05d81a5a6f374c0afdd76b33afa0089278631a20673c0210a71d992f

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /out /downloads

RUN set -eux; \
    fetch_projectdiscovery() { \
      project="$1"; version="$2"; archive="$3"; checksums="$4"; binary="$5"; \
      base="https://github.com/projectdiscovery/${project}/releases/download/v${version}"; \
      curl -fsSL --retry 3 -o "/downloads/${archive}" "${base}/${archive}"; \
      curl -fsSL --retry 3 -o "/downloads/${checksums}" "${base}/${checksums}"; \
      cd /downloads; grep "  ${archive}$" "${checksums}" | sha256sum -c -; \
      unzip -j -q "${archive}" "${binary}" -d /out; chmod 0755 "/out/${binary}"; \
    }; \
    fetch_projectdiscovery subfinder "$SUBFINDER_VERSION" \
      "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
      "subfinder_${SUBFINDER_VERSION}_checksums.txt" subfinder; \
    fetch_projectdiscovery httpx "$HTTPX_VERSION" \
      "httpx_${HTTPX_VERSION}_linux_amd64.zip" \
      "httpx_${HTTPX_VERSION}_checksums.txt" httpx; \
    fetch_projectdiscovery naabu "$NAABU_VERSION" \
      "naabu_${NAABU_VERSION}_linux_amd64.zip" naabu-checksums.txt naabu; \
    fetch_projectdiscovery nuclei "$NUCLEI_VERSION" \
      "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
      "nuclei_${NUCLEI_VERSION}_checksums.txt" nuclei; \
    nuclei_templates="nuclei-templates-${NUCLEI_TEMPLATES_VERSION}.tar.gz"; \
    curl -fsSL --retry 3 -o "/downloads/${nuclei_templates}" \
      "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/${NUCLEI_TEMPLATES_COMMIT}"; \
    echo "${NUCLEI_TEMPLATES_SHA256}  /downloads/${nuclei_templates}" | sha256sum -c -; \
    mkdir -p /nuclei-templates; \
    tar -xzf "/downloads/${nuclei_templates}" --strip-components=1 -C /nuclei-templates; \
    fetch_projectdiscovery katana "$KATANA_VERSION" \
      "katana_${KATANA_VERSION}_linux_amd64.zip" \
      "katana-${KATANA_VERSION}-checksums.txt" katana; \
    rustscan_archive=x86_64-linux-rustscan.tar.gz.zip; \
    curl -fsSL --retry 3 -o "/downloads/${rustscan_archive}" \
      "https://github.com/RustScan/RustScan/releases/download/${RUSTSCAN_VERSION}/${rustscan_archive}"; \
    echo "${RUSTSCAN_SHA256}  /downloads/${rustscan_archive}" | sha256sum -c -; \
    unzip -j -q "/downloads/${rustscan_archive}" -d /downloads/rustscan; \
    tar -xzf /downloads/rustscan/x86_64-linux-rustscan.tar.gz -C /downloads/rustscan; \
    install -m 0755 "$(find /downloads/rustscan -type f -name rustscan | head -1)" /out/rustscan; \
    curl -fsSL --retry 3 -o /downloads/nikto.tar.gz \
      "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz"; \
    echo "${NIKTO_SHA256}  /downloads/nikto.tar.gz" | sha256sum -c -; \
    mkdir -p /nikto; tar -xzf /downloads/nikto.tar.gz --strip-components=1 -C /nikto

FROM python:3.13-slim-bookworm

ARG DNSTWIST_VERSION=20250130

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
       bind9-dnsutils ca-certificates libcap2 libnet-ssleay-perl libxml-writer-perl \
       masscan nmap perl \
    && pip install --no-cache-dir "dnstwist==${DNSTWIST_VERSION}" "dnspython==2.8.0" \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner

COPY --from=downloader /out/ /usr/local/bin/
COPY --from=downloader /nikto/ /opt/nikto/
COPY --from=downloader /nuclei-templates/ /opt/nuclei-templates/
COPY cypheryn-nikto /usr/local/bin/cypheryn-nikto
COPY cypheryn-katana-auth /usr/local/bin/cypheryn-katana-auth
RUN chmod 0755 /usr/local/bin/cypheryn-nikto /usr/local/bin/cypheryn-katana-auth

ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_CONFIG_HOME=/tmp/.config

USER scanner
WORKDIR /tmp
ENTRYPOINT []
