# CYPHERYN Tool Integration Roadmap

## Phase 1 — Discovery and validation

- [x] Integrate Subfinder for passive subdomain discovery
- [x] Integrate HTTPx for live-host and web-technology detection
- [x] Integrate Naabu for authorized TCP port discovery
- [x] Integrate Nuclei for template-based vulnerability checks
- [x] Integrate testssl.sh for TLS and cipher analysis
- [x] Normalize results into CYPHERYN entities, evidence, and findings
- [ ] Apply authorization, timeout, cancellation, and rate-limit controls
- [x] Add individual enable/disable controls for every tool
- [x] Display tool versions and health status

## Phase 2 — Network assessment

- [x] Integrate Nmap service and version detection
- [x] Add carefully approved Nmap NSE checks
- [x] Integrate RustScan as an optional port-discovery engine
- [x] Add Masscan for explicitly authorized bounded IP ranges
- [x] Enforce conservative Masscan rate limits
- [x] Correlate ports with Censys and Shodan observations
- [x] Compare current and previous service exposure
- [x] Create findings when unexpected services appear
- [x] Resolve findings after two clean observations

## Phase 3 — Web application security

- [x] Integrate OWASP ZAP passive scanning
- [x] Add ZAP spidering for authorized websites
- [x] Add authenticated scan profiles
- [x] Require additional approval for active ZAP attacks
- [x] Integrate Katana for endpoint discovery
- [x] Integrate Nikto for server configuration checks
- [x] Integrate Wappalyzer-compatible technology detection through HTTPx
- [x] Track discovered URLs, forms, and APIs
- [x] Deduplicate overlapping Nuclei and ZAP findings by canonical CWE and asset

## Phase 4 — Domain and email security

- [x] Integrate DNSTwist for look-alike domains
- [x] Detect possible typosquatting and homoglyphs
- [x] Validate SPF
- [x] Validate DKIM (known-selector discovery; selectors cannot be inferred universally)
- [x] Validate DMARC
- [x] Validate MTA-STS
- [x] Validate TLS-RPT
- [x] Validate BIMI
- [x] Monitor certificate transparency for new subdomains
- [x] Monitor DNS and nameserver changes
- [x] Monitor certificate expiration and replacement
- [x] Add cautious dangling-CNAME takeover checks (verification required)

## Phase 5 — Source-code security

- [x] Integrate Gitleaks
- [x] Integrate TruffleHog
- [x] Integrate Semgrep
- [x] Integrate OSV-Scanner
- [x] Support explicitly authorized local repositories
- [x] Support explicitly authorized GitHub repositories
- [x] Prevent secrets from appearing in logs or evidence payloads
- [x] Store only fingerprints and redacted locations (no source excerpts)
- [x] Correlate repository evidence with known public assets using bounded in-memory matching

## Phase 6 — Containers and software supply chain

- [x] Integrate Trivy
- [x] Integrate Grype
- [x] Integrate Syft
- [x] Generate bounded CycloneDX software bills of materials
- [x] Detect vulnerable dependencies
- [x] Detect exposed secrets in images without retaining secret values
- [x] Detect unsafe container configuration
- [x] Track CVE remediation across repeated scans
- [x] Monitor newly disclosed CVEs affecting stored components with daily rescans

## Phase 7 — Cloud security

- [x] Integrate Checkov for infrastructure-as-code
- [ ] Integrate Prowler for cloud posture
- [ ] Integrate ScoutSuite
- [ ] Support AWS assessment credentials
- [ ] Support Azure assessment credentials
- [ ] Support Google Cloud assessment credentials
- [x] Support Kubernetes configuration assessment through authorized Checkov repository scans
- [ ] Encrypt cloud credentials at rest
- [ ] Add least-privilege credential instructions
- [ ] Require explicit cloud-account authorization
- [ ] Import cloud assets into the exposure graph

## Phase 8 — Vulnerability management

- [x] Deploy Greenbone/OpenVAS locally
- [x] Integrate Greenbone Management Protocol
- [x] Synchronize vulnerability feeds
- [x] Create and schedule scan targets
- [x] Import CVEs, CVSS scores, and remediation guidance
- [x] Track scan progress and failures
- [x] Deduplicate OpenVAS and Nuclei findings
- [x] Compare vulnerability results between scans
- [x] Add remediation verification
- [x] Add exception and risk-acceptance workflows

## Phase 9 — Threat-intelligence platform

- [x] Evaluate OpenCTI deployment
- [x] Evaluate MISP deployment
- [ ] Integrate OpenCTI connectors
- [ ] Integrate MISP feeds and events
- [x] Import STIX 2.1 bundles
- [x] Support TAXII collections
- [x] Correlate indicators with CYPHERYN assets
- [x] Track malware, campaigns, actors, and infrastructure
- [x] Add indicator confidence and expiration
- [x] Prevent old indicators from creating permanent false alerts

## Phase 10 — Malware and detection engineering

- [x] Integrate YARA
- [x] Integrate ClamAV
- [x] Support authorized file and hash analysis
- [x] Integrate Sigma rules
- [x] Export Sigma detections
- [x] Export Suricata rules
- [x] Integrate Suricata alerts
- [x] Integrate Zeek logs
- [x] Correlate network detections with investigations
- [x] Quarantine uploaded samples from the main application

## Phase 11 — Identity exposure

- [x] Integrate Maigret or Sherlock
- [x] Add username lookup confidence controls
- [x] Integrate Have I Been Pwned for verified domains
- [x] Support permitted email-address checks
- [x] Detect public credential and breach exposure
- [x] Add false-positive review controls
- [x] Avoid storing plaintext passwords or breach contents
- [x] Link identities to organizations only with supporting evidence

## Phase 12 — Monitoring and alerting

- [x] Schedule provider refreshes
- [x] Schedule direct verification
- [x] Add per-finding monitoring frequency
- [x] Add an in-app notification center
- [x] Add email notifications
- [x] Add webhook notifications
- [x] Alert when findings open
- [x] Alert when findings change
- [x] Alert when findings resolve
- [x] Alert when findings reopen
- [x] Deduplicate repeated alerts
- [x] Add quiet periods and maintenance windows
- [x] Add failed-job and delayed-job monitoring
- [x] Regenerate AI summaries after completed cycles

## Phase 13 — Reporting and exports

- [x] Generate executive PDF reports
- [x] Generate technical remediation reports
- [x] Export JSON
- [x] Export CSV
- [x] Export STIX 2.1
- [x] Export evidence timelines
- [x] Include provider and direct-observation timestamps
- [x] Include finding lifecycle history
- [x] Include resolved and reopened findings
- [x] Add scheduled reports
- [x] Add report branding and organization logos
- [x] Digitally hash reports and evidence exports

## Platform-wide requirements

- [x] Every active tool must require valid authorization
- [x] Clearly label passive versus active tools
- [x] Keep integrations unavailable until correctly configured
- [x] Show configuration and health status visually
- [x] Store credentials encrypted
- [x] Never return stored credentials to the frontend
- [x] Redact secrets from logs and evidence
- [x] Use durable asynchronous jobs
- [x] Support cancellation, retries, and timeouts
- [x] Record complete audit history
- [x] Track tool and ruleset versions
- [x] Preserve raw evidence hashes
- [x] Normalize findings and remove duplicates
- [x] Require supporting evidence for AI-generated claims
- [x] Add unit, integration, and end-to-end tests for every provider
