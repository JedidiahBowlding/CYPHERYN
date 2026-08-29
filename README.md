<div align="center">
  <a href="https://github.com/JedidiahBowlding/SignalTrace">
    <img src="platform/frontend/public/signaltrace-logo.png" alt="SignalTrace logo" width="220">
  </a>

  <h1>SignalTrace</h1>
  <h3>See the exposure. Prove the risk. Track the fix.</h3>

  <a href="https://github.com/JedidiahBowlding/SignalTrace">Repository</a> ·
  <a href="https://github.com/JedidiahBowlding/SignalTrace/issues">Issues</a> ·
  <a href="ROADMAP.md">Roadmap</a> ·
  <a href="SECURITY_BOUNDARIES.md">Security boundaries</a>
</div>

SignalTrace is a local-first cyber-intelligence operations platform that turns authorized OSINT, attack-surface observations, threat feeds, identity exposure, source-code intelligence, and vulnerability evidence into investigations your team can verify and act on.

It is more than a scanner. SignalTrace preserves the chain from target authorization to raw observation, normalized entity, relationship, finding, analyst decision, remediation, rescan, and final report.

The source, issue tracker, and release history are hosted in the [SignalTrace GitHub repository](https://github.com/JedidiahBowlding/SignalTrace).

## Why SignalTrace

Traditional OSINT tools return enormous result sets. Vulnerability scanners return isolated snapshots. Threat feeds return indicators without your asset context. SignalTrace brings those signals together and answers the operational questions:

- What is exposed right now?
- Which domains, hosts, services, identities, repositories, packages, certificates, and indicators are connected?
- What evidence supports each finding?
- How could the weakness realistically be used against the asset?
- What should be fixed, and how do we verify that the fix worked?
- What changed since the previous scan?
- Which findings are new, recurring, resolved, accepted, or awaiting review?

## The SignalTrace operating loop

```text
Authorize scope
      ↓
Collect passive intelligence ──→ Run approved active verification
      ↓                                      ↓
Normalize entities, evidence, and relationships
      ↓
Correlate threat intelligence and detection rules
      ↓
Score, explain, assign, and remediate findings
      ↓
Rescan automatically ──→ Compare evidence ──→ Alert on change
      ↓
Generate evidence-grounded reports and exports
```

Every active capability remains bounded by recorded authorization. AI assistance is advisory and cannot silently expand scope or replace source evidence.

## What SignalTrace can do

### Attack-surface discovery

- Discover DNS records, subdomains, certificates, hosts, and resolved IP addresses.
- Enrich public IPs automatically and map services back to the investigation graph.
- Inspect web posture, TLS, security headers, cookies, redirects, and externally visible services.
- Identify unexpected public services and retain the exact host, port, protocol, provider, and collection time.
- Perform bounded direct verification only when the target authorization permits it.

### Threat intelligence fusion

- Extract VirusTotal verdict counts and malware associations.
- Correlate AlienVault OTX pulse matches.
- Enrich Internet assets with Censys and Shodan.
- Add GreyNoise and AbuseIPDB reputation context.
- Match URLhaus and abuse.ch ThreatFox records.
- Consume TAXII 2.1 collections and normalize STIX 2.1 indicators.
- Run a private local TAXII collection seeded with trusted public threat data.

### Identity and exposure intelligence

- Investigate organizations, people, usernames, and public identity signals.
- Use Maigret and supported public sources for account discovery.
- Integrate approved breach-exposure checks such as Have I Been Pwned.
- Connect identity evidence to domains, repositories, infrastructure, and findings.

### Source code and software supply chain

- Support repository and secret discovery workflows.
- Normalize Semgrep, TruffleHog, OSV, Syft, and Trivy results when those local tools are installed.
- Track packages, vulnerabilities, code evidence, and remediation state inside the same investigation.
- Generate detection artifacts from active intelligence indicators.

### Vulnerability operations

- Integrate local Greenbone/OpenVAS for explicitly authorized vulnerability assessment.
- Support ZAP and other installed verification tools through bounded provider contracts.
- Show contextual help on vulnerability findings: hover the help control to see how the website could be attacked and how the weakness can be fixed.
- Manage finding status, ownership, notes, acceptance, resolution, recurrence, and evidence history.
- Rescan the same target and compare old evidence with the new observation instead of overwriting history.

### Evidence graph and reporting

- Explore entities and relationships through an interactive, zoomable graph.
- Trace every claim back to observations and source metadata.
- Filter large workspaces into dedicated paginated sections.
- Generate branded PDF and structured exports with evidence manifests.
- Produce source-constrained local-AI narratives while keeping the factual record authoritative.

### Continuous monitoring

- Schedule recurring investigations and automatic rescans.
- Persist jobs with leases, retries, heartbeats, cancellation, deadlines, and recovery after interruption.
- Compare collection snapshots and create change notifications.
- Deliver configured in-app, email, or webhook alerts.
- Maintain a complete finding lifecycle rather than a pile of disconnected scan reports.

## Provider architecture

SignalTrace separates a provider being **supported**, **configured**, **enabled**, and **available**:

- Built-in network providers are enabled through encrypted organization settings.
- Local tools are automatically available when their executable is installed in that runtime.
- Missing optional tools do not prevent the platform from starting.
- Provider credentials are encrypted in PostgreSQL and never returned to the browser after storage.
- Quotas, deadlines, failure thresholds, circuit breakers, and emergency kill switches apply per organization.

Supported adapters include VirusTotal, Shodan, Censys, GreyNoise, AlienVault OTX, AbuseIPDB, URLhaus, abuse.ch ThreatFox, TAXII, RDAP, certificate transparency, DNS discovery, domain security, web posture, public identity, Maigret, HIBP, OpenVAS, local service observation, source-code providers, and supply-chain providers.

Optional local-tool contracts include Subfinder, Nuclei, Naabu, ProjectDiscovery HTTPX, Gowitness, DNSX, Katana, ZMap, Nmap, Masscan, DNS Twist, TruffleHog, Semgrep, OSV Scanner, Syft, Trivy, and testssl.sh. Installation and authorization still determine whether an individual tool can run.

## Architecture

```text
                                  ┌────────────────────┐
                                  │ Encrypted provider │
                                  │ credentials/policy │
                                  └─────────┬──────────┘
                                            │
Browser ──→ SignalTrace Console ──→ SignalTrace API ──→ PostgreSQL
                                            │               ↑
                                            ↓               │
                                      Durable Worker ───────┘
                                            │
                 ┌──────────────────────────┼──────────────────────────┐
                 ↓                          ↓                          ↓
          Passive providers          Local TAXII/STIX          Authorized tools
                 │                          │                          │
                 └──────────────────────────┴──────────────────────────┘
                                            ↓
                             Evidence · Graph · Findings · Reports
```

The default Docker stack contains:

| Service | Role | Public port |
| --- | --- | --- |
| `frontend` | SignalTrace web console | `3000` |
| `api` | Authorization, investigations, evidence, reporting, provider control | `8000` |
| `worker` | Durable collection, monitoring, comparison, and report jobs | Internal only |
| `postgres` | System of record | Internal only |
| `taxii` | Private local TAXII 2.1/STIX collection | `9000` |

Ollama is optional for local AI assistance. SpiderFoot and Greenbone remain isolated optional capabilities. SignalTrace core does not require Redis or IntelOwl.

## Quick start

### Requirements

- Docker Desktop with Docker Compose v2
- Python 3.12+ for the safe cross-platform bootstrap and diagnostic tools
- Git when cloning from GitHub
- 8 GB or more available RAM recommended

No paid intelligence-provider account is required to start SignalTrace.

### Clone SignalTrace

```bash
git clone https://github.com/JedidiahBowlding/SignalTrace.git
cd SignalTrace
```

### macOS Terminal or Windows WSL

```bash
python3 scripts/setup.py --start
python3 scripts/doctor.py
```

### Windows PowerShell

```powershell
py scripts/setup.py --start
py scripts/doctor.py
```

The setup utility:

1. Creates `.env` when needed.
2. Generates unique database, encryption, and TAXII secrets.
3. Preserves all configured values on later runs.
4. Validates Docker and Compose.
5. Builds and starts SignalTrace.
6. Never prints secret values.

Open [http://localhost:3000](http://localhost:3000).

## Service URLs and health

| Endpoint | Default URL | Healthy result |
| --- | --- | --- |
| SignalTrace | `http://localhost:3000` | Landing page |
| API readiness | `http://localhost:8000/health/ready` | `{"status":"ready"}` |
| API documentation | `http://localhost:8000/api/docs` | Interactive OpenAPI UI |
| Local TAXII | `http://localhost:9000/health` | HTTP 200 JSON |

Host ports can be changed in `.env`.

macOS/WSL verification:

```bash
docker compose ps
curl http://localhost:8000/health/ready
python3 scripts/doctor.py
```

Windows PowerShell verification:

```powershell
docker compose ps
curl.exe http://localhost:8000/health/ready
py scripts/doctor.py
```

## Daily operations

```bash
# Start
docker compose up -d

# Follow logs
docker compose logs -f

# Rebuild after code changes
docker compose up -d --build

# Restart
docker compose restart

# Stop while preserving data
docker compose down
```

Start the optional inherited SpiderFoot service:

```bash
docker compose --profile spiderfoot up -d spiderfoot
```

## Configuration and credentials

The root [.env.example](.env.example) contains only host/runtime configuration. Provider API keys belong in SignalTrace Settings, not in `.env`.

Core generated values:

- `POSTGRES_PASSWORD`
- `PLATFORM_PROVIDER_ENCRYPTION_KEY`
- `TAXII_TOKEN`

Optional configuration includes host ports, OIDC, Ollama, and SMTP notifications. Never commit `.env`, provider keys, tokens, investigation databases, reports, or collected samples.

## macOS and Windows

The Docker workflow supports Intel macOS and uses multi-architecture core images for Apple Silicon. Windows 11 uses Docker Desktop with its WSL2 backend. Full instructions, explicit shell labels, architecture notes, and limitations are in the [cross-platform audit](docs/CROSS_PLATFORM_AUDIT.md).

For Windows setup, verify WSL2 in an Administrator PowerShell:

```powershell
wsl --status
wsl --install
```

A reboot may be required.

## Development and tests

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for native frontend/API setup, database backup and restore, provider-free development, and the contributor workflow.

```bash
docker compose run --rm --no-deps api pytest
docker compose run --rm --no-deps frontend npm test
```

The cross-platform CI matrix covers Ubuntu, macOS, and Windows for application tests and portability utilities.

## Updating

Back up important evidence first:

```bash
git pull
docker compose pull
docker compose up -d --build
python3 scripts/doctor.py
```

SignalTrace upgrades its application schema during API startup. Never reset volumes as part of a normal update.

## Resetting local development data

```bash
python3 scripts/reset_dev.py
```

PowerShell uses `py scripts/reset_dev.py`. The utility requires the operator to type `DELETE`. It removes the database, TAXII state, quarantine, and other Compose volumes and is unrecoverable without a backup.

## Security model

- Authorization scope is a first-class record, not a checkbox hidden inside a scanner.
- Active collection requires explicit target authorization.
- Provider secrets are encrypted at rest and redacted from API responses.
- PostgreSQL is not exposed to the host by default.
- Containers use loopback publication, internal networking, non-root users, read-only filesystems, and bounded writable volumes where compatible.
- AI output is constrained by retrieved evidence and is never the authoritative source.
- Vulnerability explanations describe plausible abuse paths; they do not claim exploitation occurred.

For production deployment, disable development identity, configure OIDC, rotate every development secret, apply HTTPS and network controls, establish backup/retention policy, and complete an environment-specific security review.

## Authorized use

SignalTrace is for defensive security, asset owners, and explicitly authorized assessments. Passive OSINT and active testing have different legal and operational effects. Do not scan third-party systems merely because they are reachable from the Internet.

## Upstream heritage and attribution

This repository contains inherited SpiderFoot 4 source under its original names so that licensing, compatibility, and upstream provenance remain clear. SpiderFoot is an optional isolated capability, not the product identity. Its internal modules, notices, `VERSION`, and required attribution are intentionally preserved.

See [LICENSE](LICENSE), [LICENSE_AUDIT.md](LICENSE_AUDIT.md), and upstream notices before redistribution. The repository should gain a dedicated third-party notices file before its first public release.

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for Docker, port collisions, database startup, TAXII, WSL2, Apple Silicon, permissions, optional providers, and recovery steps.

## Contributing

Fork the published repository, clone your fork, create a feature branch, start SignalTrace, run the affected tests, and open a pull request. Contributors do not need paid providers. Never place credentials or customer evidence in fixtures, screenshots, logs, issues, or commits.
