# CYPHERYN Engineering Maturity Audit

Audit date: 2026-08-30

Release track: `v0.9.0` production-readiness

Implementation baseline: `f01c56a4f098d841ad6befdd7f3d1afe833b5260`

Audit scope: the baseline plus the `v0.9.0` verification and release-readiness changes
committed with this document. No release tag was created during the audit.

## Executive result

CYPHERYN is an advanced pre-1.0 defensive cyber-intelligence platform with strong authorization controls, durable collection, provider certification, isolated active-scanner execution, operational telemetry, evidence provenance, and externally verifiable integrity checkpoints. The engineering maturity assessment is **8.8/10**, up from the original 6.6, the Verification & Hardening assessment of 7.6, and the prior engineering-maturity assessment of 8.2.

The previous audit is obsolete in two material areas. CYPHERYN now ships a separately trusted scanner orchestrator, leaving the normal worker without Docker control, and production scanner configuration now fails closed unless images use immutable SHA-256 digests and a managed egress network carries the required enforcement assertion. Critical-path coverage, supported-provider contracts, and external anchoring have also advanced beyond the previous report.

This is not a `v1.0` recommendation. Production scanner egress still depends on an
independently enforced network policy, and longer-term operational evidence is still needed.

## Repository and verification state

- Branch: `main`
- Product version: `0.8.0`; no `v0.9.0` tag was created by this audit.
- Baseline hosted CI: Tests, CYPHERYN cross-platform, CodeQL, Dependabot, and Security and
  supply chain all passed for exact commit `f01c56a`.
- GitHub `main` protection is enabled and enforced for administrators. It requires one
  approving review, dismissal of stale reviews, approval after the last push, resolved
  conversations, linear history, strict up-to-date checks, all 16 current CI check contexts,
  and denies force-pushes and deletion.
- A tag remains prohibited unless every required check is green on the exact candidate
  commit.

### Current local verification

| Area | Result | Evidence |
| --- | --- | --- |
| CYPHERYN API tests | PASS | 156 passed, 0 failed |
| Owned API coverage | PASS | 66% total; worker gate raised to 75% |
| Critical coverage gates | PASS | all 19 module gates passed |
| Ruff | PASS | API source and tests clean |
| Frontend rendered tests | PASS | 2 passed, 0 failed |
| Frontend lint | PASS | ESLint clean |
| TypeScript | PASS | `tsc --noEmit` clean |
| Frontend production build | PASS | all declared routes built |
| Compose image identities | PASS | `cypheryn-api`, worker, frontend, TAXII, and scanner orchestrator |
| Browser verification | PASS | recolored CYPHERYN UI rendered without console errors |

The owned HTTP status deprecations and test-engine resource leaks observed at baseline were
removed. The remaining Python notice originates in FastAPI/Starlette's TestClient shim,
which requests the future `httpx2` package. The frontend build emits Node warnings from
vinext/Vite dependencies; these are upstream notices to track through dependency upgrades.

## Critical-path coverage

| Critical module or control | Coverage | Gate |
| --- | ---: | ---: |
| Evidence integrity | 97.14% | 90% |
| Observability | 93.88% | 85% |
| Process isolation | 80.65% | 80% |
| Provider certification | 94.12% | 90% |
| Provider contract | 96.08% | 85% |
| Provider safety | 88.31% | 85% |
| Supported threat-intelligence adapters | 92.52% | 90% |
| Security controls | 95.00% | 90% |
| External integrity anchoring | 70.43% | 70% |
| Scanner isolation policy | 85.23% | 80% |
| Docker scanner runner | 90.76% | 80% |
| Scanner orchestrator | 82.39% | 80% |
| Orchestrator client | 86.21% | 80% |
| Worker orchestration | 75.04% | 75% |
| Detection engine | 70.27% | 70% |
| Normalization | 93.24% | 90% |
| Report exports | 93.75% | 90% |
| Notifications | 84.00% | 80% |
| Malware analysis | 91.55% | 90% |

This is a material improvement over the previous audit: worker orchestration rose from 46%
to 75.04%, detection from 15%, normalization and exports from 21%, notifications from 30%,
and malware analysis from 28%. New worker tests exercise scheduling, duplicate suppression,
active-authorization denial, direct verification target creation, stale-job alert
deduplication, monitoring summaries, and scheduled PDF persistence. The central API module
remains 51%, and experimental/inherited adapters remain below Supported-provider gates.

## Trusted scanner orchestration

CYPHERYN now includes a deployable `scanner-orchestrator` Compose profile. The ordinary worker and API do not mount the Docker socket. Only the separately trusted orchestrator receives Docker control, is isolated on the internal backend network, and authenticates job-scoped submit, status, and cancellation requests with a generated bearer token.

Verified controls include:

- server-side provider/image/executable allowlists;
- immediate persisted authorization revalidation before active execution;
- one disposable container per execution;
- read-only root filesystem, all capabilities dropped, and `no-new-privileges`;
- bounded CPU, memory, PID count, deadline, output, and temporary storage;
- reduced environments with no application credentials;
- no repository, host, or worker-directory mounts in scanner children;
- forced container removal for cancellation, timeout, startup cleanup, and shutdown;
- fail-closed behavior for missing, unreachable, unauthenticated, or policy-rejecting orchestration.

Adapters requiring host-side file exchange remain disabled through the remote contract rather than weakening isolation with worker mounts.

### Production supply-chain and egress policy

Production mode requires every configured scanner image to use an immutable `@sha256:` digest. Floating tags and the unrestricted Docker `bridge` network are rejected. Active scanners must use a `cypheryn-egress-*` network whose Docker metadata asserts `cypheryn.egress-policy=enforced`; an absent, inaccessible, or unlabeled network fails closed.

The label is an assertion, not a firewall. Operators must place the orchestrator behind a policy-aware gateway or on a dedicated scanner node that actually constrains authorized destinations. CYPHERYN correctly refuses to pretend that ordinary Docker bridge networking provides destination-level enforcement.

## Supported-provider certification

The five Supported providers—VirusTotal, Shodan, AlienVault OTX, Censys, and abuse.ch ThreatFox—are now directly covered by one deterministic contract matrix. Adding a provider to the Supported tier without a complete case fails CI.

Every provider case proves HTTPS request construction, correct target encoding and credential placement, missing credentials, 401/403 failures, 429 throttling, malformed transport data, provider-schema rejection, timeout, cancellation before and during I/O, provider-specific normalization, secret redaction, evidence provenance, non-synthetic status, and SHA-256 response fingerprints. Tests use mocked transports and do not require customer keys or live third-party calls.

The controlled live-verification runbook specifies authorized benign indicators,
least-privilege accounts, credential handling, expected evidence, UTC recording, staleness,
and failure handling. Live provider calls remain deliberately outside ordinary CI.

Runtime readiness remains a separate operational truth:

**Supported → Installed → Configured → Healthy → Live Verified**

`Live Verified` still requires a recorded successful real collection and ages with time; certification does not manufacture that status.

## Evidence integrity and independent anchoring

Evidence and audit events retain linked SHA-256 integrity chains. CYPHERYN now operationalizes external checkpoints rather than merely providing a signing primitive:

- a capability-dropped initializer creates and rotates Ed25519 keys outside PostgreSQL;
- the API never receives the private-key mount;
- the worker creates due checkpoints when evidence first appears, the chain head changes, or the interval elapses;
- immutable `*.anchor.json` and `*.integrity.json` bundles are written to the configured destination;
- offline verification checks signature, trusted key identity, checkpoint digest, record hashes, chain continuity, scope, count, and chain head;
- JSON and PDF reports embed the latest public checkpoint metadata;
- key rotation retains historical verification material.

The key-operations runbook covers separate custody, encrypted backup, authenticated
public-key distribution, verifier key-ID pinning, compromise response and revocation,
quarterly restore drills, and explicit continuity handling after active-key loss.

The default local directory is not an independent trust domain. Production assurance requires separately administered WORM, object-lock, immutable NFS, or equivalent storage plus monitored key rotation and offline verification.

## Observability and operations

CYPHERYN exposes API readiness, worker heartbeat and version, active jobs, queue depth/age/wait/execution/retry/cancellation/lease metrics, provider latency and failures, circuit states, evidence counts, and Prometheus-compatible metrics. Correlation IDs propagate from HTTP entry through persisted jobs and structured logs. Secret-named log fields and payload logging are suppressed.

The doctor utility verifies core service readiness, the trusted orchestrator when enabled, and protected integrity-anchor paths without weakening key-directory permissions.

## Release and supply-chain machinery

The release path now consistently uses CYPHERYN public identities:

- images: `cypheryn-api`, `cypheryn-worker`, `cypheryn-frontend`, `cypheryn-taxii`, and `cypheryn-scanner-orchestrator`;
- SBOMs: `cypheryn-*.spdx.json`;
- source package: `CYPHERYN-vX.Y.Z.tar.gz` with a `CYPHERYN-vX.Y.Z/` archive prefix;
- provenance subject: the CYPHERYN source archive;
- GitHub Release title: `CYPHERYN vX.Y.Z`;
- issue templates and private-advisory links: the CYPHERYN repository.

The tag-triggered release continues to run API and frontend tests, critical coverage gates, Ruff, dependency audits, five image builds, High/Critical Trivy gates, SPDX SBOM generation, SHA-256 checksums, GitHub build-provenance attestation, and release publication.

## Rebrand residue classification

| Occurrence class | Decision |
| --- | --- |
| Release names, images, archives, SBOMs, attestations, titles | Public branding; renamed to CYPHERYN |
| Issue templates, security-advisory URL, scanning-policy comments | Public/developer branding; renamed to CYPHERYN |
| Compose source project and image identities | Safe internal rename already completed; validated as `cypheryn-*` |
| Tracked database, migration, environment, and volume identifiers | No remaining tracked `signaltrace` identifiers found |
| Local ignored `platform/api/signaltrace-dev.db` | User-owned development data; deliberately not renamed or deleted by this audit |
| Git history and legacy remote | Historical compatibility/audit record; not rewritten |

The ignored local database is not shipped, packaged, or referenced by current source. Removing or renaming it could discard or fork local data, so it remains outside the rebrand commit unless the operator explicitly migrates it.

## Remaining limitations and risks

1. Production egress enforcement is external infrastructure; the Docker-network label only records a fail-closed deployment assertion.
2. The large API routing module and experimental/inherited providers need more behavioral coverage and simplification.
3. One TestClient deprecation and several vinext/Vite build notices remain upstream-owned.
4. The orchestrator is a privileged trust component because Docker-socket control is host-equivalent; it must remain unexposed and narrowly deployed.
5. Independent evidence assurance depends on real external retention, key custody, rotation, restore drills, and periodic offline verification.
6. Inherited SpiderFoot remains an isolated optional legacy surface with mutable Internet-dependent tests.
7. Live-provider verification requires operator-controlled accounts and authorized indicators and is intentionally not asserted by deterministic CI.
8. The exact release-candidate commit must retain green hosted checks; no local result substitutes for that external evidence.

## Engineering scorecard

| Assessment | Score | Rationale |
| --- | ---: | --- |
| Original baseline | 6.6/10 | Broad capability, insufficient proof and hardening |
| Verification & Hardening | 7.6/10 | Authoritative gates, readiness semantics, hard process termination, and integrity chains |
| Previous maturity audit | 8.2/10 | Isolation design, telemetry, signed checkpoints, focused gates, and governance |
| Current production-readiness audit | **8.8/10** | Deployable trusted orchestration, production digest/egress enforcement gates, exhaustive Supported-provider contracts, stronger critical coverage, and operational external anchoring |

## Release recommendation

CYPHERYN is technically positioned for `v0.9.0` once the exact release-candidate commit has
passed every protected hosted check. Repository protection is now confirmed, the worker
gate is 75%, release naming is regression-tested, dependency audits are clean, and no tag
was created prematurely. `v1.0` should wait for independently enforced scanner egress in a
documented production topology, broader API/adapter verification, repeated live-provider
operations, proven independent anchor retention/rotation/restore, and sustained production
evidence.

NOT READY FOR v0.9.0 TAG
