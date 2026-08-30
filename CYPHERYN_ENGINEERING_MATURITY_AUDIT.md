# CYPHERYN Engineering Maturity Audit

Audit date: 2026-08-30

Release track: `v0.9.0` production-readiness

Implementation baseline: `2aa033b7abfdea97ddfb29b8afbd027d4ba06464`

Audit scope: the baseline plus the release-brand residue corrections committed with this document.

## Executive result

CYPHERYN is an advanced pre-1.0 defensive cyber-intelligence platform with strong authorization controls, durable collection, provider certification, isolated active-scanner execution, operational telemetry, evidence provenance, and externally verifiable integrity checkpoints. The engineering maturity assessment is **8.8/10**, up from the original 6.6, the Verification & Hardening assessment of 7.6, and the prior engineering-maturity assessment of 8.2.

The previous audit is obsolete in two material areas. CYPHERYN now ships a separately trusted scanner orchestrator, leaving the normal worker without Docker control, and production scanner configuration now fails closed unless images use immutable SHA-256 digests and a managed egress network carries the required enforcement assertion. Critical-path coverage, supported-provider contracts, and external anchoring have also advanced beyond the previous report.

This is not a `v1.0` recommendation. Production scanner egress still depends on an independently enforced network policy, worker orchestration remains below its long-term coverage target, and hosted release evidence must be collected from the final tagged commit.

## Repository and verification state

- Branch: `main`
- Product version: `0.8.0`; no `v0.9.0` tag was created by this audit.
- Baseline hosted CI: Tests, CYPHERYN cross-platform, CodeQL, and Pages passed for `2aa033b`.
- Baseline supply-chain workflow: failed because it still requested removed `signaltrace-*` image names. The application images built successfully; Trivy could not find the obsolete image reference. This audit corrects that release residue and requires a green rerun on the resulting commit.

### Current local verification

| Area | Result | Evidence |
| --- | --- | --- |
| CYPHERYN API tests | PASS | 150 passed, 0 failed |
| Owned API coverage | PASS | 65% total; 60% gate |
| Critical coverage gates | PASS | all 19 module gates passed |
| Ruff | PASS | API source and tests clean |
| Frontend rendered tests | PASS | 2 passed, 0 failed |
| Frontend lint | PASS | ESLint clean |
| TypeScript | PASS | `tsc --noEmit` clean |
| Frontend production build | PASS | all declared routes built |
| Compose image identities | PASS | `cypheryn-api`, worker, frontend, TAXII, and scanner orchestrator |
| Browser verification | PASS | recolored CYPHERYN UI rendered without console errors |

The Python run emitted deprecation and SQLite resource warnings that do not fail the suite. They should be reduced before `v1.0`, especially leaked test-engine connections, because warning-free tests are easier to operate and diagnose.

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
| Worker orchestration | 61.44% | 60% |
| Detection engine | 70.27% | 70% |
| Normalization | 93.24% | 90% |
| Report exports | 93.75% | 90% |
| Notifications | 84.00% | 80% |
| Malware analysis | 91.55% | 90% |

This is a material improvement over the previous audit: worker orchestration rose from 46%, detection from 15%, normalization and exports from 21%, notifications from 30%, and malware analysis from 28%. The largest remaining critical-path weakness is worker orchestration. Schedule creation, provider outcome combinations, retries, monitoring summaries, and scheduled report generation still need deeper failure and concurrency tests. The central API module is 51%, and several experimental/inherited adapters remain intentionally below supported-provider coverage levels.

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
2. Worker orchestration is 61.44%, above its current gate but below the long-term 75% target.
3. The large API routing module and experimental/inherited providers need more behavioral coverage and simplification.
4. Test runs expose deprecation and unclosed SQLite connection warnings.
5. The orchestrator is a privileged trust component because Docker-socket control is host-equivalent; it must remain unexposed and narrowly deployed.
6. Independent evidence assurance depends on real external retention, key custody, rotation, and periodic offline verification.
7. Inherited SpiderFoot remains an isolated optional legacy surface with mutable Internet-dependent tests.
8. Branch protection, release environment policy, and the final hosted supply-chain result are external GitHub state and must be verified on the exact release commit.

## Engineering scorecard

| Assessment | Score | Rationale |
| --- | ---: | --- |
| Original baseline | 6.6/10 | Broad capability, insufficient proof and hardening |
| Verification & Hardening | 7.6/10 | Authoritative gates, readiness semantics, hard process termination, and integrity chains |
| Previous maturity audit | 8.2/10 | Isolation design, telemetry, signed checkpoints, focused gates, and governance |
| Current production-readiness audit | **8.8/10** | Deployable trusted orchestration, production digest/egress enforcement gates, exhaustive Supported-provider contracts, stronger critical coverage, and operational external anchoring |

## Release recommendation

CYPHERYN is technically positioned for a `v0.9.0` release candidate after the corrected hosted security/supply-chain workflow passes on the exact commit and repository protection settings are confirmed. Do not publish the tag before that evidence exists. `v1.0` should wait for independently enforced scanner egress in a documented production topology, worker orchestration coverage near 75%, warning cleanup, proven external anchor retention/rotation operations, and sustained release-operation evidence.
