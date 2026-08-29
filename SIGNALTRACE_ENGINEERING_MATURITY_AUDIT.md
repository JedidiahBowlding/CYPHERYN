# SignalTrace Engineering Maturity Audit

Audit date: 2026-08-29  
Release candidate: `v0.8.0`  
Audit target: the commit containing this document. Resolve the immutable identifier with `git rev-parse HEAD`; the hosted-CI result linked from that commit is the authoritative record.

## Executive result

SignalTrace's owned application code passes its API and frontend test suites, dependency audits, static checks, Compose smoke test, secret scan, and fixable High/Critical scans of all four shipped images. This release adds a materially stronger scanner-execution design, durable worker health, provider/queue telemetry, focused security coverage gates, independently signed integrity checkpoints, and public-project governance.

The release is not scored as production-complete. The default Compose worker intentionally has no Docker socket and therefore cannot launch configured disposable scanner images; production active scanning still needs a separately trusted orchestrator deployment. Critical orchestration modules also remain below their long-term coverage targets. Provider certification is strongest for the five priority providers but several contract requirements are proven across shared controls rather than by twenty provider-specific tests each.

## Repository state

- Branch: `main`
- Baseline inspected: `9513c1f32ca55ab5a07e155d1c155e1a920032ba`
- Exact release commit and clean status: recorded in the completion report after hosted CI, because a Git commit cannot contain its own hash.
- Version: `0.8.0`; no `v1.0` claim and no release tag created by this audit.

## Verification results

| Area | Result | Evidence |
| --- | --- | --- |
| SignalTrace API tests | PASS | 55 passed, 0 failed |
| Frontend rendered tests | PASS | 2 passed, 0 failed |
| Frontend lint | PASS | ESLint clean |
| TypeScript | PASS | `tsc --noEmit` clean |
| Frontend production build | PASS | all declared routes built |
| API coverage | PASS | 56.39% global, 50% floor |
| Ruff | PASS | owned API source/tests clean |
| npm audit | PASS | 0 vulnerabilities |
| Python audit | PASS | 0 known vulnerabilities; local package is not on PyPI |
| Secret scan | PASS | Gitleaks, 16 commits, no leak |
| Compose validation | PASS | configuration valid |
| Compose smoke | PASS | API, frontend, PostgreSQL, TAXII healthy; worker heartbeat healthy |
| Container scan | PASS | API, worker, frontend, TAXII: 0 fixable High/Critical each |
| SBOM | PASS | CycloneDX generated for all four shipped images |
| Workflow syntax | PASS | all workflow YAML parsed |
| Inherited SpiderFoot tests | ENVIRONMENT-LIMITED | 1,612 passed, 6 network-fixture failures, 214 skipped in legacy Python 3.8 container |

The six inherited failures depend on mutable public blocklists/DNS: EasyList no longer matches the old fixture, DNS for Family/OpenNIC resolution differs, and the live StevenBlack file format changed. SignalTrace-owned code is not involved. These results are reported, not suppressed. A previously verified modern-host baseline had 1,584 inherited passes and 35 skips.

## Coverage

Current focused results:

| Critical module/control | Coverage | Gate |
| --- | ---: | ---: |
| Evidence integrity | 97% | 90% |
| Security controls | 95% | 90% |
| Provider certification | 94% | 90% |
| Observability | 94% | 85% |
| Provider safety | 88% | 85% |
| Scanner isolation | 85% | 80% |
| Process isolation | 81% | 80% |
| External anchoring | 65% | 60% |
| Entire owned API | 56.39% | 50% |

The focused gates pass. `worker.py` (46%), detection (15%), normalization (21%), report exports (21%), notifications (30%), and malware analysis (28%) remain below the requested long-term orchestration/business-logic goals. Raising these is required before `v0.9.0`; this release does not disguise the gap with low-value tests.

## Scanner isolation and authorization

Verified controls include explicit non-floating images, one disposable container per execution, read-only root, dropped capabilities, `no-new-privileges`, CPU/memory/PID/deadline/output/tmpfs limits, reduced environment, no host mounts, no repository mount, no scanner Docker socket, cancellation and timeout force-removal, and bounded output. Active tools fail closed when an isolated image is not configured. Existing tests continue to verify missing, future, expired, revoked, cross-organization, target-mismatch, and per-run active authorization behavior.

Network policy defaults to `none`; `bridge` or a named `signaltrace-*` network must be explicit. Docker bridges cannot enforce target-specific egress by themselves. The trusted runner needs Docker control, but the shipped worker is not granted that control. A production deployment must place the runner in a separate trusted orchestration service or isolated worker node with policy-aware egress. This is a deployment boundary, not a hostile-code sandbox claim.

## Provider certification matrix

Runtime readiness remains independent of support tier: Supported → Installed → Configured → Healthy → Live Verified. Live Verified requires a successful collection timestamp and ages after seven days; it is stale at thirty days.

| Provider | Tier | Adapter | Contract | Runtime readiness |
| --- | --- | --- | --- | --- |
| VirusTotal | Supported | Present | Priority contract suite | Runtime-derived |
| Shodan | Supported | Present | Priority contract suite | Runtime-derived |
| AlienVault OTX | Supported | Present | Priority contract suite | Runtime-derived |
| Censys | Supported | Present | Priority contract suite | Runtime-derived |
| ThreatFox / abuse.ch | Supported | Present | Priority contract suite | Runtime-derived |
| SpiderFoot | Inherited | Present | Upstream behavior | Runtime-derived |
| Active local scanners | Adapter-only | Varies | Isolation/shared controls | Runtime-derived |
| Other SignalTrace-native adapters | Experimental | Present | Partial/shared contracts | Runtime-derived |

The deterministic priority suite proves request construction, credential absence, 401/403/429 handling, malformed response and timeout propagation, security-signal normalization, and secret-free URLs. Shared worker/provider tests prove evidence hashing/provenance, circuit-breaker behavior, and successful-collection timestamp semantics. Ordinary CI makes no live third-party calls. A future certification revision should make every one of the twenty requirements directly parameterized for every Supported provider; until then the matrix is credible but not exhaustive.

## Observability

- `/health/ready` reports API/dependency readiness.
- `/health/workers` separately reports persisted worker identity, version, heartbeat, successful poll, active jobs, failure and staleness.
- `/metrics` exposes Prometheus-compatible worker, queue, evidence, and per-provider request/success/failure/timeout/throttle/authentication/cancellation counts.
- Queue snapshot includes age, wait, execution time, retries, cancellations and expired leases.
- Provider snapshot includes average and p95 latency, circuit state and last successful collection.
- Correlation IDs are accepted/generated at HTTP entry, persisted on jobs, returned to clients and included in structured worker/API logs. Evidence and findings remain traceable through job and evidence references.
- Secret-named structured-log fields are dropped and payloads are not logged.

The local smoke test observed a fresh worker heartbeat while an older stopped worker record was correctly marked stale.

## Evidence and external-anchor verification

Existing evidence and audit SHA-256 chains still pass mutation-detection tests. The new checkpoint format includes scope, head, count, first/last identifiers, timestamp, application version, hash algorithm and checkpoint version. Ed25519 signing keys remain external to normal database records. Offline verification proves signature/key identity, record hashes, chain continuity, head, count and scope; tests reject payload divergence and signature substitution.

The provided filesystem destination is only independent if mounted or synchronized into a separately controlled trust domain. Anchoring is tamper evidence, not absolute prevention, and does not protect history created after the latest checkpoint.

## Supply chain, governance and release status

Present: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, PR template, structured bug template, Dependabot for pip/npm/Actions/Docker/Compose, cross-platform tests, CodeQL, secret scan, dependency audits, four-image vulnerability scans and SBOMs. The release workflow performs tag-triggered gates, builds, SBOMs, source archive, SHA-256 checksum, GitHub artifact attestation and GitHub Release publication.

Recommended `main` branch rules remain a repository-setting task: pull requests/review, required Tests/Cross-platform/Security/CodeQL checks, stale-approval dismissal, conversation resolution, and force-push/deletion prevention.

## Remaining limitations and risks

1. Default Compose does not include a trusted scanner-container orchestrator; active adapters remain safely disabled without it.
2. Target-specific scanner egress requires an environment-specific policy gateway or isolated node.
3. Scanner tags are explicit but production should require immutable digests and signature verification.
4. Critical orchestration and core-business coverage is not yet at the 70–75% long-term target.
5. Priority provider certification combines provider-specific and shared-control tests; direct twenty-case-per-provider coverage is future work.
6. Anchor scheduling, remote immutable destinations, rotation ceremony and ordinary report-export embedding need expansion.
7. Inherited SpiderFoot uses an obsolete Python/Alpine dependency surface and mutable Internet-dependent tests; it should remain isolated and optional.
8. Hosted CI and repository branch settings are external state and must be verified on the final commit.

## Engineering scorecard

| Assessment | Score | Rationale |
| --- | ---: | --- |
| Original baseline | 6.6/10 | Broad capability, insufficient proof and hardening |
| Verification & Hardening audit | 7.6/10 | Clean gates, readiness semantics, process termination and DB-local chains |
| Current engineering-maturity release | 8.2/10 | Stronger isolation design, real operations telemetry, signed external checkpoints, focused gates and OSS release controls; deployment and coverage gaps remain |

Recommendation: the project is credible as `v0.8.x` and can begin narrowly scoped `v0.9.0` work after the final hosted checks pass. It should not move toward `v1.0` until isolated active scanning is deployable without privileged worker access, critical orchestration coverage materially improves, provider certification is exhaustive, and anchors are routinely exported to an independent trust domain.
