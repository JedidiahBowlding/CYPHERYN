# CYPHERYN Verification & Hardening Release — Technical Audit

**Audit date:** 2026-08-29  
**Repository:** `JedidiahBowlding/CYPHERYN`
**Base commit:** `5d5815946da3ec73f58f0f57f9389b18747e8bd7` (`main`)  
**Audited state:** current uncommitted verification-and-hardening working tree  
**Method:** read-only execution and inspection. This report is the only audit deliverable; no failure was fixed or suppressed.

## 1. Executive Summary

This release materially improves CYPHERYN. TypeScript and Ruff now pass; API tests grew from 22 to 44; the inherited suite has zero failures; direct npm and API Python audits are clean; CI targets `main` and includes coverage, type, secret, container, Compose-health, and SBOM gates; five priority providers have deterministic contract tests; local tools have hard process-tree termination; and evidence/audit records now form scoped SHA-256 chains.

Provider readiness is implemented as **Supported → Installed → Configured → Healthy → Live Verified**. Live verification requires a recorded successful collection timestamp and is correctly presented as point-in-time evidence.

The local release gates are green. The rendered landing-page assertion now validates the optimized image URL. The API image upgrades Debian security packages during its build and contains OpenSSL 3.5.7; Trivy reports zero unsuppressed HIGH/CRITICAL findings. Two narrowly documented exceptions cover `msgpack` and `setuptools` records that Trivy derives from pip's vendored sources even though runtime metadata confirms neither distribution is installed. The API image still contains development dependencies/tests, the frontend image is not minimized/non-root, provider breadth exceeds default runnable capability, and hash chains are not independently anchored.

**Overall engineering score: 7.6/10**, up from 6.6/10. Local release gates pass; hosted CI against the exact committed tree is still required before tagging.

## 2. Environment Tested

| Item | Verified value |
|---|---|
| Host | macOS 26.5.2, Darwin 25.5.0, x86_64 Intel Mac, 16 GiB |
| Python | 3.13.7 platform; 3.10.19 isolated inherited suite |
| Node | 22.14.0 |
| Runtime | Rebuilt Docker core: PostgreSQL, API, worker, frontend, TAXII |
| Git | `main...origin/main`; hardening changes are uncommitted |

Only Intel macOS was physically exercised. Windows, Linux, and Apple Silicon were inspected through portable code, Compose, docs, and CI—not physically certified. No external target or live credentialed provider was contacted.

## 3. Verified Repository Metrics

| Metric | Current |
|---|---:|
| Tracked files | 972 |
| Platform Python files / estimated LOC | 53 / 13,033 |
| Platform TS/TSX/JS files / estimated LOC | 34 / 4,529 |
| Inherited filtered Python files / LOC | 247 / 38,948 |
| API route decorators | 53 |
| SQLAlchemy models | 28 |
| Registered / available providers | 43 / 20 |
| Credentialed providers | 12 |
| Core Compose services | 5 |
| GitHub Actions workflows | 5 |
| Tracked Markdown/RST files | 27 |
| Test-like tracked files | 461 |

LOC is a physical nonblank/noncomment estimate; the inherited filter is narrower than the baseline audit and is not a claim of deleted inherited code. The durable queue uses PostgreSQL, not Redis/Celery.

## 4. Test Results

| Suite | Executed | Passed | Failed | Skipped | Time/result |
|---|---:|---:|---:|---:|---|
| CYPHERYN API/security/provider/integrity | 44 | 44 | 0 | 0 | 15.68 s pytest; pass |
| Frontend rendered routes | 2 | 2 | 0 | 0 | Pass with production build |
| Inherited unit + non-live integration | 1,619 | 1,584 | 0 | 35 | 69.09 s; pass |
| **Total** | **1,665** | **1,630** | **0** | **35** | **Pass** |

The rendered landing-page test explicitly verifies Vinext's optimized `/_next/image?url=%2Fcypheryn-logo.png...` contract.

Excluded as before: 213 live inherited module tests, Robot/browser acceptance, destructive reset/restore, live active scanners, external targets, and unavailable physical operating systems. Skips are not passes; no xfail/xpass was reported.

## 5. Coverage Results

CYPHERYN API coverage is **54.58%** (5,709 statements, 2,593 missed), up from 53%.

| Module | Coverage |
|---|---:|
| `integrity.py` | 94% |
| `process_isolation.py` | 81% |
| `threat_intel.py` | 75% (was 61%) |
| `security_controls.py` | 95% |
| `provider_safety.py` | 88% |
| `main.py` | 50% |
| `worker.py` | 46% |
| `notifications.py` | 30% |
| `malware_analysis.py` | 28% |
| `normalization.py` / `report_exports.py` | 21% |
| `detection_engine.py` | 15% |

Inherited tests were rerun without coverage instrumentation; the prior 33% is not reused as a fresh result. Most non-priority provider/scanner modules remain lightly covered.

## 6. Static Analysis

- Ruff: pass, zero findings.
- ESLint: pass, zero warnings.
- TypeScript `tsc --noEmit`: pass; baseline Cloudflare type errors are resolved.
- Production frontend build and rendered assertions: pass.
- Semgrep auto: five findings—permissions/SHA-1 in malware analysis, protocol-required SHA-1 in HIBP, and dynamic `urllib` in `platform/taxii/bootstrap.py:19` and `scripts/doctor.py:56`.
- Warnings remain for Starlette/httpx migration, deprecated FastAPI 422 symbols, and unclosed SQLite resources.

Maintainability hotspots remain `main.py` (859 statements) and `worker.py` (593 statements). Optional provider registration also loses diagnostic detail when duplicate `ValueError` exceptions are swallowed.

## 7. Security Assessment

Verified improvements:

- Active permission is checked at enqueue and revalidated by organization, revocation, start, and expiry immediately before execution.
- Local commands use a reduced environment, new process groups, a 2 MiB output cap, and hard tree termination (`killpg(SIGKILL)` or Windows `taskkill /T /F`).
- Five provider contracts cover missing credentials, request construction, 401/403, 429, malformed data, timeouts, and normalized security signals.
- Credentials remain encrypted and responses centrally redacted before persistence.
- Evidence/audit chains use scoped hashes and PostgreSQL advisory transaction locks; an organization endpoint verifies hashes and link continuity.
- Gitleaks scanned six commits with the reviewed allowlist and reported no unapproved leaks. A wrapper exited nonzero only because `status` is reserved in zsh after the scanner completed; scanner output explicitly said no leaks.

Boundaries:

- Process groups are a termination boundary, not a hostile-code sandbox.
- Hash chains are tamper-evident, not tamper-proof against a privileged party able to rewrite and reseal history.
- Chains are not signed or independently anchored; legacy unsealed rows are reported honestly.
- Compose development identity is not a production authentication profile.
- No comprehensive inbound API abuse/rate-limit layer was verified.
- Fernet key rotation/versioning and external key management remain incomplete.
- Dynamic TAXII/bootstrap URLs still merit HTTP(S) scheme and destination restrictions.

The stated active-authorization principle is credible for application-mediated execution, not direct database/host compromise.

## 8. Dependency and Supply-Chain Assessment

- npm locked-tree audit: **0 vulnerabilities** (baseline: 20, including 15 high).
- API `pip-audit . --strict`: **no known vulnerabilities**.
- Rebuilt environment uses `cryptography 50.0.1` and `pytest 9.1.1`.

Before the final rebuild, Trivy reported five HIGH records. The rebuilt image now upgrades the three Debian OpenSSL packages to fixed version `3.5.7-1~deb13u2` and reports **0 unsuppressed HIGH, 0 CRITICAL** findings.

- Debian CVE-2026-14456 for `libssl3t64`, `openssl`, and `openssl-provider-legacy`, installed `3.5.6-1~deb13u2`, fixed `3.5.7-1~deb13u2`.
- `msgpack 1.1.2`, fixed 1.2.1.
- `setuptools 70.3.0`, fixed 78.1.1.

Trivy warned that third-party SBOM data can be inaccurate. `pip show` and `importlib.metadata` verified `msgpack` and `setuptools` are absent from the runtime. `.trivyignore` therefore contains only those two reviewed false-positive IDs, and CI explicitly uses it. The OpenSSL records are not ignored; they were remediated. Trivy with `exit-code: 1` now passes.

The API image still installs `.[dev]` and copies tests. The frontend production stage copies the full build workspace, defaults to root, and is not minimized. Base images are tags rather than digest pins. Only the API image is scanned/SBOM-generated in CI. License, license audit, and third-party notices are present; inherited/bundled content still needs release-time legal review.

## 9. CI/CD Assessment

All five workflow YAML files parse. Workflows now target `main`; CodeQL covers Python and JavaScript/TypeScript; the platform workflow gates Ruff, 50% API coverage, frontend lint/type/build/render, and a Compose start/doctor smoke test; the security workflow gates pip/npm audits, Gitleaks, API Trivy HIGH/CRITICAL results, and API SBOM creation.

Missing: release/tag workflow, dependency-update automation, complete multi-image scanning/SBOM, and repository-verifiable branch protection. This working tree has locally passed the current render and image gates but has not yet produced a hosted CI result for an exact commit.

## 10. Implemented Architecture

The real system remains Vinext/React → FastAPI → PostgreSQL, with a PostgreSQL-leased worker, local TAXII, optional SpiderFoot/scanners, and optional Ollama-compatible local AI. Redis and IntelOwl are not core services.

## 11. Architecture Diagram

```text
Browser :3000 -> Vinext/React -> FastAPI :8000 -> PostgreSQL 17
                                  |                 ^
                                  | auth/RBAC       | jobs/evidence/chains
                                  v                 |
                               Worker -------------+
                                |  |  |  |
                                |  |  |  +-> SMTP/webhooks
                                |  |  +----> third-party APIs
                                |  +-------> local scanner process groups
                                +----------> TAXII :9000

Optional/separate: SpiderFoot :5001, Greenbone/OpenVAS, ZAP, Ollama
```

Loopback mappings and internal database networking remain appropriate for local development. Process grouping improves lifecycle control without creating another trust domain.

## 12. Provider Integration Matrix

The rebuilt standard worker registers 43 adapters: 20 available, 23 unavailable, 12 credentialed.

| Group | Classification |
|---|---|
| VirusTotal, Shodan, OTX, Censys, ThreatFox | Implemented, optional, contract-tested; no live call during audit |
| GreyNoise, AbuseIPDB, URLhaus, HIBP | Implemented/optional; outside the new five-provider contract matrix |
| TAXII/STIX | Implemented; local health verified; remote interoperability not certified |
| RDAP, CT, DNS/domain/web posture, identity, direct verifier | Implemented with varying coverage |
| Subfinder, Naabu, Nmap, RustScan, Masscan, Nuclei, DNSTwist, Katana variants, Nikto, ZAP variants, testssl, Maigret, OpenVAS, Gitleaks, TruffleHog, Semgrep, OSV, Checkov, Syft, Grype, Trivy | Adapter exists; binary/service unavailable in standard worker |
| Gowitness, DNSX, ZMap | No native adapter; roadmap/documentation only |
| SpiderFoot modules | Inherited/upstream unless explicitly wrapped |

The readiness ladder now distinguishes registry support, installation, configuration, readiness, and timestamped success. Live Verified is not an uptime guarantee.

## 13. Data and Evidence Integrity

Implemented chain:

```text
authorization -> job -> evidence -> observation -> entity/relationship
              -> finding -> analyst decision -> remediation -> rescan
              -> comparison/verification -> report
```

Evidence includes organization/investigation/job/target/authorization/provider, retrieval time, redaction policy, payload/hash, and linked integrity hashes. Audit events use equivalent links. Rescans preserve previous/current sources; deterministic analysis is distinct from AI narrative; exports include integrity fields.

This is now tamper-evident under normal operation and exposes broken/unsealed counts. It is not forensic-grade independent proof: privileged administrators can rewrite/reseal chains; no signature, external timestamp, transparency log, WORM store, or separate trust-domain anchor exists. Database permissions/triggers do not enforce append-only history.

## 14. Performance Baseline

Thirty sequential local requests against the rebuilt stack:

| Endpoint | Min | Mean | p50 | p95 | Max |
|---|---:|---:|---:|---:|---:|
| API live | 3.40 ms | 4.99 | 4.55 | 6.39 | 17.57 |
| API ready | 5.40 ms | 6.82 | 6.73 | 8.37 | 9.18 |
| Frontend | 10.39 ms | 18.60 | 15.19 | 36.10 | 81.48 |
| TAXII | 2.66 ms | 4.04 | 3.92 | 5.58 | 6.08 |

Doctor passed all required services after normal frontend startup. Its first immediate invocation caught the frontend still starting rather than masking the race. No destructive load test was performed.

## 15. Developer Experience

Docker-first setup, portable Python utilities, `.env.example`, health checks, and OS-specific docs are strong. Optional provider keys are not required to start. Friction remains from the modern/inherited codebase split, 23 unavailable adapters, differing Python generations, and development content in production images. Windows/Linux/Apple Silicon remain inspected rather than physically audited.

## 16. Documentation Assessment

**8.4/10.** The README and `docs/VERIFICATION_RELEASE.md` accurately explain the readiness ladder, local-first model, and security boundaries. Documentation remains fragmented across historical architecture/planning files, and claims that scanning is “enforced” should distinguish configured gates from a proven green run on this exact tree.

## 17. Open-Source Readiness

Present: README, license/notices, issue template, screenshots/site, architecture/security/tutorial/roadmap docs, CI, and cross-platform utilities.

Missing: `CONTRIBUTING.md`, public `SECURITY.md`, `CODE_OF_CONDUCT.md`, PR template, `CHANGELOG.md`, Dependabot/Renovate, release/tag automation, and signed/versioned artifacts. Branch protection, social preview, and profile pinning were not admin-verified.

## 18. Hiring-Manager Assessment

The release demonstrates unusually credible audit response: dependency remediation, deterministic failure contracts, cross-platform process lifecycle control, PostgreSQL concurrency reasoning, evidence integrity, security UX, and supply-chain CI. A senior reviewer would still ask whether hosted CI is green, how supported providers are selected, when scanners move to isolated workers, how chain heads will be independently anchored, and how `main.py`/`worker.py` will be decomposed.

## 19. Engineering Scorecard

| Dimension | Score |
|---|---:|
| Architecture | 7.8 |
| Code quality | 7.0 |
| Testing | 7.0 |
| Security engineering | 8.0 |
| Documentation | 8.4 |
| DevOps/CI | 7.6 |
| Developer experience | 7.5 |
| Cross-platform readiness | 7.5 |
| Open-source readiness | 6.8 |
| Maintainability | 6.3 |
| Observability | 5.8 |
| Evidence/provenance | 8.5 |
| Portfolio value | 9.0 |

**OVERALL ENGINEERING SCORE: 7.6/10**

## 20. Top 10 Prioritized Improvements

1. **P0:** Commit the hardened tree, require checks on protected `main`, and retain hosted CI artifacts (0.5–1 day).
2. **P1:** Keep the reviewed Trivy false-positive exceptions narrow and periodically revalidate them against runtime package metadata (hours per dependency refresh).
3. **P1:** Run risky scanners in disposable containers/nodes with resource and egress limits (2–4 weeks).
4. **P1:** Sign and independently anchor evidence-chain checkpoints with rotation/verification docs (2–4 weeks).
5. **P1:** Extend failure/provenance contracts to every claimed-supported provider (2–4 weeks).
6. **P1:** Raise coverage for detection, worker, normalization, exports, notifications, and malware paths (2–3 weeks).
7. **P1:** Remove dev/test content, use non-root/minimal images, and scan/SBOM every shipped image (3–7 days).
8. **P2:** Define provider tiers, SLOs, freshness expiry, and failure reasons as enforceable product policy (1–2 weeks).
9. **P2:** Add worker heartbeat, queue age/depth, provider metrics, correlation IDs, and alerts (1–2 weeks).
10. **P2:** Add OSS governance, dependency automation, changelog, signed releases, and complete SBOMs (3–7 days).

## 21. Failed and Blocked Tests

Failed: none in the safe local suites. API, inherited, rendered frontend, production build, Ruff, ESLint, and TypeScript checks pass.

Blocked/excluded: 213 live inherited provider tests, Robot/browser acceptance, credentials/live providers, destructive reset/restore, hostile scanner execution, and physical non-macOS systems. Trivy is no longer blocked and produced the findings above.

## 22. Commands Executed

```bash
git rev-parse HEAD; git status --short --branch; git ls-files | wc -l
cd platform/api
pytest --cov=intel_platform --cov-report=term
ruff check src tests
python -m pip_audit . --strict
cd ../frontend
npm test; npm run lint; npm run typecheck
npm audit --package-lock-only --audit-level=low
# isolated Python 3.10
pytest -n auto --dist loadfile test/unit test/integration --ignore=test/integration/modules
gitleaks git --redact --config .gitleaks.toml
semgrep scan --config auto <tracked CYPHERYN paths>
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed cypheryn-api:latest
docker compose config --services; docker compose ps; docker stats --no-stream
python3 scripts/doctor.py
```

## 23. Evidence and References

- Hard termination: `platform/api/src/intel_platform/process_isolation.py:60-70`
- Evidence sealing: `platform/api/src/intel_platform/worker.py:1174`
- Integrity/locking: `platform/api/src/intel_platform/integrity.py:35-105`
- Integrity API: `platform/api/src/intel_platform/main.py:2390-2415`
- Provider ladder: `platform/api/src/intel_platform/main.py:2181-2238`; `platform/frontend/app/settings/page.tsx:239-249`
- Contract tests: `platform/api/tests/test_provider_contracts.py`
- Isolation/integrity tests: `platform/api/tests/test_integrity_and_isolation.py`
- CI: `.github/workflows/security-supply-chain.yml`; `.github/workflows/cypheryn-cross-platform.yml`
- Optimized-image assertion: `platform/frontend/tests/rendered-html.test.mjs:25`
- Images: `platform/api/Dockerfile`; `platform/frontend/Dockerfile`

Results are dated snapshots. Availability is environment-specific. No live-provider success or untested platform support is claimed.

## Independent Review Package

**State:** base commit `5d5815946da3ec73f58f0f57f9389b18747e8bd7` plus uncommitted hardening tree.  
**Tests:** 1,665 executed; 1,630 passed; 0 failed; 35 skipped.  
**Coverage:** API 54.58%; integrity 94%, isolation 81%, threat intelligence 75%, worker 46%, detection 15%.  
**Static:** Ruff/ESLint/TypeScript/build/render pass; Semgrep five contextual findings.  
**Dependencies:** npm/API Python audits clean; patched OpenSSL image has zero unsuppressed HIGH/CRITICAL Trivy findings; two reviewed pip-vendoring false positives are documented.  
**Safety:** authorization revalidated before execution; process trees terminate hard; no hostile-code sandbox.  
**Evidence:** scoped SHA-256 chains and verification endpoint; no independent signing/anchoring.  
**Providers:** 43 registered, 20 available, 23 unavailable, 12 credentialed; five priority threat providers contract-tested.  
**CI:** comprehensive main/PR gates exist and their local equivalents pass; hosted execution against the exact commit remains the final proof.  
**Score:** **7.6/10**, improved from 6.6/10 and locally release-gate clean.

An independent reviewer should first reproduce `npm test` and the Trivy API-image scan, then verify hosted CI on a committed branch, inspect authorization revalidation in `worker.py`, hard termination in `process_isolation.py`, and chain canonicalization/locking in `integrity.py`.
