# CYPHERYN Production and Federation Audit V2

Audit date: 2026-09-01 UTC  
Application version: 0.9.0  
Audited and deployed source commit: `088b5420e5e70634e4d3f1b9ef7dca6c45a6dd2a`  
Repository: `https://github.com/JedidiahBowlding/CYPHERYN`

## Executive conclusion

The blocking conditions from the prior production and federation audit are closed. Production runs a clean checkout of the audited commit and images built from that exact checkout. Federation assertions use a closed privacy schema, request size is bounded before JSON parsing and again after canonicalization, PostgreSQL race behavior is tested, and the independent two-node test proves local operation during peer loss. All 33 historical CodeQL alerts received an individual disposition; the GitHub open-alert count is zero.

This PASS applies to the stated deployment and evidence below. It does not turn the experimental federation protocol into a compatibility guarantee, make the scanner orchestrator a hostile-code sandbox, or claim that the production deployment is a two-node federation. Federation remains disabled and unexposed in production.

## Production reproducibility

| Control | Verified result |
| --- | --- |
| Repository commit | `088b5420e5e70634e4d3f1b9ef7dca6c45a6dd2a` |
| Deployed commit | `088b5420e5e70634e4d3f1b9ef7dca6c45a6dd2a` |
| Git worktree | Clean (`git status --porcelain` returned zero entries) |
| Manifest | `/var/lib/cypheryn/deployments/20260901T013351Z-manifest.json` |
| Manifest SHA-256 | `98ccfe4a456b0b61750decd303c5fead219649949f2d79e6841608a971f50de7` |
| Manifest ownership/mode | `root:root`, `0600` |
| Database schema state | `sqlalchemy-metadata-at-088b542` (CYPHERYN does not claim an Alembic revision) |
| Operator | `newblockdev` |
| Runtime readiness | API, frontend, TAXII, PostgreSQL, and scanner orchestrator healthy; worker running; anchor initializer completed successfully |

The manifest records the Git commit, clean-tree flag, application version, UTC deployment time, operator, database state, running services, image identities and repository digests, Compose hashes, and Caddy configuration hash. It lives outside the checkout so recording a deployment cannot dirty production source.

### Exact application image identities

| Image | SHA-256 image identity |
| --- | --- |
| `cypheryn-api` | `sha256:961eafef8f1eb00e6913c1d3c5e5baf352e53c03a0cb0e749b3169d765ff6a0a` |
| `cypheryn-worker` | `sha256:5322e50b63af8d28cf6d7a58149a82ab12a3c5b9117e16a427001980da2ef54f` |
| `cypheryn-frontend` | `sha256:4111bc02e85b319740ca9816ed0a555ebd25dcfbc468ef3ff23cb85ba0155112` |
| `cypheryn-taxii` | `sha256:6715d9956e7cf9282279d6f258d7646e1bea2c24a1021d689b7bee1b6c8e4acb` |
| `cypheryn-scanner-orchestrator` | `sha256:31827de62d2b027270ca43f40b9ce6c34ba4a1881dd7445fefa3a53de034ac14` |

Legitimate production drift was separated into focused PRs for web/domain behavior (#25), dependency security (#27), federation/security (#26), frontend/dashboard (#28), scanner/providers (#29), CodeQL triage (#30), reproducible production operations (#31), initializer/gateway correction (#32), and final federation proof (#33). Historical dirty artifacts were preserved in restricted backups rather than deleted or reset.

## CodeQL disposition

All 33 observed alerts were inspected for reachability, attacker control, data sensitivity, and actual security impact. Twenty-three were fixed and ten were dismissed individually with technical rationale; no bulk dismissal was used. GitHub reports zero open code-scanning alerts. The release policy separately gates workflow success and unresolved High/Critical alerts.

| Alerts | Rule family | Count | Disposition |
| --- | --- | ---: | --- |
| 1–2 | Incomplete JavaScript sanitization | 2 | Fixed: graph labels now escape every occurrence before DOM insertion. |
| 3–6 | Clear-text sensitive storage | 4 | Individually dismissed: the cached value is public provider response content, not credentials, request URLs, or headers. |
| 7–9 | Clear-text sensitive logging | 3 | Concrete leaks fixed; remaining conservative request/response taint paths individually dismissed after URL redaction and `noLog` controls were tested. |
| 10 | Overly permissive regex range | 1 | Fixed with an explicit hexadecimal class. |
| 11–22 | Incomplete URL substring sanitization | 12 | Fixed with parsed hostname boundary checks and canonical, enumerated filesystem paths. |
| 23 | Incomplete URL substring sanitization | 1 | Individually dismissed: `ASP.NET` classifies a response cookie and is not an authorization or URL-sanitization boundary. |
| 24 | Incomplete URL substring sanitization | 1 | Fixed with parsed-hostname validation. |
| 25–26 | Path injection | 2 | Fixed with canonical isolated-root confinement, enumeration, and traversal/symlink regression tests. |
| 27–28 | Weak sensitive-data hashing | 2 | Individually dismissed: SHA-224 names public-data cache entries and is not used for secrecy, credentials, authentication, or signatures. |
| 29 | Insecure default protocol | 1 | Fixed: minimum TLS 1.2. |
| 30–33 | Insecure protocol | 4 | Fixed: four clients require TLS 1.2 or later with certificate and hostname verification. |

The detailed alert-by-alert rationale is maintained in `docs/CODEQL_ALERT_TRIAGE.md`; release rules are in `docs/CODEQL_RELEASE_POLICY.md`.

## Federation privacy and protocol boundary

`FederatedSecurityAssertion` v1 no longer transports an arbitrary `evidence_checkpoint`. `source_category` is a closed enumeration rather than free text. The transport schema contains only explicitly typed, minimal classifications and fingerprints; arbitrary nested JSON is not accepted.

Negative tests reject prohibited credentials, API tokens, private keys, PII, customer records, raw topology, unrestricted evidence, analyst notes, authorization documents, raw malware, source code, and full vulnerability reports. Protocol/version, identity, signature, expiry, replay, malformed-data, and revocation cases are also covered.

Federation request bodies are bounded at the Caddy boundary before JSON decoding. The API independently enforces canonical serialized size as defense in depth. Federation is disabled by default and is not routed publicly in the production deployment.

## Full two-node independence result

The Compose federation integration uses two CYPHERYN API nodes with separate PostgreSQL databases, Ed25519 signing keys, identities, worker queues, evidence/report state, and configuration. The exact-commit hosted `Federation Two Node` workflow passed.

The test demonstrated:

1. reciprocal enrollment and distinct identities;
2. successful signed assertion exchange;
3. replay and tamper rejection;
4. explicit peer revocation followed by a newly signed delivery rejected as untrusted;
5. permitted local collection, local evidence persistence, and local PDF report generation;
6. Node A termination and positive confirmation that it was unreachable;
7. continued Node B readiness, worker-backed local collection, evidence persistence, and report generation;
8. federation health remaining enabled/ready while reporting peer loss; and
9. no central CYPHERYN control-plane dependency.

This is an isolated integration proof. Production currently runs one CYPHERYN application node, and this audit does not misrepresent the test environment as a production federation.

## PostgreSQL concurrency result

The hosted `Federation PostgreSQL` workflow passed against PostgreSQL rather than SQLite. The multi-process race launches four simultaneous deliveries of one signed assertion: exactly one is accepted and three are rejected as replays, leaving one assertion and one issuer/nonce record. Tests also cover assertion-ID races, issuer/nonce uniqueness, rollback after revoked-peer rejection, and concurrent peer-state transitions.

## Failure and chaos result

Controlled tests cover packet loss, response delay, dropped connections, temporary DNS failure, network partition, asymmetric connectivity, node restart, database restart, duplicate retry, delivery timeout, and extended peer outage. Federation failures do not interrupt local collection, evidence, report, worker, or readiness paths. Timeout and unreachable-peer counters increase, and a delivery latency observation is recorded.

Federation metrics include bounded-label rejection reasons, signature failures, replay, expiry, revoked-peer, malformed assertion, timeout, unreachable-peer, and delivery latency. Raw subjects, evidence, credentials, and high-cardinality peer-controlled values are not metric labels.

## Key continuity

Normal rotation is intentionally treated as a new peer identity today. `docs/FEDERATION_KEY_CONTINUITY.md` specifies a future versioned transition record with old node/key IDs, new public key and node/key IDs, timestamp, protocol version, old-key signature, and new-key proof of possession. A compromised or lost old key cannot authorize continuity; peers must revoke and independently enroll the replacement. Unsafe automatic trust migration was not implemented.

## Web and domain verification

| Request | Result |
| --- | --- |
| `https://cypheryn.com/` | `200` public landing page |
| `https://cypheryn.com/og.png` | `200` |
| `robots.txt` and `sitemap.xml` | `200`, apex-domain content |
| Unknown apex route | `404` |
| `https://www.cypheryn.com/` | `301` to `https://cypheryn.com/` |
| Protected application route | `302` to the Auth0 entry path |
| Empty OAuth callback | bounded `400` |

The canonical URL, Open Graph asset, robots and sitemap URLs use the apex domain. Auth0 protection remains in front of application routes. Production headers retain CSP with nonce and `frame-ancestors 'none'`, `X-Frame-Options: DENY`, Permissions Policy, same-origin CORP, and HSTS.

## Dependency and supply-chain status

- npm production audit: zero vulnerabilities.
- Python dependency audit: clean.
- Gitleaks: clean across repository history.
- CodeQL workflow and zero-open-alert check: green.
- Trivy gates: zero fixable High/Critical findings in the five shipped application images.
- CycloneDX SBOMs: generated for all five application images.
- Cross-platform Python/API and frontend validation: green on Ubuntu, macOS, and Windows.
- Two GitHub Dependabot Moderate alerts still reference stale `pytest 7.2.1` graph metadata. Current locked/manifests use `pytest 9.0.3`, and the dependency audit is clean. They are documented as stale graph state, not dismissed as nonexistent vulnerabilities.

## Secret backup hygiene

The active `/etc/cypheryn/production.env` was not printed or modified. Three historical plaintext copies were encrypted with AES-256, copied to restricted production, second-node, and local backup locations, and the plaintext copies were securely removed. Archives and the local recovery material are mode `0600`; the recovery passphrase is kept off the production host. No credential values appear in this report.

## Remaining risks and operating obligations

- The scanner orchestrator uses strong disposable-container restrictions and keeps the Docker socket away from the normal worker, but the trusted orchestrator itself remains privileged infrastructure and is not a hostile-code sandbox.
- Federation v1 is experimental. Operators must pin identities, protect private keys, keep it private by default, and perform explicit enrollment/revocation.
- Key continuity is a formal design, not an implemented trust migration. Rotation remains a new identity.
- The production deployment is a single application node; the two-node result is a repeatable CI/integration proof.
- Database schema initialization currently uses SQLAlchemy metadata rather than versioned Alembic migrations.
- The local encrypted-backup recovery key requires independent workstation backup and rotation discipline; it is not protected by a cloud KMS or hardware-backed key service.
- Ed25519 external integrity checkpoints provide tamper evidence, not absolute prevention against an administrator who controls application behavior and all anchor destinations.
- `Live Verified` provider status is evidence of a successful collection at a recorded time, not a promise of continued upstream availability.

## Final verification checklist

| Requirement | Result |
| --- | --- |
| Clean production tree and exact manifest | PASS |
| Exact source-built image identities recorded | PASS |
| Hosted required CI on audited commit | PASS |
| Zero untriaged High/Critical CodeQL alerts | PASS |
| npm/Python/Gitleaks/Trivy gates | PASS |
| Federation closed-schema privacy tests | PASS |
| PostgreSQL multi-process concurrency | PASS |
| Full two-node independence | PASS |
| Network failure/partition behavior | PASS |
| Landing/domain/Auth0 behavior | PASS |

PRODUCTION AND FEDERATION AUDIT PASSED
