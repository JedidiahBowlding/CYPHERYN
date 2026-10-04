# Agent Security Control-Plane Foundation Certification

Date: 2026-10-04

Branch: `feature/agent-security-foundation`

Scope: Generic CYPHERYN identity → capability → destination → classification → policy → decision foundation

## Overall result

**PASS — recommend MERGE after review.**

This certification does not authorize deployment, Nova Steward integration, MCP gateway work,
agent-to-agent trust, anomaly blocking, or short-lived delegated authority.

## Release gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Migration certification | PASS | PostgreSQL 17 recreation of the 40-table `origin/main` schema; upgrade, downgrade, and re-upgrade passed |
| Identity enforcement | PASS | Unknown, invalid, expired, revoked, human-token, unknown-agent, inactive-agent, and cross-client cases reject or deny |
| Capability enforcement | PASS | Missing, revoked, disabled, expired, wrong-environment, wrong-scope, and privilege-escalation cases deny |
| Destination security | PASS | HTTPS origin canonicalization, IDNA, case, trailing-dot, IPv4/IPv6, credentials, ports, fragments, private/loopback/link-local, and DNS answers tested |
| Classification enforcement | PASS | All eight public classifications tested; sensitive/unknown and prohibited destinations deny |
| Secret protection | PASS | Synthetic API key, Bearer/header, password, private key, database URI, and session-token forms detected without value disclosure |
| Policy precedence | PASS | Conflicting active policies fail closed; deny precedes approval and allow in deterministic single-policy evaluation |
| BLOCK/DENY compatibility | PASS | Public `DENY` maps to historical internal `BLOCK` without rewriting stored records |
| SHADOW/ENFORCE | PASS | Evaluated, effective, and enforced decisions remain distinct and durable |
| Fail closed | PASS | Missing, ambiguous, inactive, and integrity-invalid policy states do not become `ALLOW` |
| Tenant isolation | PASS | Workload evaluation, reads, and administrative mutations are organization-scoped |
| Replay protection | PASS | Nonce, idempotency key, changed-input reuse, stale time, and future time tested |
| Concurrency | PASS | PostgreSQL 17 identical and independent request races passed without duplicate receipts or chain forks |
| GitHub egress regression | PASS | Full historical egress firewall suite passed |
| Federation regression | PASS | Signature, lifetime, size, replay, revocation, API, chaos, and PostgreSQL concurrency tests passed |
| Receipt secret safety | PASS | Context values are represented only by hashes; receipts and ordinary persisted metadata omit raw values |
| Full suite | PASS | Backend, coverage gates, Ruff, TypeScript, ESLint, production build, and rendered tests passed |

## Defects found and corrected

1. IPv6 origins lacked RFC-compatible URL brackets; canonical identifiers now retain brackets.
2. Invalid textual ports escaped as parser errors; they now fail as `UnsafeDestination`.
3. DNS labels now receive explicit canonical validation.
4. Bearer/header, database-URI, and session-token secret forms were absent from artifact detection.
5. Generic receipt hashes did not cover the human reason, risk score, or request timestamp.
6. Concurrent idempotent duplicates could fail during `flush()` before recovery logic.
7. Integrity chains could fork because the previous record was selected by creation time rather than the actual unreferenced chain head.

## Performance baseline

The deterministic evaluator does not call an LLM.

Local TestClient/SQLite baseline, 50 sequential decisions:

- Mean: 58.773 ms
- p50: 53.109 ms
- p95: 83.068 ms
- Maximum: 158.590 ms
- SQL statements per decision: 15.0 (constant in this sample)

With 32 requests and eight local threads, wall time was 1,699.833 ms and request p95 was
1,046.461 ms. SQLite write serialization dominates that concurrency figure; PostgreSQL 17 was
used separately to certify correctness, idempotency, tenant separation, and integrity-chain safety.
This baseline is diagnostic, not a production SLO.

## Known limitations and documented race boundaries

- Phase 1 intentionally supports exactly one active deterministic policy per organization. Multiple
  active policies fail closed with HTTP 503 instead of attempting implicit composition.
- A revocation is authoritative for subsequent evaluations. An already-running transaction that
  completed all lookups before a concurrent administrative revocation has a narrow in-flight race
  window; eliminating it requires a stronger serializable revocation/evaluation protocol.
- DNS is resolved and public addresses are bound into the receipt. Redirects require re-evaluation,
  but the caller/enforcement layer must honor that binding to eliminate DNS time-of-check/time-of-use
  risk during the actual network connection.
- Regex-based secret detection is defense in depth and cannot identify every proprietary credential
  shape. Raw request context is not persisted; its digest is persisted.
- The performance result is a local SQLite baseline, not a production PostgreSQL load test.
- The suite emits a Starlette TestClient deprecation warning and several existing SQLite resource
  warnings; neither changed decision results, but both should be cleaned up separately.

## Next phase recommendation

After review and merge, the next narrowly scoped phase should close the documented revocation race
and bind destination-resolution receipts to the actual network enforcement point. Do not connect
Nova Steward or begin MCP/agent-to-agent expansion until those boundaries have explicit designs and
tests.
