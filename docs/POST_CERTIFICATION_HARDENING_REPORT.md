# Post-Certification Authorization and DNS Hardening Report

Date: 2026-10-04

Branch: `feature/agent-security-foundation`

## Result

**PASS — prepare for review; do not deploy automatically.**

The certified control plane now supports the stronger question: is this exact workload and agent
still authorized to perform this exact operation against this exact destination now?

## Architecture

Authoritative `ALLOW` decisions create short-lived `decision_authorizations` records. Each record
binds the decision to client, agent, capability grant, destination, policy, operation fingerprint,
canonical HTTPS origin, resolved public-address set, resolution lifetime, authorization lifetime,
and use limit. SHADOW advisory allows and non-ALLOW decisions receive no execution authority.

Final validation is provided by:

```text
POST /api/v1/security/decisions/{decision_id}/validate
```

Validation locks the authorization row and rechecks current client, agent, grant, destination,
policy integrity, five generation snapshots, operation binding, expiration, current DNS results,
connected address, and usage limit. High-consequence authority is single-use.

## Revocation behavior

Monotonic generations cover the client, agent, capability grant, destination, and policy.
Administrative state changes increment the relevant generation. Tests verify revocation after
`ALLOW` and before final validation for all five scopes. Expired leases and expired DNS receipts
deny. PostgreSQL concurrency permits only one successful consumer of a single-use authorization.

The database can guarantee freshness at final validation. It cannot atomically revoke an operation
that an external system has already accepted, nor can it make a direct client socket atomic with
the validation transaction. That final interval requires a compliant pinned client or, preferably,
a future CYPHERYN-controlled egress proxy.

## DNS and redirect behavior

The receipt binds scheme, hostname, port, exact resolved-address set, resolution time, and expiry.
Final validation re-resolves and denies any address-set change. Every answer must be globally
routable; mixed public/private, loopback, link-local, RFC1918, metadata, IPv6 loopback, and IPv6
unique-local answers fail the entire resolution.

Same-origin path redirects retain the binding. Any scheme, host, or port change requires a new
evaluation. Public-to-private redirects fail canonicalization and cannot validate.

## Performance and query review

Local TestClient/SQLite diagnostic baseline:

- Evaluation: 16 SQL statements per decision (previous baseline: 15)
- Evaluation p50: 61.146 ms
- Evaluation p95: 131.621 ms
- Final validation: 10 SQL statements
- Final-validation p50: 40.865 ms
- Final-validation p95: 63.186 ms
- 32 evaluations / 8 threads: 1,981.424 ms wall time; p95 1,247.641 ms

One additional evaluator statement persists the authorization lease. The decision path has no N+1
loop. Safe future opportunities are combining idempotency and nonce reads, rate-limiting freshness
writes, and avoiding insert-then-seal updates. Authority-state reads must remain fresh.

These values are not production SLOs; SQLite write serialization dominates concurrency results.

## Verification

- Backend: 330 tests collected; 328 passed in the ordinary run.
- Skipped in ordinary run: two PostgreSQL-gated tests.
- PostgreSQL 17: both gated tests passed separately, including concurrent single-use consumption.
- Migration: exact 40-table `origin/main` schema upgraded through both security revisions,
  downgraded from the lease revision, and re-upgraded successfully.
- Ruff: PASS.
- TypeScript: PASS.
- ESLint: PASS.
- Frontend production build: PASS.
- Rendered frontend tests: 4/4 PASS.
- Coverage: 71.08% overall; every critical security coverage gate passed.
- GitHub Egress and federation regression suites: PASS.

## Known limitations and remaining risks

1. Direct clients must obey the pin-and-validate contract. The API cannot prove that a malicious or
   defective client actually used the submitted connected address.
2. A revocation after final validation can race a direct external connection. A controlled egress
   proxy is required to own both the check and the socket.
3. Conservative exact-set DNS comparison can deny legitimate DNS rotation during the short receipt
   window. This is an availability tradeoff in favor of security.
4. Authorization and DNS lifetimes are process configuration. Production values must remain short
   and coordinated with client connection reuse.
5. Existing Starlette TestClient deprecation and SQLite resource warnings remain cleanup items.

## Merge preparation

Recommend **squashing the three phase commits into one reviewed feature commit** when merging. The
foundation, certification-driven fixes, and lease/DNS hardening form one security boundary; an
atomic merge simplifies review, rollback, and release notes. Keep the existing commits intact on
the review branch until reviewers finish examining the development history.

## Next phase

After merge review, design a separately trusted CYPHERYN egress enforcement proxy that performs
final validation and owns the pinned network socket. Do not begin MCP, agent-to-agent, autonomous
blocking, or Nova integration under this phase.
