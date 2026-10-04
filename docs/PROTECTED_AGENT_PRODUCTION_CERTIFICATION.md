# Protected Agent Production Certification

Date: 2026-10-04  
Scope: local implementation and certification evidence; no push, merge, or deployment  
Status: **LOCAL PASS; HOSTED CI EVIDENCE PENDING**

## 1. Branch and commit

Work was performed on `feature/agent-security-foundation`, based on commit `c0538a8` (`feat: add trusted agent egress proxy`). This report describes the uncommitted working tree on top of that commit. No remote mutation occurred.

## 2. Protected agent selected

The pilot is the generic `protected-read-agent` in `intel_platform.pilot_agent`. It is deliberately not Nova Steward. It uses an OIDC client-credentials workload token, supports only `web.read`, and performs one evaluated GET/HEAD through the trusted proxy.

## 3. Agent network architecture

The pilot is UID 10002, read-only, capability-dropped, and attached only to the internal `protected-agents` network. It reaches evaluation only through `agent-control-plane:8015`, which permits POST `/api/v1/security/evaluate`; the API is not on the protected network. It reaches external resources only through `egress-proxy:8020`. The proxy reaches security endpoints only through an internal `proxy-control` network and the mTLS gateway; it is not attached to the API backend network. Only the trusted proxy is attached to `proxy-egress`.

## 4. Direct-internet bypass results

Inside the actual hardened pilot container on an internal Docker network, all tested bypasses failed: raw public IPv4, raw public IPv6, hostname resolution, direct HTTP, direct HTTPS, private RFC1918 address, metadata address, alternate port, and direct query to 8.8.8.8. The three proxy health endpoints remained reachable. Docker Desktop did not provide usable IPv6 on the test network; the IPv6 attempt failed closed with an OS network error.

## 5. Approved proxy flow

The pilot contract test proves evaluation precedes proxy submission and carries the same workload bearer. Proxy integration tests prove receipt start, final consume, pinned socket ownership, TLS, response, and receipt completion. PostgreSQL certification proves the authority is consumed globally once. Durable receipts expose replica, decision, authority context, DNS binding, pinned address, outcome, upstream status, and correlation ID.

## 6. Denied proxy flow

A policy DENY returns without calling the proxy. Final validation DENY tests prove the transport receives zero calls. The protected container cannot use direct egress as a fallback.

## 7. Expired-authority result

`AUTHORIZATION_EXPIRED` maps to `AUTHORITY_EXPIRED`, writes the denial outcome, and opens no socket.

## 8. Revocation results

Agent/client changes, capability revocation, destination binding changes, policy changes, explicit revocation, and consumed authority are rechecked by final validation. Distinct outcomes are retained and the transport is not invoked.

## 9. Proxy service identity

The proxy uses a dedicated client certificate issued by a proxy-only CA plus its normal workload bearer. It does not use a human credential. The gateway allows only final validation, receipt start, and receipt completion paths/methods.

## 10. mTLS implementation

Caddy requires and verifies the proxy client chain. The proxy uses an `ssl.SSLContext` with a pinned control-plane CA and client certificate/key. Hostname, SAN, expiry, EKU, and chain verification remain enabled. Production configuration rejects HTTP and incomplete mTLS settings. `trust_env=False` prevents environment proxy injection. There is no plaintext or `verify=false` fallback.

## 11. Certificate rotation result

Automated tests validated the current client, an old/new overlap CA bundle, the new client, cutover to new-only trust, and rejection of the old client. `scripts/egress_pki.py` provides `init`, `prepare-rotation`, and `complete-rotation`; production should use managed PKI with equivalent identities.

## 12. Three-replica result

Three independent proxy containers reported distinct identities (`proxy-a`, `proxy-b`, `proxy-c`). A PostgreSQL-backed three-caller race against one authority produced exactly one protected execution and two `AUTHORITY_CONSUMED` results. No sticky session or replica-local authorization state is used.

## 13. Replica-chaos result

Stopping A left B and C healthy. A was restarted; stopping B left A and C healthy; B was restarted. The database-backed concurrency test establishes that retries cannot duplicate a single-use operation. One immediate post-start probe failed until Uvicorn became ready, which confirms callers must honor health/readiness rather than treating container start as readiness.

## 14. Control-plane interruption result

Unavailable receipt creation or final validation fails closed before transport use. The proxy has no cached-ALLOW path.

## 15. PostgreSQL interruption result

PostgreSQL is authoritative for atomic consumption. The real PostgreSQL 17 concurrency test passed. Database/control-plane exceptions cannot produce a confirmed validation and therefore cannot reach the proxy-owned socket. Receipt start is also before socket creation, so receipt-storage uncertainty fails closed.

## 16. DNS interruption result

Resolver errors, empty answers, unsafe mixed answers, resolution expiry, and address-set changes fail closed. Complete address sets are verified and a selected approved address is pinned before connect.

## 17. Network bypass matrix

| Attempt | Result |
| --- | --- |
| Raw public IPv4 | Blocked |
| Raw public IPv6 | Blocked; host environment had no usable IPv6 route |
| Public hostname/DNS | Blocked |
| Alternate DNS resolver | Blocked |
| Direct TLS/HTTPS | Blocked |
| Direct HTTP | Blocked |
| Private network | Blocked |
| Metadata-style address | Blocked |
| Alternate public port | Blocked |
| Proxy environment manipulation | Ineffective; HTTP client ignores environment proxies |
| Alternate/manual socket | Blocked by the network boundary |
| Cross-origin redirect | Requires new authorization |

## 18. Proxy misuse matrix

| Misuse | Enforcement |
| --- | --- |
| Wrong/unknown decision | Final validation DENY |
| Wrong agent/client/tenant | OIDC and stored authority binding DENY |
| Wrong destination/address set | Destination or DNS binding DENY |
| Wrong scheme/port | Canonicalizer DENY |
| Expired/revoked/consumed authority | Distinct final-validation DENY |
| Modified body | SHA-256 resource-scope binding DENY |
| Protected/secret headers | Blocked or quarantined |
| Capability/method mismatch | Pre-socket DENY |
| Direct API/security endpoint | Network isolation plus route-limited gateways |

## 19. TLS matrix

| Case | Result |
| --- | --- |
| Valid CA, hostname, SNI, client identity | Accepted |
| Missing/untrusted client | Rejected by gateway |
| Old client after rotation | Rejected |
| Wrong hostname/SNI | Rejected by standard TLS validation |
| Self-signed/untrusted upstream | Rejected |
| Expired certificate | Rejected |
| Insecure fallback | Not implemented |

## 20. Load-test diagnostics

A bounded three-replica health diagnostic completed 300 requests with 0 errors in 0.878 seconds: 341.8 requests/second, p50 40.48 ms, p95 90.73 ms, max 204.38 ms. Idle post-test replicas used approximately 69.9–72.0 MiB each and 0.23–0.27% CPU on Docker Desktop. These are local diagnostics, not SLOs. Proxy metrics now separately accumulate DNS, receipt-start, final-validation, TLS/socket, receipt-finish, total latency, outcome, and byte measurements so a staging full-path test can report phase latency and database utilization.

## 21. Connection-reuse decision

Control-plane and external upstream pooling remain disabled. Fresh mTLS connections make certificate revocation/rotation immediate and keep a single-use authorization bound to a bounded socket sequence. Performance optimization is deferred until it can preserve those properties.

## 22. Observability result

Operators can correlate workload identity, decision, execution authority, replica ID, canonical destination, pinned IP, body hash/classification, socket outcome, response status, receipt, latency, and correlation ID without recording bearer tokens, keys, or bodies.

## 23. Alert recommendations

Alert on replica quorum loss, control-plane/mTLS failure, elevated DENY or authority-validation rates, DNS safety changes, TLS failures, receipt persistence failures, protected-network bypass attempts, p95 latency degradation, and unexpected revocation acceptance. Thresholds must be calibrated in staging rather than inferred from this local diagnostic.

## 24. Hosted-CI readiness

Release and supply-chain workflows now build, scan, and generate SBOMs for both the proxy and pilot image. Hosted CI remains required on the exact future commit for GitHub OIDC, branch protection, runner isolation, attestations, and release permissions.

## 25. Deployment checklist

The actionable image, digest, SBOM, vulnerability, PKI, identity, network, DNS, PostgreSQL, feature flag, health, metrics, testing, and rollback gates are in `docs/PROTECTED_AGENT_DEPLOYMENT.md`.

## 26. Rollback strategy

Stop protected operations, keep the protected-agent network internal/default-deny, restore a known-good proxy/gateway/certificate set, rerun security probes, then resume. Never restore direct internet to make a rollback “work.”

## 27. Backend tests

The complete backend suite collected 369 tests and passed with 366 passed and 3 environment-gated skips in a Linux Python 3.13 container. The PostgreSQL-gated security test was then passed separately against PostgreSQL 17.

## 28. PostgreSQL tests

The PostgreSQL 17 gated test passed separately with three logical proxy replicas racing one single-use authority.

## 29. Ruff

`ruff check src tests` and the new PKI utility check passed. Unrelated legacy scripts retain pre-existing lint findings and are outside the hosted workflow's Ruff scope.

## 30. TypeScript

`tsc --noEmit` passed.

## 31. ESLint

ESLint passed.

## 32. Frontend build

The production frontend build passed and emitted all expected routes.

## 33. Proxy image build

The hardened proxy and non-root pilot images built successfully. Compose validates with both opt-in profiles.

## 34. Rendered frontend tests

All 4 rendered frontend tests passed.

## 35. Trivy

The proxy and pilot images each reported zero fixable High/Critical vulnerabilities with Trivy 0.74.0 and the repository ignore policy.

## 36. SBOM

SPDX JSON generation succeeded for both images; each diagnostic document contained 148 package entries. CI publishes named SBOM artifacts for both.

## 37. Security coverage

All critical-path gates passed. `egress_proxy.py` measured 87.64%, above its 70% enforced floor, in the final source-only rerun after phase-latency instrumentation.

## Certification conclusion

The local phase meets the protected network, mTLS identity, rotation, three-replica, fail-closed, atomic authority, observability, image, vulnerability, and SBOM objectives. Hosted branch-protection CI is the remaining external evidence gate. This phase does not begin MCP, Nova integration, agent-to-agent communication, or autonomous behavioral blocking.
