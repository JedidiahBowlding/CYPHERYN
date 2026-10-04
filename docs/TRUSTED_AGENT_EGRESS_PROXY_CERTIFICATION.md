# Trusted Agent Egress Proxy Certification

Date: 2026-10-04  
Branch: `feature/agent-security-foundation`  
Baseline: `40975ad feat: bind execution authority to revocation and DNS`

## 1. Architecture

Protected workloads authenticate with their existing OIDC client-credentials token and submit an already evaluated operation to a separately deployable proxy. The proxy owns canonicalization, DNS resolution, final validation/atomic consumption, and the pinned TLS socket. PostgreSQL and the control plane remain authoritative; replicas are stateless.

## 2. ADR

`docs/adr/011-trusted-agent-egress-proxy.md` records the trust boundary, isolation model, failure behavior, HA design, migration path, and remaining post-validation/pre-connect race.

## 3. Files added or modified

The implementation adds the proxy runtime, hardened Dockerfile, receipt migration/model/API, proxy tests, deployment and certification documentation, dashboard telemetry, Compose networks/profile, configuration, coverage gating, and release/SBOM/container-scan integration.

## 4. Proxy authentication

The proxy requires a bearer token and delegates authoritative OIDC client-credentials verification to the existing workload-authenticated control-plane endpoints. Client, tenant, agent, decision, and authority identities are derived from control-plane state; caller-supplied `agent_id` is neither requested nor trusted.

## 5. Final-validation flow

The proxy resolves the destination, creates a durable attempt receipt, inspects the request, and calls `POST /api/v1/security/decisions/{decision_id}/validate` with the exact operation and pinned address using `consume=true`. No unrelated work occurs between a successful validation and the socket call.

## 6. Single-use consumption

The existing PostgreSQL `SELECT ... FOR UPDATE` validation path atomically increments use count. Concurrency certification proves one winner and `AUTHORITY_CONSUMED` for the loser.

## 7. DNS ownership

The proxy calls CYPHERYN canonicalization itself. All answers must be globally routable; mixed public/private answers fail. Final validation compares the current answer set to the authority-bound set and verifies the selected connected address.

## 8. Pinned socket implementation

`socket.create_connection()` targets the approved IP directly. The outbound HTTP request is written to that socket; no HTTP library performs another DNS lookup.

## 9. TLS behavior

`ssl.create_default_context()` retains chain, hostname, and expiry validation. The canonical hostname is used for SNI and `Host`. Wrong-hostname tests prove there is no insecure fallback. Only HTTPS/443 is supported.

## 10. Redirect behavior

Only bounded same-origin path redirects proceed on the same pinned address. Scheme, host, or port changes return `REDIRECT_REQUIRES_REAUTHORIZATION`; loops and excessive chains fail.

## 11. Header and body inspection

Credential, cookie, internal, proxy, framing, and hop-by-hop headers are blocked. Values and bounded bodies reuse CYPHERYN artifact classification. Secret or uninspectable content is quarantined. Raw secrets are never logged or persisted.

## 12. Response limits

Header bytes, response bytes, request bytes, redirects, validation, connection, and read time are configurable and bounded. Authentication response headers are stripped. Streaming is deliberately excluded.

## 13. Execution receipts

Migration `20261006_egress_proxy_receipts` stores safe identity, authority, destination, pinned IP, method, hashes/classifications, status, counts, timing, outcome, reason, and correlation metadata. No raw request/response body or credential is stored.

## 14. Multi-proxy concurrency

PASS. The PostgreSQL-gated integrated test runs two logical proxy replicas against one single-use authority and observes exactly one transport/socket execution.

## 15. Revocation race results

PASS for revocation before final validation: existing client, agent, capability, destination, and policy generation tests deny before socket ownership. The remaining interval is after the validation transaction commits and before `connect(2)` in the same trusted process; it is documented and no longer client-controlled.

## 16. Network-isolation design

Compose defines internal `protected-agents`, internal `backend`, and egress-capable `proxy-egress` networks. Only the proxy spans them. Production guidance requires default-deny workload egress and forbids workload membership in public/egress networks.

## 17. Bypass-test results

PASS in an isolated Docker network: a protected test workload reached proxy health but a direct connection to `1.1.1.1:443` failed. Unit and integration tests cover private/metadata destinations, alternate DNS/mixed answers, redirects, and consumed authority. Host/Kubernetes policy remains deployment-specific and must be certified in its target environment.

## 18. Failure-mode results

Control-plane/receipt failure, final denial, DNS rejection, timeout, TLS mismatch, response overflow, secret quarantine, redirect violations, and upstream errors fail closed and do not create a direct-egress fallback. A failed receipt finalization returns failure even if an upstream operation already completed; pending receipts require operational reconciliation.

## 19. Observability

The proxy exports secret-free Prometheus counters for requests, executions, denials/outcomes, timeouts, TLS/upstream failures, bytes, and aggregate latency, plus `/health`. Durable receipts provide per-operation traceability.

## 20. Dashboard integration

The existing Agent Egress page now shows recent proxy executions with time, agent, method/capability, destination, outcome/reason, latency, decision link data, and correlation ID. No broad redesign was performed.

## 21. Performance diagnostics

Local diagnostics only—these are not SLOs: policy destination canonicalization median 0.062 ms/p95 0.630 ms; DNS median 3.027 ms with a 51.539 ms maximum over ten samples; proxy logic with in-memory control/transport median 0.112 ms/p95 0.251 ms; SQLite/TestClient security evaluation median 68.430 ms/p95 148.081 ms; final validation median 40.666 ms/p95 51.535 ms; one containerized pinned TLS connection was 666.202 ms. Environment and network effects dominate real results.

## 22. Backend test count

357 tests collected. The ordinary suite passes with the PostgreSQL-gated test intentionally run separately.

## 23. PostgreSQL results

PASS on disposable PostgreSQL 17: migration upgrade, downgrade, and re-upgrade; idempotency concurrency; atomic authority consumption; two-proxy/one-socket certification; independent tenant work; and integrity-chain verification.

## 24. Ruff

PASS for API source, tests, the new migration, and the coverage gate.

## 25. TypeScript

PASS: `tsc --noEmit`.

## 26. ESLint

PASS.

## 27. Production build

PASS. The frontend production build and the separately hardened proxy image build complete.

## 28. Rendered frontend

PASS: four rendered-route tests.

## 29. GitHub Egress regression

PASS as part of the complete backend suite.

## 30. Federation regression

PASS for local federation suites as part of the complete backend suite. Hosted two-node CI was not run locally.

## 31. Security coverage

PASS: overall coverage remains above 60%; all existing critical gates pass and the proxy has a new 70% minimum gate. The proxy image has zero fixable High/Critical Trivy findings and an SPDX JSON SBOM was generated locally.

## 32. Known limitations

No streaming, HTTP, non-443 destination, CONNECT tunneling, client certificate, or cross-origin redirect support. The proxy currently handles HTTP/1.1 and buffers only up to a strict response limit. Compose demonstrates rather than imposes host-level enforcement.

## 33. Remaining risks

The narrow validation-to-connect race remains; an administrator with control-plane/database privilege can alter authoritative state; target-orchestrator network policy may be misconfigured; internal control-plane transport should be protected by the deployment network and upgraded to service identity/mTLS where its threat model requires it.

## 34. Release blockers

No code/test blocker for opt-in certification. Production enablement is blocked until the target environment applies and proves proxy-only workload egress and configures workload OIDC credentials. Hosted CI must prove the exact commit before release.

## 35. PASS or FAIL

PASS for the separately trusted, opt-in proxy milestone. This is not a claim that direct egress is blocked in deployments that do not enable network enforcement.

## 36. Merge recommendation

Recommend review and hosted CI on the feature branch, then merge if branch protection and the deployment-specific isolation review pass. Do not deploy merely because the code is merged.

## 37. Recommended next CYPHERYN phase

Pilot one protected agent class behind enforced proxy-only networking, add service-to-service mTLS/workload identity for the proxy-to-control-plane hop, exercise chaos at replica scale, and operationalize pending-receipt reconciliation. MCP, agent-to-agent communication, Nova integration, and autonomous behavioral blocking remain intentionally out of scope.
