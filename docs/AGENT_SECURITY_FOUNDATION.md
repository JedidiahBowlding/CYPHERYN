# Agent Security Control-Plane Foundation

CYPHERYN exposes a generic security-decision service for AI systems and other
workloads. It is independent of any particular agent product.

## Security flow

1. A workload obtains an OAuth 2.0/OIDC client-credentials access token from the
   configured identity provider.
2. CYPHERYN verifies the token signature, issuer, audience, timestamps and client
   identity.
3. The verified client is matched to an active organization-owned `SecurityClient`.
4. The requested agent must belong to that client and be active.
5. The agent must have an unexpired capability grant for the environment.
6. CYPHERYN canonicalizes and resolves the HTTPS destination. Any non-public DNS
   answer fails closed. Redirect targets must be evaluated as new destinations by
   the enforcing client.
7. The active immutable policy evaluates destination trust, classifications and
   capability requirements deterministically.
8. CYPHERYN returns an `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `QUARANTINE`, or
   `ALLOW_WITH_REDACTION` result and stores a tamper-evident receipt.

No LLM participates in the authoritative decision.

## Workload authentication

The initial mechanism is OAuth 2.0 client credentials represented by a verified
OIDC access token. This reuses CYPHERYN's issuer, audience, JWKS and signing
algorithm validation. It avoids introducing a proprietary credential protocol and
supports centralized rotation and revocation at the identity provider.

The token must contain `azp` or `client_id`. Browser proxy identity and development
identity headers are deliberately rejected by workload endpoints. CYPHERYN stores
only the external client identifier and a non-secret credential reference; it does
not store the client secret.

## Generic decision API

`POST /api/v1/security/evaluate` requires:

- a verified workload bearer token;
- an active registered client and associated protected agent;
- action, capability, HTTPS destination and environment;
- canonical data classifications;
- bounded resource-scope and context metadata;
- request ID, idempotency key, nonce and timezone-aware timestamp.

Context is reduced to a SHA-256 digest in the receipt. Idempotency keys and nonces
are stored only as hashes. Reusing an idempotency key with a different request or
reusing a nonce is rejected.

## Shadow and enforce modes

In `ENFORCE`, the evaluated decision is also the effective and enforced decision.

In `SHADOW`, the full evaluated decision is recorded, but the effective and
enforced decisions are `ALLOW`. Identity, timestamp, replay, policy availability
and tenant-boundary failures occur before shadow evaluation and remain fail closed.

The receipt always exposes evaluated, effective and enforced decisions separately.

## BLOCK compatibility

Existing `/api/v1/egress/*` records and database enums continue using `BLOCK`.
The generic public contract maps internal `BLOCK` to `DENY` at the API boundary.
Historical records are neither rewritten nor silently reinterpreted.

## Current phase boundary

This milestone does not implement delegated authority, advanced risk scoring,
behavioral baselines, short-lived authority tokens, MCP proxying, or agent-to-agent
protocols. The data and decision contract is designed to accommodate those later
phases without coupling CYPHERYN to a specific agent product.

As of 2026-10-04, npm reports GHSA-vfj7-8cjw-p6xm against the transitive
build/lint dependency `braces` 3.0.3. No fixed npm release exists. CYPHERYN does
not pass user-controlled glob patterns to this dependency, but the advisory remains
an explicit supply-chain limitation until Vinext and the lint dependency graph can
consume a patched upstream release.
