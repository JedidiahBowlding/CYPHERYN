# CYPHERYN Federation Readiness Audit

Audit date: 2026-08-30

Released prerequisite: `v0.9.0` at `12ea6849132806cdebbf642447fe7b0c0506053b`

Federation implementation commit: `ba323a0889526eaf9c6332eec774baf5161df89f`

Branch: `feature/federation-foundation`

## Executive result

CYPHERYN now has an optional, experimental, non-blockchain federation foundation. Two
independently administered nodes can identify one another cryptographically, enroll pinned
peers, create and exchange minimal signed assertions, preserve remote provenance, reject
tampering and replay, revoke trust, expose bounded federation metrics, and continue local
operation when a peer disappears. Federation remains disabled by default and does not alter
v0.9.0 evidence, scanner, provider, authorization, or report behavior.

## Release prerequisite

The annotated `v0.9.0` tag resolved to exact commit `12ea684`. Release workflow
`33331274052` passed API/frontend tests, Ruff, TypeScript, dependency audits, five image
builds, Trivy High/Critical gates, SPDX SBOM generation, SHA-256 checksums, provenance
attestation, and GitHub Release publication. The release is
https://github.com/JedidiahBowlding/CYPHERYN/releases/tag/v0.9.0. All seven downloaded
artifacts passed `SHA256SUMS`; provenance verification succeeded.

## Architecture and identity

A node is an autonomous CYPHERYN installation with separate administration, database,
evidence, providers, scanners, and keys. Node ID and key ID are SHA-256 fingerprints of an
Ed25519 public key, not host or database identifiers. The private key remains in a local
read-only runtime secret. Identity initialization refuses overwrite and is idempotent when
the existing key is valid.

## Trust, protocol, and API boundaries

Peer trust is explicit: `PENDING → TRUSTED → SUSPENDED/REVOKED`. Enrollment validates that
the supplied node ID and key ID match the pinned public key. No discovery service or central
CYPHERYN system is required. The separate `/api/federation/v1/` namespace exposes identity,
health, capabilities, organization-authorized peer administration, explicit assertion
creation, signed inbound delivery, and provenance-preserving reads.

Remote delivery requires HTTPS except loopback development. Application signatures remain
mandatory independently of TLS. Production mTLS belongs at a policy-enforcing reverse proxy
and does not replace message verification.

## Assertion and cryptographic model

`FederatedSecurityAssertion` v1 uses canonical compact, sorted-key JSON and Ed25519. It
contains protocol/assertion identity, issuer node/key IDs, issuance/expiration/observation
times, closed assertion and subject classifications, SHA-256 subject/evidence fingerprints,
source category, confidence, severity, optional public checkpoint metadata, a random nonce,
algorithm, and signature. Unknown fields, versions, types, algorithms, and malformed hashes
fail closed.

Verification pins issuer and key IDs, enforces a 30-day maximum lifetime, clock skew,
expiration, future-time rejection, signature validity, and a 64 KiB default body limit.
Persistent assertion-ID and issuer/nonce uniqueness provide restart-safe replay protection;
nested transactions translate uniqueness races into fail-closed replay rejection.

## Privacy and provenance

The closed schema cannot carry credentials, tokens, private keys, customer records, private
topology, source code, raw reports, malware, PII, authorization documents, unrestricted
evidence, or analyst notes. Sharing requires an authenticated organization administrator.
Remote assertions live in dedicated tables and never become local `EvidenceSource` records.
Issuer, key, signed payload, payload/evidence fingerprints, verification result, trust state,
receipt time, and expiration remain inspectable.

## Revocation, corroboration, and disagreement

Suspended/revoked peers cannot submit new assertions. Historical records retain the public
identity and signed payload for inspection while current trust reflects revocation. Rotation
is deliberately treated as a new cryptographic identity pending a standardized signed key-
transition protocol.

Corroboration reports independent issuer count, source diversity, ages, evidence
fingerprints, severities, and whether claims agree. It preserves malicious/unknown/benign
disagreement and does not use majority vote or manufacture a probability.

## Observability and audit

Prometheus output includes total/trusted/suspended/revoked peers and received/verified
assertion counts without raw subjects or secrets. Peer enrollment/state changes and accepted,
created, and rejected assertions enter CYPHERYN's integrity-chained audit log. Per-issuer,
per-organization minute windows are transaction-locked for bounded API rate limiting.

## Two-node verification

`compose.federation.yaml` built and ran Node A and Node B with separate PostgreSQL volumes,
Ed25519 key volumes, configurations, identities, and loopback ports. The observed integration
sequence was:

1. Both nodes returned different cryptographic identities.
2. Each node created an independent organization and administrator.
3. Both nodes enrolled and explicitly trusted the other pinned identity.
4. Node A created and signed an allowed fingerprint-only assertion.
5. Node B accepted it with HTTP 202 and stored verified remote provenance.
6. Duplicate delivery returned 422; a tampered severity returned 422.
7. Delivery after peer revocation returned 422.
8. Node B retained one valid record.
9. Node A was stopped; Node B federation health remained `ready`.

The disposable test containers and four test volumes were removed after verification.

## Failure and regression tests

Federation tests cover cryptographic identity, valid round trip, unsupported protocol and
algorithm, invalid assertion/subject classes, malformed fingerprints and confidence,
tampering, key substitution, expiration, future timestamps, oversized and extra fields,
agreement/disagreement, durable provenance, replay, suspension/revocation, disabled-by-
default behavior, API enrollment/delivery, HTTPS enforcement, timeout, unreachable peer,
HTTP failure, malformed acknowledgement, and independent-peer loss. Database uniqueness and
nested rollback protect duplicate/concurrent delivery.

The complete API suite passed with all critical gates, including worker orchestration at
75.04%, federation core at 75.85% (70% gate), and federation API at 78.23% (70% gate). Ruff
and both core and federation Compose validations passed.

The exact merged implementation commit passed hosted Tests run `33332402794`,
cross-platform run `33332402811`, CodeQL run `33332402808`, and Security and supply chain
run `33332402830`.

## Backward compatibility

`PLATFORM_FEDERATION_ENABLED` defaults to false. Core Compose adds no federation service or
public port. Existing deployments require no peer, new credential, blockchain component,
or extra Internet dependency. Existing evidence chains, anchors, reports, providers,
authorization, scanner isolation, and local workflows are unchanged.

## Known limitations and remaining work

- This is an experimental foundation, not a production federation release.
- Production mTLS, certificate issuance, edge rate limiting, and network policy are operator
  responsibilities; the API should not be exposed directly to the Internet.
- Automatic outbound scheduling/retry is not yet wired to the worker; delivery is explicit.
- Key rotation currently creates a new node identity; signed continuity transitions remain
  planned and must not be implied.
- Federation metrics do not yet include latency histograms or per-rejection counters.
- A future milestone should add PostgreSQL multi-process load tests, chaos/network-partition
  tests, and a formal external interoperability suite.
- Signed assertions prove issuer authorship, not objective truth; trusted nodes can lie.

FEDERATION FOUNDATION VERIFIED
