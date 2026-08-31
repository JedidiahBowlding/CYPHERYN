# CYPHERYN Federation Architecture

Status: **EXPERIMENTAL**. Federation is disabled by default and is not part of v0.9.0.

## Purpose and node definition

A CYPHERYN node is one independently administered installation with its own database,
provider credentials, scanners, evidence, authorization records, and Ed25519 node-identity
key. A node remains fully useful without peers. Federation exchanges signed, minimal
security assertions; it never replicates customer databases or grants peers access to local
administrative APIs.

Node identity is the SHA-256 fingerprint of its Ed25519 public key, expressed as a stable
`cypheryn-node:` identifier. Display names, hostnames, IP addresses, and DNS are mutable
metadata and are never identity roots. Private keys stay in the issuing node's key store.

## Trust and threat model

The first protocol uses explicit administrative enrollment. There is no public discovery,
automatic trust, central CYPHERYN dependency, consensus system, blockchain, or economic
mechanism. Peers move through `PENDING`, `TRUSTED`, `SUSPENDED`, and `REVOKED`. Enrollment
requires out-of-band comparison of node ID, key ID, and public key. TLS protects transport;
Ed25519 application signatures provide portable authenticity after transport ends.

Threats include impersonation, key substitution, replay, clock manipulation, compromised
peers, malicious payloads, privacy leakage, denial of service, downgrade, and confused
provenance. Controls are pinned keys, canonical serialization, bounded schemas and request
sizes, expiration and future-time checks, persistent nonce uniqueness, explicit revocation,
rate limits, correlation IDs, audit events, and fail-closed verification.

## Assertion and evidence boundary

`FederatedSecurityAssertion` v1 contains issuer/key identity, issuance and expiration,
assertion and subject classes, subject and evidence fingerprints, source category,
confidence, severity, observation time, optional public checkpoint metadata, a random nonce,
and an Ed25519 signature over canonical JSON. Fingerprints are SHA-256 values, not raw
customer artifacts.

Credentials, tokens, private keys, customer identity, private topology, source code, raw
reports, malware, PII, authorization documents, evidence payloads, and analyst notes are
never valid assertion fields. Sharing is explicit, minimal, policy-controlled, and audited.
Received assertions are stored separately from local evidence and always retain issuer,
signature result, trust state, fingerprint, receipt time, expiration, and correlation data.

## Protocol and synchronization

The schema is closed: source categories are enumerated and there is no arbitrary
evidence or nested-object field. Only SHA-256 subject/evidence fingerprints cross the
boundary; raw evidence and sensitive operational/customer material cannot be encoded
as a valid v1 assertion.

The versioned boundary is `/api/federation/v1/`. Identity, health, and capabilities are
read-only. Peer administration remains organization-authorized. Assertion submission uses
strict schemas and signature verification before persistence. Synchronization is
store-and-forward with idempotent assertion IDs and nonces; it is not database replication.
An unreachable peer cannot prevent local operation.

Unknown versions, unknown keys, invalid signatures, expired or future assertions, replayed
nonces, oversized bodies, suspended/revoked peers, and malformed objects fail closed.
Protocol evolution must preserve canonical v1 verification and historical key material.

## Revocation and rotation

Suspension blocks current exchange without deleting history. Revocation blocks new trust
decisions permanently unless an administrator performs a new enrollment. Historical signed
assertions remain inspectable with retained public keys and are displayed with the issuer's
current revoked state. Key rotation is a new cryptographic identity until an explicitly
signed transition format is standardized; administrators enroll and verify it out of band.

## Corroboration and disagreement

Corroboration groups compatible subject fingerprints while preserving every issuer's claim.
It reports independent issuer count, current trust state, age, source diversity, agreement,
disagreement, and evidence fingerprints. It does not use majority vote as truth or invent a
probability. Conflicting malicious, unknown, and benign assertions remain visible.

## Operations and failure behavior

Metrics cover peer states, request/failure counts, latency, signature/replay/expiration
rejections, sent/received assertions, and corroborated groups without labels containing
secrets or raw subjects. Peer and assertion lifecycle actions enter the existing integrity-
chained audit model. Federation defaults off, opens no additional port, and requires no peer,
Internet service, or change to existing evidence and checkpoint verification.
