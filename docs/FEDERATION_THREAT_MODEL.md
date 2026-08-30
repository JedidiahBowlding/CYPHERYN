# Federation Threat Model

Status: **EXPERIMENTAL**.

Protected assets are local evidence, authorization, credentials, signing keys, organization
isolation, peer trust decisions, and assertion provenance. Adversaries include Internet
attackers, malicious or compromised peers, replaying intermediaries, compromised operators,
and accidental misconfiguration.

Key threats and controls:

- impersonation/key substitution: cryptographic node IDs, pinned keys, explicit enrollment;
- tampering/downgrade: canonical Ed25519 signatures and exact protocol/algorithm allowlists;
- replay/duplicate delivery: persistent issuer/nonce and assertion-ID uniqueness;
- stale/future data: expiration, maximum lifetime, timezone and clock-skew enforcement;
- privacy exfiltration: minimal closed schema containing fingerprints and classifications;
- provenance confusion: separate federated tables, never promoted to local observation;
- malicious peers: suspension, revocation, bounded payloads, auditability, reverse-proxy rate limits;
- denial of service: body limits, timeouts and edge rate limits; local functions remain independent;
- central outage: no central dependency or discovery requirement;
- disagreement: retain every issuer and expose conflicts instead of majority truth.

Residual risks include administrator key-verification mistakes, node-key theft, traffic
analysis, compromised trusted peers emitting signed lies, and multi-worker rate limiting.
Signatures prove who asserted a claim, not that the claim is objectively true.
