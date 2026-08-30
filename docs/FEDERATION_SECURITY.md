# Federation Security

Status: **EXPERIMENTAL**.

Federation uses TLS for encrypted transport and Ed25519 signatures for portable message
authenticity. Operators should deploy mTLS at a reverse proxy for production peers, while
still verifying application signatures. CYPHERYN does not implement custom encryption.

Private node keys are local files with restrictive permissions and are never returned by an
API. Peer records contain public keys only. Node identity and key ID are derived from the
public key, preventing a hostname or database identifier from substituting identity.

Inbound assertions are accepted only from explicitly trusted, non-revoked peers. Strict
field allowlists, SHA-256 fingerprint fields, a 64 KiB default limit, Ed25519 verification,
five-minute clock skew, 30-day maximum lifetime, persistent issuer/nonce uniqueness, and
idempotent assertion IDs fail closed against malformed data, tampering, downgrade, future
timestamps, expiration, and replay.

Federated records never become local `EvidenceSource` records. They preserve the remote
issuer, key, signed object, payload fingerprint, verification result, trust state, receipt
time, and expiration. Suspension/revocation changes current trust without erasing historical
cryptographic inspection.

Production gaps: distributed rate limiting and mTLS certificate lifecycle remain deployment
responsibilities; the experimental API should stay behind a policy-enforcing reverse proxy.
Do not expose it directly to the public Internet.
