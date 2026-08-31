# Federation key continuity

Status: design only; automatic trust migration is intentionally not implemented.

CYPHERYN treats an Ed25519 public key as the node identity root. Replacing that key
therefore creates a new peer identity. Operators must enroll and approve the new peer
explicitly, then revoke the old peer. The application never silently carries trust,
authorization, rate state, or reputation from one key to another.

## Proposed normal-rotation record

A future versioned transition object may authorize continuity only when it contains:

- protocol version and transition identifier;
- old node ID and old key ID;
- new Ed25519 public key, derived new node ID, and derived new key ID;
- UTC transition time and a short expiry;
- signature by the old private key over the canonical transition object; and
- proof of possession signed by the new private key over the same transition ID.

Both signatures, both derived identifiers, the validity interval, replay uniqueness,
and current trust/revocation state must verify transactionally. Acceptance must remain
an administrator decision and must preserve an audit record. The old identity is
revoked only after explicit acceptance; transition records never reactivate revoked
keys.

## Compromise

Compromise is not normal rotation. If the old key may be compromised, its signature
cannot prove continuity. Revoke it, create a new node identity, distribute the new
fingerprint through an independently authenticated channel, and enroll it as a new
peer. Do not use an automatic transition record.

Until the complete protocol and interoperability/concurrency tests exist, key rotation
continues to create a new peer identity by design.
