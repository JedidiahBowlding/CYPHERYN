# ADR 004: Commitment construction

Status: accepted as design.

## Decision

Derive SHA-256 commitments from an explicit CYPHERYN domain tag, closed commitment type, protocol context, existing canonical checkpoint digest, and fresh 256-bit random salt using deterministic length-prefix encoding. Never expose a generic user-supplied hashing endpoint.

## Consequences

Domain separation prevents cross-protocol confusion; salts hide guessable inputs; canonical encoding prevents ambiguity. Opening material requires encrypted independent retention.
