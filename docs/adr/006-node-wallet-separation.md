# ADR 006: Node and wallet identity separation

Status: accepted.

## Decision

Ed25519 remains the authoritative CYPHERYN node identity. A chain account is only a transaction signer. Optional binding requires chain-specific, expiring proof of possession from both keys and never enrolls a peer or migrates trust.

## Consequences

Wallet and node compromise, rotation, revocation, custody, and audit are separate lifecycles.
