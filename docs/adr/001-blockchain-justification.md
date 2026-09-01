# ADR 001: Blockchain justification

Status: accepted for 0.9.x.

## Decision

Do not add a blockchain dependency or testnet prototype now. A public chain is justified only as an optional external timestamp/order witness for privacy-preserving batched commitments. Existing Ed25519 checkpoints plus independently administered immutable storage remain the default.

## Consequences

CYPHERYN works during every chain/RPC/signer failure. No chain is used for scan authorization, evidence truth, federation trust, availability, or customer data. Reconsider only with measured customer demand and volume.
