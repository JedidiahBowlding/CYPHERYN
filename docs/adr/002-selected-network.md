# ADR 002: Selected network

Status: accepted; no network selected for deployment.

## Decision

Select **NO BLOCKCHAIN** for 0.9.x. If a later public-timestamp pilot passes privacy and custody review, evaluate infrequent Merkle super-roots on Ethereum L1 first. L2 deployment is contingent on measured L1 cost pressure.

## Rationale

Ethereum provides the clearest long-term public verification and EVM tooling, while L2s introduce sequencer, proof, upgrade, and dual-finality semantics. A permissioned ledger does not add independent public witnessing.
