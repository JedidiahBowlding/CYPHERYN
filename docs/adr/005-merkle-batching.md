# ADR 005: Merkle batching

Status: accepted as the only scalable public-anchor design; not implemented.

## Decision

Use sorted unique leaves and RFC 6962-style `0x00` leaf/`0x01` parent domain separation. Store only root, leaf count, batch sequence, version, and context on-chain. Retain leaf, salt, proof, and checkpoint off-chain.

## Consequences

Batching lowers transaction count and weakens one-to-one timing correlation, but an aggregator can omit leaves. Signed receipts, deadlines, and omission monitoring are required.
