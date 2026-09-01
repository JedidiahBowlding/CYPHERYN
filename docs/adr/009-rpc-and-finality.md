# ADR 009: RPC trust and finality

Status: accepted.

## Decision

One RPC may submit but cannot establish finality. Production verification requires agreement between two independently operated RPCs and preferably a self-hosted read node on chain ID, registry bytecode, receipt, event, block, and finalized head.

States are `PENDING`, `SUBMITTED`, `CONFIRMED`, `FINALIZED`, `FAILED`, and `STALE`. Disagreement or reorganization stops blockchain finalization without affecting CYPHERYN core.
