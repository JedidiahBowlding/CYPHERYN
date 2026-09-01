# ADR 007: Smart-contract architecture

Status: accepted as a future constraint.

## Decision

If implemented, deploy one non-upgradeable event-only anchor registry. It accepts a fixed Merkle root record with sender-scoped monotonic sequence. It holds no funds, tokens, identity mappings, governance, marketplace, pause role, or proxy administrator.

## Consequences

Verification happens off-chain. A defect requires a new version/address and explicit verifier update; immutability is preferred over proxy attack surface.
