# Blockchain Threat Model

Status: design only. Blockchain is optional and absent from production.

Security invariant: loss of every blockchain, RPC, signer, or anchor-worker component must not interrupt CYPHERYN scanning, evidence collection, reporting, federation, local revocation, or signed checkpoint creation.

| Threat | Asset | Attacker/precondition | Impact | Mitigation | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Malicious CYPHERYN node | Public-root meaning | Enrolled or independent node submits misleading checkpoints | Publicly timestamps a lie | Roots prove existence, not truth; preserve signer provenance; no automatic trust/reputation | Observers may overinterpret timestamp evidence |
| Compromised node key | Federation identity | Attacker steals Ed25519 key | Valid-looking assertions/transitions | Local revocation, short assertion lifetime, explicit re-enrollment, separate wallet | Events before detection remain attributable to the compromised key |
| Compromised wallet | Anchor account/funds | Chain signer is stolen or coerced | False roots, fee loss, metadata spam | KMS/HSM signer policy, zero-value fixed-contract calls, spend/rate ceilings, emergency disable, separate node key | Public false events cannot be deleted |
| Compromised or malicious RPC | Verification truth | RPC lies, censors, or serves stale fork | False submission/finality status | Two independent providers, optional self-hosted node, block/receipt/event agreement, fail closed | Providers may share upstream infrastructure |
| Chain reorganization | Anchor ordering/finality | Canonical chain changes | Previously observed event disappears or moves | Explicit confirmed/finalized states, finalized tags, reorg reconciliation, receipt re-verification | Catastrophic consensus failure can violate policy assumptions |
| Censorship/sequencer outage | Anchor availability | Validator/sequencer/provider excludes transactions | Delayed public timestamp | Bounded retries and fee ceiling; alternate RPC; L1 escape path where supported; core continues | A timestamp cannot be backdated after recovery |
| Smart-contract exploit | Registry integrity/funds | Contract bug or unexpected call semantics | Invalid/misleading events, locked workflow | Minimal non-upgradeable event-only contract, no funds/token/admin, audit and bytecode pinning | Immutable bugs require a new registry and explicit migration |
| Replay/cross-chain replay | Commitment uniqueness | Old signed request reused on another chain/registry | Duplicate or misleading anchor | Bind chain ID, registry, namespace, sequence, version; monotonic sequence and DB uniqueness | Reorg replacement must distinguish legitimate resubmission |
| Front-running | Operator metadata/sequence | Observer copies pending calldata | Copy or sequence griefing | Sender-scoped namespace/sequence, no secrets, commitment ownership defined by signed bundle—not transaction sender alone | Mempool reveals timing before inclusion |
| Metadata correlation | Customer confidentiality | Observer analyzes account and batch timing | Infers activity or operator relationships | Regular coarse batching, many leaves, fresh salts, no per-customer namespace, optional cover batches | Strong traffic analysis remains possible |
| Commitment guessing | Sensitive investigation data | Low-entropy domain/IP/email guessed | Confirms a private subject | 256-bit random salt, domain separation, no raw hashes, salt access control | Compromised opening bundle reveals the relationship |
| Contract-admin compromise | Registry integrity | Upgrade/pause/admin key compromised | Rules replaced or service censored | No proxy, pause, privileged submitter, or mutable admin in v1 | Chain governance can still alter underlying execution |
| Dependency compromise | Signer/verifier integrity | SDK, compiler, library, image compromised | Key theft or false verification | Lockfiles, SBOM, provenance, isolated builds, minimal libraries, reproducible bytecode, audits | Supply-chain compromise can evade automated detection |
| CI/release supply-chain compromise | Deployment integrity | Workflow/token/action compromised | Malicious worker/contract release | Pinned actions, protected branches, artifact attestations, independent bytecode verification | Repository administrator compromise remains powerful |
| Denial of service | Core and anchor availability | RPC flood, huge bundles, job storms | Queue exhaustion | Separate worker/queue/DB role, body and batch limits, quotas, circuit breakers; core has no dependency | Public verification freshness degrades during sustained outage |
| Economic spam/gas spike | Funds/availability | Congestion or attacker raises fees | Excess cost or delayed anchor | Fee/value ceilings, batch aggregation, daily budget, stale state, operator approval | Price volatility can make anchoring uneconomic |
| Signer unavailable | Anchor availability | KMS/HSM/network outage | Cannot submit transaction | Durable unsigned queue, alerting, no fallback key in `.env`, core continues | Public timestamp delayed until recovery |
| Signer policy bypass | Funds/registry integrity | Worker crafts unauthorized transaction | Transfer or arbitrary contract call | Signer reconstructs and allowlists destination, selector, chain, zero value, root/sequence bounds | Signer implementation is a high-assurance component |
| Database restart/race | Exactly-once submission | Concurrent workers or failover | Duplicate transactions/nonces | Transactional leases, unique batch/network constraint, nonce manager, idempotent reconciliation | Provider-side replacement semantics remain chain-specific |
| Anchor omission | Completeness | Aggregator excludes a node leaf | Valid root lacks expected checkpoint | Signed submission receipt, inclusion deadline, omission alarm, alternate batcher or direct anchor | Public chain cannot prove data that was never submitted |
| Salt loss | Verifiability | Opening bundle backup fails | Commitment cannot be opened | Encrypted independent bundle retention, restore drills, bundle checksums | Public root alone is intentionally opaque |
| Salt disclosure | Privacy | Bundle or storage compromised | Dictionary confirmation becomes possible | Least privilege, encryption, retention policy, incident response | Public permanence prevents revoking disclosed commitments |
| False revocation | Identity continuity | Compromised wallet/node key emits revocation | Observers treat valid identity as revoked | Dual proof, reason/version binding, local policy remains authoritative | External observers may still accept the false event |
| Lost old key during rotation | Continuity | Old key unavailable | Cannot prove normal transition | Treat new key as new identity; independent enrollment | Operational continuity requires manual coordination |
| Conflicting transition events | Identity continuity | Compromised key equivocates | Multiple successors claimed | Never auto-migrate trust; expose conflict; operator verifies out of band | No global mechanism can identify the legitimate successor |
| Privacy-policy bypass | Customer confidentiality | Arbitrary data reaches commitment API | Sensitive low-entropy data anchored | No generic hash endpoint; typed allowlist from signed checkpoints only; privacy tests and review | Insider with direct wallet access can bypass CYPHERYN controls |

## Trust boundaries

- The CYPHERYN evidence and federation boundaries remain authoritative and blockchain-free.
- The commitment builder may read signed checkpoint metadata but not raw evidence.
- The batcher has no signing key.
- The anchor worker has no node/evidence key and cannot read provider credentials.
- The policy signer has chain authority but accepts only a fixed, bounded registry operation.
- RPC services are untrusted observations, not consensus by themselves.
- The standalone verifier trusts configured chain genesis/chain ID, registry identity/bytecode, finality policy, and pinned CYPHERYN public keys.

## Incident priorities

1. Preserve local operation and evidence.
2. Disable chain submission without deleting queued commitments.
3. Revoke affected chain credentials and locally revoke affected node identities when applicable.
4. Record the last independently verified finalized event and all conflicting observations.
5. Rotate to a new chain account or registry only through an explicit, audited configuration update.
6. Never rewrite local evidence or peer trust to match a disputed chain observation.
