# CYPHERYN Blockchain Architecture Audit

Audit date: 2026-09-01  
Repository commit reviewed: `9035d688bd4fbc7cb1b3b6355a45e5d2b79e1d3f`  
Application version: 0.9.0  
Decision: **NO TESTNET PROTOTYPE JUSTIFIED**

## Executive result

Blockchain is not required for CYPHERYN federation, evidence integrity, or production operation. The only distinctive near-term property a public chain could add is an independently observable timestamp and ordering witness outside all CYPHERYN-controlled trust domains. That value does not presently outweigh signer, RPC, contract, privacy, finality, monitoring, and operational complexity.

CYPHERYN must remain local-first, federation-capable, and blockchain-independent. No token, wallet feature, smart contract, chain dependency, testnet transaction, mainnet deployment, marketplace, staking system, DAO, or production change was created.

## Existing architecture verified

Source and current audits confirm:

- Ed25519-derived node identities and separately held private keys;
- signed canonical federation assertions with explicit peer enrollment;
- `PENDING`, `TRUSTED`, `SUSPENDED`, and `REVOKED` peer states;
- expiry, future-time checks, persistent assertion/nonce replay protection, and PostgreSQL race tests;
- a closed privacy-limited assertion schema and bounded request bodies;
- independent databases, worker queues, evidence/report state, and peer-loss survival;
- linked SHA-256 evidence/audit chains and Ed25519-signed external checkpoints;
- offline checkpoint verification and independently configurable storage;
- federation disabled by default with no central CYPHERYN control plane; and
- no blockchain dependency.

The existing Ed25519 node identity remains authoritative. Blockchain cannot authorize a scan, validate truth, override local revocation, or transport customer evidence.

## Value proposition and no-chain alternative

The useful blockchain proposition is narrow: publish a hiding commitment to a batch of existing signed checkpoints so an unrelated public consensus network witnesses the root no later than a finalized block. This can make later backdating or selective rewriting more detectable.

The no-chain alternative is stronger for current needs: send signed checkpoints to multiple independently administered WORM/object-lock destinations, add independent timestamp-authority receipts, retain public keys separately, and run scheduled offline verification/restore drills. It has lower privacy, custody, fee, dependency, and incident complexity while retaining CYPHERYN’s current guarantees.

## Chain decision matrix

Weighted score uses 1–5 fit scores and weights: security/decentralization 22%, cost/throughput 15%, finality clarity 10%, tooling 12%, data longevity 12%, operations 12%, governance/vendor risk 10%, and privacy fit 7%.

| Option | Weighted score / 5 | Decision |
| --- | ---: | --- |
| No blockchain | 4.54 | Recommended now |
| Base | 4.10 | Future high-frequency EVM candidate; sequencer/L2 risks apply |
| Arbitrum One | 4.10 | Future high-frequency EVM candidate; optimistic-rollup risks apply |
| OP Mainnet | 4.10 | Future high-frequency EVM candidate; dual finality applies |
| Ethereum L1 | 4.02 | Future infrequent-super-root candidate |
| Polygon PoS | 3.86 | Not preferred over Ethereum-derived candidates |
| Avalanche C-Chain | 3.71 | Capable but weaker fit for long-term public witness goal |
| Solana | 3.62 | Capable but unnecessary non-EVM operational divergence |
| Permissioned ledger | 2.71 | Does not supply independent public witnessing |

Official current sources and the full criterion table are in `docs/BLOCKCHAIN_ARCHITECTURE_EVALUATION.md`. Scores are decision aids, not immutable facts. Fees, governance, proof systems, sequencers, and network behavior must be re-evaluated at any future implementation date.

## L1/L2 decision

No chain is selected now. If requirements change, start by evaluating a periodic Ethereum L1 Merkle super-root because it minimizes verification semantics and maximizes long-term public accessibility. Frequent L2 roots plus periodic L1 super-roots are deferred: they add two finality policies, two reconciliation paths, cross-layer configuration, and extra metadata. Adopt that hierarchy only after measured volume makes L1 batching unsuitable.

## On-chain/off-chain and privacy boundary

Public chain data may contain only a versioned salted commitment or Merkle root, leaf count, batch sequence, and non-sensitive protocol context. Every customer, user, target, investigation, authorization, vulnerability, scanner, evidence, provider, malware, source, note, topology, credential, PII, report, key, and relationship value remains off-chain.

Raw hashes of domains, IPs, emails, IDs, node keys, or checkpoints are prohibited because low-entropy values are guessable and repeated digests are correlatable. There is no generic “hash arbitrary input” path. Commitment creation accepts only typed existing checkpoint objects inside a dedicated component.

## Commitment and Merkle construction

Each leaf is SHA-256 over a length-prefixed encoding of the `CYPHERYN:PUBLIC-COMMITMENT:v1` domain, closed type, protocol context, canonical checkpoint digest, and fresh 256-bit random salt. The salt and opening bundle remain encrypted off-chain.

Merkle batching uses sorted unique leaves, `SHA-256(0x00 || leaf)` for leaves, and `SHA-256(0x01 || left || right)` for parents. Algorithm version, ordering, and odd-node promotion are fixed. Proof bundles retain checkpoint, salt, sibling path, root, chain, registry, transaction, and finality evidence. Batching lowers cost and correlation but does not provide anonymity.

## Node/wallet identity and key transitions

Ed25519 remains the node identity; a chain account is only an optional transaction signer. Any binding is chain- and registry-specific, expires, and requires proof from both keys. Wallet compromise and node compromise remain separate incidents.

Normal key transition retains the existing dual-Ed25519 design and explicit administrator approval. A chain may publish only a salted transition commitment. It cannot automatically migrate trust. A lost or compromised old key cannot establish continuity; the new key is a new identity enrolled independently.

## Revocation

Local federation revocation is immediate and authoritative. An optional public self-revocation commitment could improve transparency but must not reveal peer relationships. It requires strong proof and is advisory because wallets can be compromised, RPCs can be stale, events can be censored, and chains can reorganize.

## Smart-contract and upgrade architecture

If a future pilot is approved, use one event-only `CypherynAnchorRegistry` accepting a fixed Merkle-root record with sender/namespace monotonic sequence. It has no token, funds, payments, marketplace, governance, identity mappings, mutable administrator, pause authority, or proxy.

Verification belongs in the independent utility. The contract is non-upgradeable; a defect or new format uses a new address/version and explicit verifier configuration. This makes bytecode identity auditable and removes proxy-admin compromise.

## Signing-key custody

Development uses disposable testnet-only encrypted keys. Automated testnet use requires a low-value policy signer isolated from general CI secrets. Any production signer must be a dedicated service backed by KMS/HSM, with fixed destination/function/chain, zero-value, fee/rate/budget ceilings, dual-control administration, audit logs, and emergency disable.

Chain keys are separate from federation node keys, evidence-anchor keys, Auth0 secrets, and provider credentials. They never enter `.env`, databases, source, frontend, images, normal logs, the normal worker, or scanner orchestrator.

## RPC architecture and finality

One RPC can submit but never alone establish consensus. Production verification requires two independently operated providers and preferably a read-only self-hosted node. Chain ID, registry bytecode, transaction receipt, event, block identity, and finalized head must agree.

States are `PENDING`, `SUBMITTED`, `CONFIRMED`, `FINALIZED`, `FAILED`, and `STALE`. Submission is not confirmation; confirmation is not finality. Reorganizations move affected anchors backward and trigger reconciliation. RPC disagreement stops public-anchor finalization but never CYPHERYN core.

## Anchor-worker architecture

The optional flow is existing checkpoint → typed commitment builder → durable Merkle-batch queue → dedicated anchor worker → policy signer → primary RPC → independent verifier RPCs. The component sees checkpoint metadata, not raw evidence. It has a narrow database role and no provider, node, evidence, Auth0, or scanner secrets.

Every chain failure degrades only anchor freshness. Scans, jobs, reports, evidence, federation, local revocation, and ordinary signed checkpoints continue.

## Database model

Future tables are `BlockchainNetwork`, `BlockchainCommitment`, `BlockchainBatch`, `BlockchainTransaction`, `BlockchainConfirmation`, and `BlockchainVerification`. They record network/contract policy, salted commitment, checkpoint reference, root/sequence, public sender/transaction/block data, provider observations, finality, and bounded failures. Private keys and raw sensitive inputs are forbidden. Unique constraints and transactional leases prevent duplicate/concurrent submissions.

## Independent verifier

A future `cypheryn verify-chain-anchor <bundle>` command operates without the API. It verifies evidence against the current Ed25519 checkpoint, derives the salted leaf, checks the Merkle path/root, validates expected chain/registry/bytecode and event, compares independent RPC observations, and applies the configured finality rule. Unknown versions/algorithms fail closed.

## Failure model

RPC outage or dishonesty, rejected/stuck/replaced transactions, gas spikes, chain halt, sequencer outage, reorganization, contract defect, signer outage, and wallet compromise are isolated to the optional worker. Bounded retry, cost ceilings, circuit breakers, replacement tracking, reorg reconciliation, and operator alerts apply. No fallback key is placed in application configuration.

## Cost model

Individual annual transaction volume ranges from 5,200 (100 nodes weekly) to 87.6 million (10,000 nodes hourly). Daily individual anchoring produces 36,500, 365,000, or 3.65 million transactions for 100, 1,000, or 10,000 nodes. A global Merkle batch reduces hourly/daily/weekly roots to 8,760/365/52 annually but adds aggregator omission and availability risk.

Actual cost is transaction volume multiplied by measured execution/data fees, plus RPC, indexing, KMS/HSM, monitoring, reconciliation, and staffing. No future token price or fee is fabricated. Testnet gas measurement and current fee percentiles are mandatory before reconsideration.

## Future economic layer

No economic layer is justified now. Future intelligence, analysis, scanner, or researcher payments should evaluate fiat first and stablecoins second. A proprietary CYPHERYN token currently adds no necessary property beyond stable settlement, cryptographic identity, and reputation, while adding major legal, tax, AML/sanctions, governance, liquidity, and manipulation risk.

Any token proposal is a separately governed and legally reviewed project. This phase creates none.

## Threat model and ADRs

`docs/BLOCKCHAIN_THREAT_MODEL.md` defines assets, attackers, preconditions, impact, mitigation, and residual risk for node/wallet/RPC compromise, reorganization, censorship, contract defects, replay, front-running, metadata leakage, guessing, admin/dependency/supply-chain compromise, denial of service, and economic spam.

Ten ADRs record blockchain justification, network selection, off-chain boundary, commitment construction, Merkle batching, identity separation, contract minimization, key custody, RPC/finality policy, and the no-token decision under `docs/adr/`.

## Prototype decision and entry criteria

**NO TESTNET PROTOTYPE JUSTIFIED.** Existing independent anchoring should be operationally proven first. A future prototype requires all of:

1. documented customer need for public timestamping;
2. measured batch volume and retention requirements;
3. privacy review of the commitment/opening format;
4. signer and RPC threat-model approval;
5. contract and verifier specifications independently reviewed;
6. testnet-only funds and isolated development branch; and
7. proof that chain outage cannot affect core or federation.

If approved later, the required test plan includes deterministic commitments/canonicalization/salts, valid and invalid Merkle proofs, wrong root/chain/contract/node, duplicates and concurrent submission, RPC outage/disagreement, failed/replaced transaction, delayed confirmation, reorganization, signer failure, database/worker restart, and core operation throughout chain outage.

## Final architecture judgment

CYPHERYN should not adopt blockchain merely because its evidence is security-sensitive. The system already has stronger application-specific provenance than a raw public transaction supplies. Public anchoring becomes rational only when an external, globally observable timestamp is a concrete customer or assurance requirement. Until then, no-chain independent storage is simpler, more private, cheaper, and easier to operate correctly.

ARCHITECTURE EVALUATION PASSED — NO BLOCKCHAIN OR TOKEN IMPLEMENTATION AUTHORIZED
