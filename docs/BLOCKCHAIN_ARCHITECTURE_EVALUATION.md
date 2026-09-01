# Blockchain Architecture Evaluation

Status: architecture decision for CYPHERYN 0.9.x; no blockchain implementation or deployment.

Repository commit reviewed: `9035d688bd4fbc7cb1b3b6355a45e5d2b79e1d3f`

## The question

> What security or economic properties can blockchain provide that CYPHERYN federation and independent anchor storage cannot already provide?

CYPHERYN already creates SHA-256 evidence chains and Ed25519-signed checkpoints that can be copied into an independently administered immutable store and verified without the API. A blockchain adds useful value only when CYPHERYN needs a globally observable, append-only timestamp and ordering witness whose operation is independent of every CYPHERYN operator and storage administrator. It does not establish that evidence is true, authorize a scan, make a malicious node honest, protect plaintext, or replace explicit federation trust.

The decision for 0.9.x is **NO TESTNET PROTOTYPE JUSTIFIED**. Continue improving independent WORM/object-lock anchoring and offline verification. Preserve a chain-neutral commitment format so a later testnet pilot can be evaluated without changing evidence, federation, or identity semantics.

## Capability classification

| Capability | Classification | Reason |
| --- | --- | --- |
| Public timestamping | OPTIONAL ON-CHAIN | A public chain can witness existence before a block, but RFC 3161-style timestamping and multiple independent immutable stores are simpler alternatives. |
| Evidence checkpoint anchoring | OPTIONAL ON-CHAIN | Publish only a hiding commitment or batched root. Existing signed checkpoints remain authoritative. |
| Node identity transparency | KEEP OFF-CHAIN | Public node discovery creates correlation and targeting risk. Explicit pinned enrollment is safer. |
| Key-transition transparency | OPTIONAL ON-CHAIN | A public commitment can make equivocation visible, but dual Ed25519 signatures and administrator approval remain mandatory. |
| Revocation transparency | OPTIONAL ON-CHAIN | Public self-revocation may help observers; local revocation remains authoritative and peer relationships stay private. |
| Protocol-version commitments | OPTIONAL ON-CHAIN | Release signatures, source attestations, and transparency logs usually provide the same property more directly. |
| Federation assertion commitments | KEEP OFF-CHAIN | Per-assertion commitments leak timing/volume metadata and add no trust to a signed assertion. If ever needed, include only in a mixed Merkle batch. |
| Future payments | NOT JUSTIFIED NOW | No present settlement requirement. Fiat and stablecoins should be evaluated before new assets. |
| Future marketplace settlement | NOT JUSTIFIED NOW | Marketplace governance, quality disputes, sanctions, privacy, and legal obligations are unsolved. |
| Staking/reputation | NOT JUSTIFIED | Capital at risk does not prove intelligence accuracy and invites Sybil, bribery, and regulatory complexity. |

## Absolute public-chain privacy boundary

Public-chain data is permanent, replicated, indexable, and correlatable. CYPHERYN must never publish customer names, usernames, email addresses, customer-associated IP addresses or domains, credentials, tokens, authorization documents, customer vulnerability descriptions, scanner output, evidence, malware, source code, notes, investigation IDs, node topology, provider responses, PII, or secrets.

Hashing a low-entropy value is not anonymization. A raw hash of an email, domain, IP address, investigation ID, checkpoint digest, or node key can be guessed or correlated. No application endpoint may accept arbitrary bytes and forward their digest on-chain.

An eligible public commitment must be derived inside a dedicated anchor component from an allowlisted internal object, using a fresh 256-bit cryptographically random salt and explicit domain/context binding. Salt and opening data remain off-chain and access-controlled. Batch timing should be coarse and regular; empty or cover batches may be needed if traffic analysis is material.

## Commitment construction

Use established SHA-256 and deterministic length-prefixed encoding:

```text
leaf = SHA-256(
  len("CYPHERYN:PUBLIC-COMMITMENT:v1") || "CYPHERYN:PUBLIC-COMMITMENT:v1" ||
  len(commitment_type)                 || commitment_type                 ||
  len(protocol_context)                || protocol_context                ||
  len(checkpoint_sha256_bytes)         || checkpoint_sha256_bytes         ||
  len(random_salt_32_bytes)            || random_salt_32_bytes
)
```

The checkpoint digest binds the public commitment to the existing canonical checkpoint. The domain tag blocks cross-protocol use; type and context block cross-purpose use; fixed-length cryptographic salt provides hiding against dictionary attacks; length prefixes prevent ambiguous concatenation. The salt is never reused. Sequence, batch identifier, chain ID, registry identifier, commitment version, and Merkle algorithm are bound into the signed off-chain bundle and the on-chain batch context. A public commitment is not accepted twice for the same `(network, registry, batch, leaf)`.

Publishing the existing checkpoint SHA-256 directly is rejected as the default because repeated publication allows correlation across stores and may confirm possession of a leaked checkpoint. SHA-256 collision resistance is adequate; no novel cryptography is introduced.

## Merkle batching

Leaves are sorted by their 32-byte value, deduplicated, and combined using RFC 6962-style domain separation:

```text
merkle_leaf = SHA-256(0x00 || leaf)
parent      = SHA-256(0x01 || left || right)
```

The tree algorithm, odd-node rule, leaf count, and ordering are versioned. An odd final node is promoted unchanged rather than duplicated. Off-chain bundles retain the checkpoint, salt, leaf, ordered sibling path, batch sequence, root, network, registry, transaction, and finality evidence.

Batching materially reduces transaction count and obscures one-to-one timing, but does not guarantee anonymity: an observer can still see batch timing and operator account activity. A verifier recalculates checkpoint digest and leaf, walks the proof, compares the root and event context, then verifies finality through independent RPC sources.

## Node identity and wallet separation

The Ed25519 node key remains the sole CYPHERYN federation identity. A chain account is only an optional payment/transaction signer. A binding requires proof of possession by both keys over a canonical object containing protocol version, chain ID, registry address, Ed25519 node/key commitments, chain account, nonce, issuance, and expiry. Neither signature silently enrolls a peer or migrates trust.

Wallet compromise permits fraudulent chain submissions but not valid federation assertions. Node-key compromise permits CYPHERYN impersonation but not chain spending. Both require separate revocation. Bindings are chain-specific to prevent replay. Wallet and node rotations are independent lifecycle events.

## Key transition and revocation

The off-chain transition in `docs/FEDERATION_KEY_CONTINUITY.md` remains authoritative: old and new Ed25519 keys sign, and an administrator decides whether to accept it. A public chain may record only a salted commitment to that complete transition. It must not contain node IDs, keys, peer relationships, or operator metadata.

If the old key is lost or suspected compromised, it cannot authorize continuity. The replacement is a new identity enrolled out of band. An on-chain event never automatically migrates peer trust.

An optional self-revocation event may commit to a node/key identity and revocation statement with dual proof from the node key and separately controlled chain signer. False, censored, reorganized, or stale events are advisory. Every node applies local `SUSPENDED`/`REVOKED` state immediately and without RPC availability.

## Minimal registry

If a future pilot is approved, use one non-upgradeable, event-only `CypherynAnchorRegistry` with no token, payments, governance, allowlisted evidence fields, or mutable identity mapping. Conceptual operation:

```solidity
event RootCommitted(
    bytes32 indexed namespace,
    uint64 indexed sequence,
    bytes32 root,
    uint32 leafCount,
    bytes32 context
);

function commitRoot(
    bytes32 namespace,
    uint64 sequence,
    bytes32 root,
    uint32 leafCount,
    bytes32 context
) external;
```

The registry rejects zero roots, zero leaves, and non-monotonic sequences per sender/namespace. Events are sufficient because verification needs inclusion and ordering evidence, not mutable application state. `verifyCommitment` belongs in the standalone verifier; a view method cannot prove off-chain checkpoint ownership. Identity and revocation registries are deferred. No proxy or upgrade administrator is justified; a new version uses a new contract address and explicit verifier configuration.

## Failure and finality policy

The optional anchor pipeline has `PENDING`, `SUBMITTED`, `CONFIRMED`, `FINALIZED`, `FAILED`, and `STALE` states. `SUBMITTED` means only that an RPC accepted a transaction. `CONFIRMED` means included but still inside the configured reorg window. `FINALIZED` requires the chain-specific finalized block policy and agreement from independent RPC sources.

RPC outage, dishonest RPC, rejection, replacement, fee spike, chain halt, sequencer outage, reorganization, contract fault, signer outage, or wallet compromise never blocks scanning, evidence persistence, reporting, federation, or existing signed checkpoint creation. Jobs retry with bounded exponential backoff and a cost ceiling. Reorganizations return affected records to `SUBMITTED` or `STALE`; conflicting RPC observations stop finalization and alert an operator.

## Multi-RPC verification

Production would require two independently operated RPC providers and preferably a read-only self-hosted node. Transaction hash, receipt status, block hash/number, event payload, chain ID, registry bytecode hash, and finalized head must agree. One provider may submit, but cannot alone assert finality. Provider disagreement fails closed for blockchain verification while CYPHERYN core stays available.

## Signing-key custody

| Environment | Recommended custody |
| --- | --- |
| Development | Disposable local encrypted keystore with testnet-only funds and no reused password/key. |
| Testnet CI | Dedicated low-value signer service or CI workload identity backed by a test-only KMS key; strict spend and destination policy. |
| Production | Dedicated signing service backed by cloud KMS/HSM, transaction-policy allowlist, fee/value ceiling, dual-control administration, audit logging, and emergency disable. |

Blockchain private keys never enter `.env`, PostgreSQL, source, frontend, images, or ordinary logs. They are separate from node identity, evidence-anchor, Auth0, and provider keys. The normal worker and scanner orchestrator never receive signing authority.

## Optional anchor-worker architecture

```text
evidence chain -> existing signed checkpoint -> commitment derivation
              -> durable batch queue -> dedicated anchor worker
              -> policy-enforcing signer -> RPC submitter
              -> independent RPC verifier -> finalized receipt bundle
```

The worker consumes checkpoint references, not raw evidence. Its database role cannot read provider credentials or authorization documents. Queue deduplication keys use network, registry, commitment version, and batch ID. The signer accepts only the fixed registry operation, zero native-value transfer, bounded fee, expected chain ID, and approved contract bytecode identity.

## Database design

| Table | Security-relevant fields |
| --- | --- |
| `BlockchainNetwork` | name, chain ID, finality policy, enabled flag, approved registry and bytecode hash; no secret RPC credentials |
| `BlockchainCommitment` | version, type, salted commitment, checkpoint reference, salt-custody reference, state, created time |
| `BlockchainBatch` | sequence, algorithm, root, leaf count, closed time, state |
| `BlockchainTransaction` | batch, network, sender public address, nonce, tx hash, replacement hash, submitted time, bounded failure code |
| `BlockchainConfirmation` | tx, RPC source identifier, block hash/number, receipt status, observed/finalized time |
| `BlockchainVerification` | bundle digest, expected/observed network and registry, proof/finality result, verifier version, time |

Private keys and raw sensitive inputs are forbidden. Failure text is enumerated/redacted. Unique constraints prevent duplicate leaves, batches, sequence reuse, and concurrent transaction submission.

## Independent verifier

The future `cypheryn verify-chain-anchor <bundle>` utility must operate without the CYPHERYN API. It verifies the local evidence export and Ed25519 checkpoint, derives the salted commitment, verifies the Merkle path, obtains the registry event from at least two RPC views or supplied authenticated headers/receipts, checks chain ID/contract/bytecode identity, and applies the configured finality policy. The bundle format must be self-describing, versioned, canonical, and reject unknown algorithms.

## Cost and scale model

Annual individual transactions, before retries or replacements:

| Nodes | Hourly | Daily | Weekly |
| ---: | ---: | ---: | ---: |
| 100 | 876,000 | 36,500 | 5,200 |
| 1,000 | 8,760,000 | 365,000 | 52,000 |
| 10,000 | 87,600,000 | 3,650,000 | 520,000 |

Cost equals `transactions × (execution gas + data gas) × contemporaneous fee`, plus RPC, indexing, signer, monitoring, and reconciliation. Future token prices and congestion are unknowable, so this evaluation does not fabricate dollar totals. Measure gas on testnet and price it with observed fee percentiles before any pilot.

One globally aggregated hourly/daily/weekly Merkle root reduces chain transactions to 8,760/365/52 per year regardless of leaf count, but creates an aggregator availability and omission problem. Per-node daily batches preserve autonomy but scale linearly. A hierarchical design can combine node-signed roots into a periodic public super-root while keeping signed omission receipts. At present volume, operational infrastructure dominates and public-chain cost is not justified.

## Current network comparison

Scores are architectural estimates from 1 (poor fit) to 5 (strong fit), weighted for CYPHERYN anchoring—not a claim of universal network quality. Fees are variable and must be measured at decision time.

| Criterion | Weight | Ethereum | Base | Arbitrum | OP Mainnet | Polygon PoS | Avalanche C | Solana | Permissioned | No chain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Security/decentralization | 22 | 5 | 4 | 4 | 4 | 3 | 3 | 3 | 2 | 4 |
| Cost/throughput | 15 | 1 | 5 | 5 | 5 | 5 | 4 | 5 | 3 | 5 |
| Finality clarity | 10 | 5 | 4 | 4 | 4 | 5 | 5 | 5 | 5 | 5 |
| Contract/tool maturity | 12 | 5 | 5 | 5 | 5 | 5 | 5 | 4 | 3 | 5 |
| Data longevity/access | 12 | 5 | 4 | 4 | 4 | 3 | 3 | 3 | 2 | 3 |
| Operational simplicity | 12 | 3 | 4 | 4 | 4 | 4 | 4 | 3 | 2 | 5 |
| Governance/vendor risk | 10 | 5 | 3 | 3 | 3 | 3 | 3 | 3 | 2 | 5 |
| Privacy fit | 7 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 4 | 5 |
| **Weighted score / 5** | **100** | **4.02** | **4.10** | **4.10** | **4.10** | **3.86** | **3.71** | **3.62** | **2.71** | **4.54** |

| Option | Security/finality and reorg model | Fees, throughput, and data availability | Contracts and integration | RPC, archive, adoption, and governance | Test environment |
| --- | --- | --- | --- | --- | --- |
| Ethereum L1 | Broad PoS validator set; Casper-FFG finalized checkpoints require an extreme consensus failure to revert | Lowest throughput and congestion-sensitive EIP-1559 gas; calldata/logs replicated by L1 | EVM/Solidity; mature Python `web3.py` and TypeScript/Ethers ecosystem | Many independent RPC/archive operators and long-lived public history; protocol upgrades require ecosystem coordination | Sepolia |
| Base | Optimistic Ethereum rollup; unsafe sequencer inclusion progresses through L1 batch inclusion/finality; permissionless fault proofs and a security council, with one active sequencer documented | Low L2 execution plus Ethereum data-security fee; transaction data posted to Ethereum | EVM/Solidity and OP Stack tooling; straightforward Python/TypeScript reuse | Multiple commercial/public RPCs, but chain operation/upgrades retain rollup-specific governance and sequencer dependencies | Base Sepolia |
| Arbitrum One | Optimistic Nitro rollup; sequencer path plus L1 delayed-inbox force inclusion and dispute/finality semantics | Low execution/data fees and high throughput relative to L1; Ethereum settlement/data dependencies | EVM/Solidity plus optional Stylus; mature EVM Python/TypeScript libraries | Broad ecosystem/RPC support; sequencer, upgrade, and L1/L2 archive interpretation remain operational dependencies | Arbitrum Sepolia |
| OP Mainnet | OP Stack unsafe → safe → Ethereum-finalized progression; fault-proof and upgrade assumptions must be tracked | Lower L2 fees; data posted as Ethereum blobs/calldata | EVM/Solidity; mature OP/EVM tooling for Python and TypeScript | Broad RPC ecosystem; sequencer and collective/governance upgrades add trust and monitoring requirements | OP Sepolia |
| Polygon PoS | Heimdall-v2/CometBFT milestones document 2–5 second deterministic finality; checkpoints periodically anchor to Ethereum | High throughput and low POL-denominated fees; separate validator/data system | EVM/Solidity with standard Python/TypeScript JSON-RPC tooling | Many RPC vendors and broad adoption; validator, staking, and protocol governance differ from Ethereum L1 | Amoy |
| Avalanche C-Chain | Snow-family repeated sampling with fast finality; distinct validator/governance system | Low-latency EVM execution and dynamic AVAX gas | EVM/Solidity and standard Ethereum tooling | Public/commercial RPC and archival operation available; smaller independent history/ecosystem than Ethereum | Fuji |
| Solana | Stake-weighted consensus with confirmed/finalized commitment levels; different failure and account semantics | High throughput and low SOL fees; compact transaction/account model | Rust/sBPF programs; strong TypeScript tooling, different Python maturity and indexer model | Public RPCs exist but production commonly needs dedicated providers/indexing; validator/client governance is non-EVM | Devnet/testnet |
| Permissioned ledger | Deterministic member-controlled ordering/finality; security equals consortium governance | Capacity/cost controlled by members; private channels/collections can limit disclosure | Fabric chaincode or Besu EVM depending stack; additional PKI/member operations | Operators themselves control availability/history, so it is not an independent public witness | Local consortium network |
| No chain | Existing Ed25519 signatures plus independently administered WORM/timestamp witnesses; no consensus reorg | No gas; throughput and retention are operator-designed | Existing Python verifier and storage interfaces; no contract/indexer | Choose multiple storage/timestamp vendors and offline copies; simplest long-term verifier, but independence must be operationally proven | Existing Compose/offline verification |

Ethereum has the strongest long-term public verification and mature EVM tooling, but variable L1 cost makes it suitable only for infrequent batching. Base, Arbitrum, and OP Mainnet reduce cost and inherit Ethereum data/finality in stages, but introduce sequencer, upgrade, fault-proof, and L1/L2 interpretation complexity. Base currently documents one active sequencer; early inclusion is not L1 finality. Arbitrum offers forced inclusion through its delayed inbox; OP chains distinguish unsafe, safe, and finalized blocks.

Polygon PoS provides EVM compatibility and fast milestone finality with periodic Ethereum checkpoints, but uses its own validator/governance system. Avalanche C-Chain offers EVM tooling and fast finality. Solana offers high throughput, low fees, mature TypeScript/Rust integration, and a different account/program/indexing stack; that divergence is unnecessary for a 32-byte root event. A permissioned ledger provides privacy and deterministic governance but merely creates another consortium control plane and does not provide independent public witnessing. No chain, using several independently administered immutable stores and timestamp authorities, best matches current requirements.

### L1 versus L2

For low-frequency roots, Ethereum L1 is simpler to explain and independently verify. For high-frequency roots, an Ethereum L2 is cheaper but requires CYPHERYN to model sequencer inclusion, L1 data inclusion, L1 finality, proof-system/upgrade risk, and possibly withdrawal finality. A two-tier `frequent L2 root → periodic Ethereum L1 super-root` design adds two contracts, two finality policies, cross-layer reconciliation, and more metadata. It is deferred until measured load proves a single periodic L1 root insufficient.

## Future economic layer

No economic layer is implemented. If a real marketplace emerges, evaluate fiat billing first for legal clarity, then regulated stablecoin settlement where atomic machine payment is genuinely needed. Native assets introduce volatility; a CYPHERYN token adds issuance, liquidity, governance, manipulation, tax, securities, AML, and sanctions risk without currently providing a property that stablecoins plus cryptographic identity and off-chain reputation cannot provide. The recommendation is **do not create a CYPHERYN token**.

Any later token proposal is a separate project requiring specialist legal, securities, tax, AML/sanctions, governance, economic, manipulation, and smart-contract review.

## Decision

Keep CYPHERYN blockchain-independent and do not build a testnet prototype in this phase. Complete real independent WORM retention, restore drills, timestamp-service diversity, and verifier operations first. Reconsider a narrowly scoped Ethereum-compatible pilot only when customers require public timestamping, expected volume is measured, privacy review approves the commitment format, and an independently audited signer/registry design exists.

If that threshold is reached, the conservative first candidate is a non-upgradeable event-only registry on Ethereum L1 for infrequent Merkle super-roots. Frequent L2 roots plus periodic L1 super-roots are not justified until measured volume makes L1-only anchoring economically unsuitable.

## Official sources

- [Ethereum proof-of-stake finality](https://ethereum.org/developers/docs/consensus-mechanisms/pos/)
- [Ethereum gas and fees](https://ethereum.org/developers/docs/gas/)
- [Base protocol overview](https://docs.base.org/base-chain/specs/protocol/overview)
- [Base transaction finality](https://docs.base.org/base-chain/network-information/transaction-finality)
- [Base network fees](https://docs.base.org/base-chain/network-information/network-fees)
- [OP Stack transaction finality](https://docs.optimism.io/op-stack/transactions/transaction-finality)
- [Arbitrum Nitro whitepaper](https://docs.arbitrum.io/nitro-whitepaper.pdf)
- [Polygon PoS finality](https://docs.polygon.technology/pos/concepts/finality/finality)
- [Polygon PoS architecture](https://docs.polygon.technology/pos/architecture/overview)
- [Avalanche consensus](https://build.avax.network/docs/nodes/architecture/consensus)
- [Avalanche exchange/finality integration](https://build.avax.network/docs/primary-network/exchange-integration)
- [Solana core concepts](https://solana.com/docs/core)
- [Solana fees](https://solana.com/docs/core/fees)
- [Hyperledger Fabric private data](https://hyperledger-fabric.readthedocs.io/en/latest/private-data/private-data.html)
