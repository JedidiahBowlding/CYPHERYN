# ADR 003: What stays off-chain

Status: accepted.

## Decision

All customer, investigation, authorization, target, evidence, scanner, provider, topology, identity-relationship, credential, malware, source, note, report, PII, and secret data stays off-chain. Raw or unsalted hashes of low-entropy data are also prohibited.

Only versioned salted commitments and Merkle batch context may become public. Off-chain bundles retain salts, checkpoints, proofs, receipts, and evidence.
