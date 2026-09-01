# ADR 008: Blockchain signing-key custody

Status: accepted.

## Decision

Use disposable encrypted test keys in development, a low-value test-only policy signer in CI/testnet, and KMS/HSM-backed dedicated signing service with destination, selector, chain, value, fee, and rate policy in production.

Keys never enter `.env`, PostgreSQL, source, frontend, images, logs, the normal worker, or scanner orchestrator. Blockchain, node, evidence, Auth0, and provider keys are distinct.
