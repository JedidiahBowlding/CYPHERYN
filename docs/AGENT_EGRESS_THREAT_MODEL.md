# Agent Egress Firewall threat model

## Assets

Source code, screenshots, credentials, application documents, customer evidence, financial data, infrastructure details, policy records, approval tokens, audit evidence, and GitHub repository state.

## Trust boundaries

1. The development agent and its workspace are untrusted request originators.
2. The authenticated CYPHERYN API is the policy and evidence boundary.
3. Artifact bytes and OCR text are untrusted input.
4. The database stores metadata, hashes, findings, and decisions but not ordinary copies of artifact bodies.
5. GitHub and other outbound destinations are external systems whose final state must be verified.
6. Administrators approve policy and high-risk outbound actions; agents cannot assume that role.

## Principal threats and controls

| Threat | Control |
| --- | --- |
| Agent creates a public repository | Deterministic default block |
| Private repository made public | Deterministic default block and final-state verification |
| Secret in code or environment file | Local signature detection; only type/count retained |
| Sensitive screenshot upload | MIME magic verification, bounded Tesseract OCR, classification, quarantine on OCR failure |
| Unknown image/file host | Destination allowlist and default block |
| Approval reused or modified | Canonical action hash, expiring token hash, one-time consumption |
| Agent self-approval | Distinct user and organization-admin enforcement |
| Path traversal or symlink escape | Artifact bytes are uploaded; filenames must be basename-only |
| Parser exhaustion | File-size, subprocess timeout, output and artifact count limits |
| Prompt injection in document | Scanners treat text only as data; no LLM participates in enforcement |
| Scanner outage | Fail-closed decision or quarantine |
| Observed GitHub state differs | `MISMATCHED` event, high-severity egress finding, approval consumption |
| Audit rewriting | Event and audit hash chains; optional signed checkpoints outside the database |
| Secret leakage through logs/metrics | Structured log denylist; metrics contain bounded categorical labels only |

## Residual risks

Pattern scanners have false negatives and false positives. OCR quality varies. A privileged host or database administrator can bypass or recompute local state unless external checkpointing is operated. Commands that do not use the mediation API are not protected. Final GitHub verification currently trusts caller-supplied observations; direct least-privilege GitHub API verification is planned. This MVP must be combined with sandboxing, private repositories, credential isolation, branch protection, and network egress controls.
