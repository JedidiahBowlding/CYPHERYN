# SignalTrace Engineering Maturity Implementation Plan

Baseline: `9513c1f32ca55ab5a07e155d1c155e1a920032ba` on `main`, clean and synchronized with `origin/main` at the start of this milestone.

## Guardrails

- Preserve local-first operation and the existing authorization, evidence-provenance, credential-redaction, and integrity-chain controls.
- Do not add providers or imply that adapter presence is live verification.
- Fail closed when scanner authorization, target policy, or anchor verification is ambiguous.
- Keep external observability and anchoring destinations optional.
- Test SignalTrace-owned behavior deterministically without live provider calls or external targets.

## Workstream design

1. **Scanner isolation:** add a provider-neutral disposable-container execution policy and runner. Container launches use allowlisted image references, read-only roots, dropped capabilities, `no-new-privileges`, bounded CPU/memory/PIDs/output/time, isolated temporary storage, no host mounts or Docker socket, and explicit network modes. High-risk adapters use this boundary only when a scanner image is configured; unavailable isolation fails closed. Authorization is revalidated immediately before launch. Cancellation removes the container and cleanup runs on every outcome.
2. **Observability:** persist worker heartbeats and provider-operation metrics, propagate correlation IDs from request/job through evidence and audit metadata, expose safe health/metrics endpoints, and document actionable alert conditions. Prometheus output remains dependency-free and optional to scrape.
3. **Provider certification:** define `SUPPORTED`, `EXPERIMENTAL`, `ADAPTER_ONLY`, and `INHERITED` policy tiers plus timestamp-derived live-verification freshness. Only explicitly certified adapters can be `SUPPORTED`; readiness and certification remain separate dimensions.
4. **Critical paths:** add behavior-focused tests for authorization, leases, retries, cancellation, provider failure, normalization, detection, reports, notifications, malware safety, isolation, observability, and integrity anchoring. Add focused per-module coverage gates without imposing SignalTrace thresholds on inherited SpiderFoot.
5. **Integrity anchoring:** produce versioned chain-head checkpoints, sign them with an external Ed25519 private key, support provider-neutral file/HTTP destination interfaces, add offline verification, and reference anchors from export manifests. Signing keys never enter application database records.
6. **Governance/releases:** add missing governance files, Dependabot, PR/issue templates, a reproducible release workflow, checksums, SBOMs, provenance where GitHub supports it, and documented branch protection.

## Verification sequence

1. Run API tests, critical coverage gates, Ruff, frontend lint/type/build/render, provider contracts, scanner-isolation tests, integrity and anchor tests.
2. Run npm and Python audits, Gitleaks, Trivy, SBOM generation, migration/schema validation, and Compose smoke tests.
3. Create `docs/ENGINEERING_MATURITY_RELEASE.md` and a final read-only `SIGNALTRACE_ENGINEERING_MATURITY_AUDIT.md` from measured results.
4. Commit and push the complete tree, then require hosted CI success on that exact commit before declaring completion.

## Explicit boundaries

- Docker network controls reduce scanner exposure but cannot express destination-level egress ACLs consistently on Docker Desktop without a policy-aware gateway. The default isolated mode therefore denies networking; active network scans require an explicitly selected restricted network and retain application-level target validation.
- Disposable containers are a stronger boundary, not proof that scanner code is harmless or that the Docker daemon is outside the host trust boundary.
- Signed anchors detect divergence from an independently retained checkpoint; they do not prevent a privileged actor from rewriting unanchored history or compromising both trust domains.
