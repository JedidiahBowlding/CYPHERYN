# Implementation Plan

## Delivery strategy

Build a separate platform application around isolated upstream services. Each milestone exits only when acceptance criteria, automated tests, security gates, rollback evidence, and documentation are present. “Implemented” does not mean “production ready.”

## M0 — Architecture and licensing

**Deliverables:** these eight documents; ADRs for repository layout, API framework, UI, job broker, evidence storage, and tenant enforcement; SBOM baseline.

**Acceptance:** decisions approved by engineering/security/legal owners; upstream commits and licenses pinned; module risk-classification process defined.  
**Tests/security:** secret scan, dependency/license inventory, threat-model review.  
**Rollback:** documentation-only; revert ADR before dependent implementation.  
**Docs:** architecture, licenses, upstream patch policy.

## M1 — Core platform/API

**Deliverables:** organization/user/membership/investigation/authorization/target APIs; OIDC; PostgreSQL migrations; audit events; health/metrics; local Compose skeleton.

**Acceptance:** versioned OpenAPI; tenant-scoped CRUD; mandatory target authorization; no public internal services.  
**Tests/security:** authn/authz/IDOR, migration, rate-limit, audit, secret-redaction, health tests.  
**Rollback:** backward-compatible migrations and prior image; restore drill.  
**Docs:** API, RBAC matrix, local development, runbooks.

## M2 — SpiderFoot integration

**Deliverables:** pinned container, internal adapter, passive module allowlist, job start/status/cancel/import, raw artifact capture.

**Acceptance:** bounded authorized scan imports provenance idempotently; collector unavailable/partial/cancel paths work.  
**Tests/security:** mocked contract tests, replay, crash recovery, SSRF/egress, module-policy enforcement; upstream suite.  
**Rollback:** disable integration flag and pin previous digest without schema loss.  
**Docs:** adapter contract, module classifications, upstream update/patch ledger.

## M3 — Canonical intelligence model

**Deliverables:** entity/observation/evidence/relationship schema; normalization; deterministic dedupe; evidence object storage.

**Acceptance:** supported SpiderFoot events map without provenance loss; invalid types quarantine; repeated imports are stable.  
**Tests/security:** property-based normalization, collisions, cross-tenant constraints, evidence hash verification, retention.  
**Rollback:** versioned normalizers; reprocess from immutable raw evidence.  
**Docs:** mapping catalog, schema, normalization versions.

## M4 — Investigation graph

**Deliverables:** Cytoscape.js workspace; bounded graph API; expand/collapse/filter/group/search; entity/evidence panel; saved layouts.

**Acceptance:** required interactions work at representative graph sizes; all edges expose claim class/confidence/evidence.  
**Tests/security:** query caps, tenant boundaries, XSS-safe rendering, visual/E2E/performance tests.  
**Rollback:** UI feature flag; graph is a projection, so canonical data remains intact.  
**Docs:** graph semantics, keyboard/accessibility, performance envelope.

## M5 — IntelOwl/threat intelligence

**Deliverables:** independent pinned IntelOwl; token-auth adapter; analyzer allowlists; provider usage/error provenance.

**Acceptance:** configured observable enrichments normalize; partial analyzer failures are visible; paid APIs mocked in CI.  
**Tests/security:** contract, quotas, timeouts, unsafe-file policy, egress, token rotation.  
**Rollback:** disable analyzers/adapter and pin prior digest.  
**Docs:** analyzer catalog, license/terms matrix, operations.

## M6 — AI investigation engine

**Deliverables:** authorized evidence retrieval; structured claim schema; citation verifier; AI analyst and security brief; model usage accounting.

**Acceptance:** every substantive claim cites accessible evidence; unsupported requests abstain; uncertainty is explicit.  
**Tests/security:** grounding metrics, prompt injection, cross-tenant retrieval, citation mutation, redaction, cost limits.  
**Rollback:** disable AI writes/display by feature flag; retain deterministic findings.  
**Docs:** model/prompt policy versions, evaluation card, human-review workflow.

## M7 — Attack-surface monitoring

**Deliverables:** registered assets, cadences, snapshots, bounded rescan scheduling, temporal observations.

**Acceptance:** resumable scheduled jobs respect authorization expiry and provider budgets.  
**Tests/security:** scheduler idempotency, revoked scope, clock/timezone, concurrency, quota.  
**Rollback:** pause schedules; preserve snapshots.  
**Docs:** monitoring profiles and ownership workflow.

## M8 — Alerts and change detection

**Deliverables:** snapshot diff engine; significance/risk rules; alert lifecycle/deduplication.

**Acceptance:** new/disappearing/changed assets and services produce explainable evidence-backed changes.  
**Tests/security:** noisy/flapping signals, late observations, duplicates, rule versions, authorization.  
**Rollback:** revert rule version and recompute from snapshots.  
**Docs:** rule catalog, triage playbook.

## M9 — Reporting

**Deliverables:** JSON, HTML, PDF reports; signed/hash manifest; fact/derived/AI visual distinction.

**Acceptance:** reports include scope, methods, timeline, evidence, confidence, remediation, versions, and chain-of-custody manifest.  
**Tests/security:** schema, snapshot/golden render, malicious content escaping, export authorization, large report, PDF inspection.  
**Rollback:** preserve template versions and regenerate.  
**Docs:** report schema/templates and verification guide.

## M10 — Security hardening

**Deliverables:** secrets manager, key rotation, security headers, WAF/rate policies, hardened containers, retention/export controls, incident runbooks.

**Acceptance:** high-risk threat-model items verified; independent penetration test issues resolved or accepted.  
**Tests/security:** SAST/SCA/DAST, container/IaC scans, backup/restore, key rotation, DR and incident exercises.  
**Rollback:** staged policy rollout and previous signed configurations.  
**Docs:** security architecture, incident response, data handling.

## M11 — Deployment

**Deliverables:** production IaC, private networking, observability/SLOs, backups, migrations, canary/blue-green release.

**Acceptance:** staging soak; load/failure tests; restore and rollback within objectives; internal services unreachable externally.  
**Tests/security:** chaos, capacity, regional failure as applicable, deployment policy and image signature checks.  
**Rollback:** tested image/config/database rollback with forward-fix rules.  
**Docs:** deployment and on-call runbooks.

## M12 — Production certification

**Deliverables:** evidence pack, legal/privacy/security approvals, operational readiness review, risk register, customer-facing limitations.

**Acceptance:** all prior gates evidenced; no unresolved critical issues; RTO/RPO/SLO and support ownership approved.  
**Tests/security:** full regression/evals, final penetration/recovery tests, audit sampling.  
**Rollback:** launch stop/feature disable/traffic rollback decision tree.  
**Docs:** certification record, known limitations, release notes.

## Cross-cutting engineering rules

- Trunk-based, reviewed changes; signed/pinned artifacts; no unreviewed upstream auto-merge.
- Expand APIs/schemas compatibly; migrations are tested against production-shaped data.
- Mock external paid providers in CI; run credentialed tests only in controlled staging.
- Structured logs and metrics include request/job/investigation IDs but exclude secrets/raw sensitive evidence.
- Milestone status is backed by linked test, review, and rollback evidence.

## First implementation slice after approval

1. Establish sibling directories (`platform/api`, `platform/worker`, `platform/frontend`, `platform/adapters`) while moving/pinning this checkout under `upstream/spiderfoot` or a submodule/subtree.
2. Implement M1 identity/investigation/scope schema and tests.
3. Define a fake collector contract before connecting SpiderFoot.
4. Complete passive/active classification for each enabled SpiderFoot module.
5. Demonstrate one passive domain scan end-to-end into immutable evidence and canonical entities.

