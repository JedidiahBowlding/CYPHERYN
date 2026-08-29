# Architecture Audit

**Audit date:** 2026-08-25  
**Repository:** SignalTrace working tree  
**Revision:** `0f815a20` (`master`, `v4.0-138-g0f815a20`)  
**Scope:** Read-only assessment. No product code was changed.

## Executive conclusion

This repository is a capable single-user OSINT collection engine, not a safe foundation for the complete multi-tenant intelligence platform by direct extension. Preserve it as a separately deployed collector and put a new application layer in front of it. The application layer should own identity, authorization, investigations, canonical entities, provenance, jobs, graph queries, AI retrieval, reporting, and audit history.

The immediate architectural decision is therefore:

- **SpiderFoot: integrate as an isolated service; maintain a minimal mirror/fork only for reproducible builds and narrowly scoped adapter fixes.**
- **IntelOwl: deploy independently and integrate through its authenticated API.**
- **Maltego: implement an original graph workspace; use only documented interoperability protocols/SDKs under their applicable terms.**
- **Primary persistence: PostgreSQL, with relational adjacency tables and recursive CTEs first.** Do not add Neo4j until representative benchmarks demonstrate a need.

## Existing system inventory

| Area | Finding | Reuse decision |
|---|---|---|
| Runtime | Python 3; SpiderFoot reports 4.0.0 | Reuse inside collector container |
| Web | CherryPy + Mako + jQuery/Bootstrap | Do not use as the product UI/API |
| Storage | SQLite with WAL and a process-wide `RLock` | Collector-local only; normalize into PostgreSQL |
| Collection | 233 `sfp_*.py` modules found locally | Reuse selectively through policy profiles |
| Orchestration | In-process scan controller, module threads, queues, shared thread pool | Wrap; do not treat as durable job infrastructure |
| Correlation | 37 YAML rules found locally | Reuse as collector-derived signals, with provenance |
| Graph | Sigma.js/D3, JSON/GEXF export | Replace UI; retain export compatibility if useful |
| Interfaces | CLI plus numerous CherryPy endpoints | Adapter may use a constrained internal interface; never expose directly |
| Authentication | Optional HTTP Digest from a plaintext `username:password` file | Replace at gateway/application layer |
| Authorization | No tenant, investigation ownership, RBAC, or scoped provider policy | New implementation required |
| AI | None identified | New evidence-grounded service required |
| Containers | Single SpiderFoot service and persistent volume | Retain as an internal-only service |
| Tests | 444 `test_*.py` files found; unit/integration/acceptance/bandit areas | Retain upstream suite; add platform suites separately |
| CI | GitHub Actions for flake8/pytest and an old CodeQL workflow | Replace/modernize actions; add SBOM, image, migration, policy tests |
| Deployment | Dockerfiles and Compose; no production topology | Build a separate platform Compose/Kubernetes topology |

## Architecture details

### Collection and module system

`sf.py` loads Python modules dynamically. Modules derive from `SpiderFootPlugin`, declare consumed/produced event types, and communicate through publisher/subscriber queues. `sfscan.py` creates a scan, loads configured modules, starts module threads, distributes `SpiderFootEvent` objects, stores results through the storage module, and optionally runs correlation rules.

This design is effective for bounded collection but lacks durable queue semantics, leases, worker heartbeats, retry policy, per-provider quota accounting, and strong cancellation guarantees. Treat one SpiderFoot scan as an opaque collector execution managed by a platform job.

### Data and provenance available today

`SpiderFootEvent` carries event type, data, generation time, confidence, visibility, risk, producing module, source-event linkage, and optional data-source fields. SQLite stores scan, module, data, source hash, confidence, visibility, risk, timestamps, logs, and correlations. This is useful input provenance, but it does not meet the target model by itself:

- event hashes are instance identities containing time/randomness, not content-addressed evidence hashes;
- provider source URL/raw reference is not uniformly represented;
- investigation/tenant ownership does not exist;
- first/last observed semantics are not canonicalized;
- facts, derived relationships, and AI assessments are not typed as separate claim classes;
- immutable evidence retention and legal deletion workflows are absent.

### Web/API surface

The CherryPy methods support scan creation, status, results, correlations, logs, exports, and visualization. They are UI-oriented endpoints rather than a versioned, tenant-safe REST contract. The open-source product advertises CLI/web operation but not the fully RESTful API offered by SpiderFoot HX. An adapter must not rely on undocumented handlers as a permanent public contract.

### Security controls

Positive controls include loopback default binding, optional TLS when certificate files exist, optional HTTP Digest authentication, CORS origin configuration, scan cancellation, and test/security tooling. Material gaps for the target platform include:

- authentication can be disabled and Docker maps port 5001 to the host;
- credentials are read from a plaintext password file;
- no MFA/OIDC, tenant model, RBAC, object ownership, or service identities;
- no mandatory authorization record for targets;
- passive and active-capable modules are not enforced by an external policy boundary;
- provider secrets are stored in collector configuration/SQLite rather than a dedicated secret manager;
- no platform-wide audit ledger, retention/export policy, or field-level sensitive-data controls;
- no durable API rate limiting or provider budget enforcement.

### Test and delivery posture

The broad upstream test inventory is valuable. CI currently targets old Python versions and old major revisions of GitHub Actions. External-module integration tests are excluded from the standard pytest command. There is no evidence in this audit of platform-level authentication, authorization, tenancy, migrations, supply-chain signing, deployment promotion, backup/restore, or disaster-recovery tests.

## Proposed target architecture

```text
Browser
  -> reverse proxy / WAF
  -> platform API (OIDC, RBAC, scope policy, audit)
       -> PostgreSQL (system of record + graph edges)
       -> object storage (raw evidence/reports)
       -> Redis-compatible broker/cache
       -> worker service
            -> SpiderFoot adapter -> isolated SpiderFoot
            -> IntelOwl adapter   -> isolated IntelOwl
            -> provider adapters  -> approved external APIs
            -> normalization/entity resolution
            -> report renderer
       -> AI gateway -> evidence retriever -> approved model provider
  <- event stream / polling for job and alert updates
```

### Service ownership

- **Frontend:** React/TypeScript; Cytoscape.js investigation graph. Cytoscape has mature interaction/layout/plugin support and is adequate for initial investigation sizes. Benchmark WebGL-based Sigma if graphs exceed agreed thresholds.
- **Platform API:** versioned REST/OpenAPI; owns authorization and canonical semantics. FastAPI is a pragmatic Python choice but should be validated in M1 ADRs.
- **Worker:** durable jobs, leases, retries, idempotency, cancellation, quotas, and provider concurrency.
- **SpiderFoot adapter:** translates a policy-approved target/module profile into a scan and streams/polls raw events into ingestion.
- **IntelOwl adapter:** submits enrichment jobs through documented API tokens, polls/webhooks results, and preserves analyzer provenance.
- **AI gateway:** retrieval-only access to authorized evidence; structured output validated against cited evidence IDs; no direct collector or internet authority.
- **PostgreSQL:** investigations, assets, observations, entities, relationships, claims, jobs, findings, alerts, audits, and report metadata.
- **Object storage:** immutable raw payloads, screenshots/documents where lawful, generated reports, and hash-addressed evidence bodies.

## Reuse versus replacement

### Reuse

- SpiderFoot module ecosystem, event propagation, target validation, correlation rules, and scanner CLI/runtime.
- Collector-local SQLite as an implementation detail and recovery artifact.
- Upstream unit/integration tests and Docker build knowledge.
- JSON/CSV/GEXF exports for migration and interoperability.

### Replace or add

- Replace the product-facing web UI and all public API assumptions.
- Add OIDC authentication, RBAC/ABAC scope checks, tenant/investigation ownership, and immutable audit.
- Add durable jobs and provider quotas.
- Normalize all collector outputs into canonical PostgreSQL models.
- Build the original graph workspace, change detection, reports, and evidence-grounded AI.
- Move secrets to a secret manager/encrypted credential service and inject short-lived values.

## Key decisions and gates

1. Keep upstream code under `upstream/spiderfoot`; place new code under separate top-level services or, preferably, a sibling platform repository.
2. SpiderFoot and IntelOwl get no inbound public ports in production.
3. Default collection profile is passive. Active-capable modules require explicit authorization, policy approval, and separate worker/network placement.
4. Store claims separately from evidence. A claim may be `OBSERVED_FACT`, `DERIVED_RELATIONSHIP`, or `AI_ASSESSMENT`.
5. Every relationship and finding must cite one or more immutable evidence records.
6. Benchmark PostgreSQL graph queries using representative datasets before evaluating a graph database.

## Audit limitations

This was a repository/static architecture audit, not a penetration test or live scan. Tests were inventoried but not used as evidence of new-platform behavior. External provider terms and SDK licenses can change and require legal review before production release.
