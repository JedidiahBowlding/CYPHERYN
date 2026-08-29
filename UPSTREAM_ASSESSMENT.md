# Upstream Assessment

**Assessment date:** 2026-08-25

## Decision summary

| Project | Decision | Reason |
|---|---|---|
| SpiderFoot | **Integrate; maintain a minimal mirror/fork** | Strong collector/module ecosystem, permissive MIT license, but its UI/storage/auth/job model is not the platform boundary |
| IntelOwl | **Independent service via API** | Purpose-built multi-analyzer enrichment API; AGPL isolation reduces coupling and preserves upgradeability |
| Maltego | **Interoperate only; build an original graph** | Product code/branding are proprietary; documented SDK/protocol concepts may be used under their own terms |

## SpiderFoot

### What it provides

The audited checkout contains a Python/CherryPy application, 233 collection modules, a publisher/subscriber event model, threaded scan orchestration, SQLite persistence, 37 YAML correlation rules, CLI/web operation, result export, and Sigma/D3 visualization. The upstream README describes 200+ integrations, JSON/CSV/GEXF export, SQLite, and passive/active collection use cases.

Primary source: [SpiderFoot repository](https://github.com/smicallef/spiderfoot).

### Recommendation: integrate, do not turn the fork into the platform

Run SpiderFoot as an internal collector service behind a narrow adapter. Maintain a pinned mirror/fork for reproducible builds, security patches, and the smallest necessary machine-interface changes. Do not add platform identity, canonical data, AI, reports, or the new graph UI to the SpiderFoot tree.

Reasons:

- Its modules and event ancestry are high-value and costly to recreate.
- MIT permits modification and commercial integration with notice preservation.
- Its SQLite and threaded scanner are appropriate collector internals but not a multi-tenant system of record or durable queue.
- Its optional Digest authentication and UI handlers are not a sufficient public service boundary.
- Adapter isolation makes upgrades, rollback, and eventual collector replacement tractable.

### Adapter contract

The adapter should expose only internal operations:

- enumerate version, modules, event types, and policy classification;
- start a scan with target, allowed modules, hard limits, and platform job ID;
- fetch status, events, errors, and correlations incrementally;
- cancel a scan;
- export a collector recovery artifact;
- report health/readiness.

Each imported event must record collector version, module, scan ID, source-event hash, event type, raw value, generated/retrieved times, and raw artifact hash. Adapter operations must be idempotent.

### Upstream synchronization

1. Configure `upstream` as `https://github.com/smicallef/spiderfoot.git`; reserve `origin` for the controlled mirror.
2. Pin production builds to an immutable commit and image digest.
3. Keep platform code out of the upstream subtree.
4. Put unavoidable changes into small, independently reviewable commits with tests and an `UPSTREAM_PATCHES.md` ledger.
5. On a schedule: fetch upstream, review changelog/diff/licenses, rebase or merge into an integration branch, run upstream plus adapter contract tests, scan dependencies/images, then promote.
6. Never auto-deploy upstream changes. Roll back by image digest.

## IntelOwl

### What it provides

IntelOwl describes itself as threat-intelligence management at scale with Django/Python REST APIs, analyzers for observables and files, a GUI, Docker deployment, and official Python/Go clients. Its documentation identifies API tokens as the server authentication mechanism.

Primary sources: [IntelOwl repository](https://github.com/intelowlproject/IntelOwl) and [official usage documentation](https://github.com/intelowlproject/docs/blob/main/docs/IntelOwl/usage.md).

### Recommendation: deploy independently and integrate by API

Do not fork or partially reimplement IntelOwl in the initial milestones. Run a pinned, internal-only instance and call it from an adapter using a least-privilege service token.

Reasons:

- It already aggregates analyzer execution behind one API.
- Service isolation contains its heavier analyzer dependencies and AGPL-licensed application.
- The platform can normalize outputs without coupling to IntelOwl database models.
- Independent deployment makes provider/analyzer enablement, scaling, and upgrade cadence explicit.
- Reimplementation would create security and maintenance cost without proving product differentiation.

Reconsider only if API latency, unavailable provenance, deployment footprint, license obligations, or missing controls fail documented acceptance tests. Any decision to distribute a modified IntelOwl build requires specialist AGPL review.

### Integration controls

- Allowlist analyzers by target type and authorization class.
- Disable malware detonation and other high-risk analyzers in the default passive profile.
- Enforce file size, type, privacy, egress, timeout, and quota limits before submission.
- Preserve IntelOwl job ID, analyzer name/version/config revision, timestamps, raw response hash, and errors.
- Do not expose the IntelOwl GUI/API publicly.

## Maltego concepts and boundaries

Maltego documentation describes entities, links, transforms, transform servers, settings, pagination, authentication, and graph-return patterns. These are general interoperability/workflow concepts. The target platform may independently implement:

- its own typed entities and relationships;
- provider adapters that transform an entity into additional evidence-backed entities;
- node expansion/collapse, layouts, filtering, timelines, confidence, provenance, and saved workspaces;
- import/export formats that are openly specified or independently documented;
- an optional connector built with an officially licensed SDK.

Primary sources: [Transforms SDK overview](https://docs.maltego.com/en/support/solutions/articles/15000062349-maltego-transforms-sdk-overview) and [Transforms documentation](https://docs.maltego.com/en/support/solutions/articles/15000015758-writing-transforms).

The platform must not:

- copy Maltego client/server source, decompile or reverse engineer proprietary components;
- reproduce proprietary icons, branding, visual trade dress, bundled transforms, entity artwork, or marketplace content;
- imply compatibility, endorsement, or origin without verification and permission;
- use SDK code outside its license or redistribute proprietary dependencies.

The graph must be designed from the platform's own requirements and implemented with independent libraries such as Cytoscape.js. “Transform” should be treated as an interoperability term only where necessary; internally use `provider adapter`, `enrichment`, and `expansion`.

## Acceptance tests before integration claims

- SpiderFoot: start/cancel/status/result import; event ancestry; module-policy enforcement; crash recovery; duplicate replay; version compatibility.
- IntelOwl: token auth; observable/file submission; analyzer allowlist; result pagination; partial failure; timeout/cancel; provenance; quota behavior.
- Maltego interoperability: only if selected, validate against official SDK documentation and license; keep it optional.

