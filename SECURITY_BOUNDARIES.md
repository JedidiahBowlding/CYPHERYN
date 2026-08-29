# Security Boundaries

## Non-negotiable boundaries

1. **The public frontend never calls SpiderFoot, IntelOwl, databases, brokers, or model providers directly.**
2. **Only the platform API makes authorization decisions.** Workers revalidate signed job claims; collectors cannot broaden them.
3. **SpiderFoot and IntelOwl are untrusted internal processors.** They receive minimum targets/configuration and have no tenant credentials or direct canonical-database access.
4. **Passive is the default.** Active-capable collection is a separate profile, approval, queue, worker identity, network segment, and audit event.
5. **AI is not an authority.** It can read retrieved evidence and create typed assessments; it cannot expand scope, invoke active scans, alter facts, dismiss alerts, or export externally.
6. **Evidence is immutable; interpretation is versioned.** Facts, derivations, and AI assessments remain distinguishable in storage, API, UI, and reports.

## Network boundary matrix

| Component | Inbound from | Outbound to | Public? |
|---|---|---|---|
| Reverse proxy/WAF | Internet | platform API/frontend | Yes, TLS only |
| Frontend static service | proxy | none/API through proxy | Through proxy |
| Platform API | proxy, trusted ops | PostgreSQL, broker, object store, identity provider | No direct public port |
| Worker | broker/control plane | adapters, PostgreSQL, object store, approved providers | No |
| SpiderFoot | SpiderFoot adapter only | policy-approved Internet via egress proxy; local DB | No |
| IntelOwl | IntelOwl adapter only | approved analyzers/providers via egress controls | No |
| AI gateway | platform API/worker | approved model endpoint, evidence retrieval service | No |
| PostgreSQL/Redis/object store | authorized service identities | backup/telemetry endpoints only | No |

Default-deny network policy applies. Production Compose/Kubernetes must not publish ports for internal services. DNS and HTTP egress is logged and allow/deny controlled; private, link-local, loopback, metadata, and cluster ranges are blocked from collectors unless an explicit internal assessment is authorized in a separate environment.

## Identity and authorization boundaries

- Humans authenticate through OIDC with MFA policy; sessions use secure, HTTP-only, same-site cookies or bounded tokens.
- Services use workload identities and short-lived credentials, not shared API keys in images/environment dumps.
- Every query/mutation binds organization from the authenticated subject, never a trusted client header/body.
- PostgreSQL row-level security is defense in depth, not a substitute for API authorization.
- Job messages carry opaque IDs and signed authorization context, not secrets or bulk evidence.
- Scope is canonical typed data with exclusions and expiry. Workers recheck revocation immediately before dispatch.

## Collection profiles

### Passive profile (default)

Only approved third-party/public-data queries that do not intentionally interact with target services beyond ordinary safe resolution/retrieval. Each SpiderFoot/IntelOwl module is deny-by-default until classified.

### Active profile

Includes port/service scanning, zone-transfer attempts, bucket enumeration/listing, external scanning tools, intrusive requests, or any function whose behavior may affect or directly test a target. It requires active authorization, named approver, method allowlist, window, rate/depth limits, separate queue/worker/egress, and prominent UI/report labeling.

No profile permits exploitation, credential attacks/theft, malware deployment, persistence, destructive actions, or unauthorized account access.

## Data boundaries

- PostgreSQL holds canonical metadata; object storage holds exact raw artifacts and reports.
- Envelope encryption uses per-environment/customer keys as policy requires; keys remain in KMS/HSM.
- Secret manager references are stored, never plaintext provider credentials.
- Evidence access is investigation-scoped and audited. Signed URLs are short-lived, single-purpose, and content-disposition constrained.
- Raw HTML/files are never executed inline. Render/sanitize or force download from a separate origin.
- Backups are encrypted, access-controlled, restoration-tested, and included in retention/deletion workflows.

## Provider and AI boundaries

Provider adapters expose a common contract but retain provider-specific terms, rate, cost, confidence, and error semantics. Credentials are injected only at call time. Raw responses are schema/size validated before storage.

The AI gateway receives a bounded retrieval manifest, never database credentials or unrestricted search. Model-provider calls follow approved data-region/retention policy. Prompt content is redacted and logged by hash/metadata rather than full sensitive text unless a restricted debugging approval exists.

## API boundary requirements

- versioned OpenAPI, strict schemas, size/time limits, pagination, idempotency keys;
- CSRF protection where cookies are used, restrictive CORS, CSP/security headers;
- per-user/organization/IP/provider rate and cost limits;
- opaque identifiers do not replace authorization;
- consistent safe errors; no provider secret/raw stack disclosure;
- export and report generation are separately authorized and audited.

## Audit boundary

Audit records capture actor/service, organization, action, object, authorization decision/reason, target scope reference, request/job ID, timestamp, outcome, and high-level changes. They are append-only/tamper-evident, sent to a separately administered sink, and exclude secrets. Read access to audit is itself audited.

## Deployment gates

- internal-service port exposure test;
- default-deny egress and module classification test;
- cross-tenant/IDOR test suite;
- secret and sensitive-log scanning;
- signed image/SBOM/pinned digest enforcement;
- backup/restore and revocation/cancellation drills;
- prompt-injection/citation-verification evaluation;
- legal approval for providers, IntelOwl, and optional Maltego interoperability.

