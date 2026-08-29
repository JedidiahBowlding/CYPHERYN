# Threat Model

**Method:** STRIDE-informed, evidence/data-flow centered  
**Scope:** Proposed platform and isolated SpiderFoot/IntelOwl services

## Security objectives

1. Only authorized users may investigate explicitly authorized scope.
2. Passive collection cannot silently become active testing or exploitation.
3. Intelligence is tenant-isolated and traceable to immutable evidence.
4. AI cannot convert unsupported inference into fact or gain collection authority.
5. Credentials, sensitive evidence, and personal data are protected throughout their lifecycle.
6. Jobs are bounded, rate-limited, cancellable, replay-safe, and auditable.

## Assets

- target authorization records and scope constraints;
- investigation/evidence data, analyst notes, reports, exports, and audit history;
- provider/API/model credentials and signing/encryption keys;
- canonical entities, relationships, findings, risk scores, and AI assessments;
- worker, collector, analyzer, database, object-store, and CI identities;
- software supply chain, images, dependencies, and policy configuration.

## Trust boundaries

```text
Untrusted browser/Internet
  | B1: WAF + OIDC + API authorization
Platform API / tenant data
  | B2: job broker + workload identity
Workers
  | B3: collector adapter policy
SpiderFoot / IntelOwl sandboxes
  | B4: controlled egress
External providers and target Internet

AI model provider is a separate B5 boundary reached only through the AI gateway.
Object storage and PostgreSQL are B6 protected data boundaries.
```

## Principal threats and controls

| Threat | Example | Required controls |
|---|---|---|
| Unauthorized target collection | User scans a third-party target | verified scope record; per-target authorization; policy engine; approval for active profiles; immutable audit |
| Privilege/tenant escalation | IDOR on investigation/entity/report IDs | server-side tenant predicates; object ownership; RBAC/ABAC; negative authorization tests; no client-supplied tenant trust |
| Passive-to-active escalation | Module triggers port scan, zone transfer, bucket listing, or external tool | classify every module; passive allowlist default; separate active worker pool/egress; explicit approval and expiry |
| Recursive explosion | Newly found entities trigger unbounded scans | depth/entity/time/request/cost limits; no automatic cross-scope expansion; dedupe; circuit breakers |
| SSRF and unsafe target parsing | Crafted URL reaches metadata/internal network | canonical target validation; DNS/IP revalidation; block private/link-local/metadata ranges unless explicitly authorized; egress proxy |
| Analyzer/file compromise | Malicious evidence exploits parser or sandbox | isolated non-root containers; no host mounts; seccomp/AppArmor; resource limits; malware-safe object storage; content handling policy |
| Provider compromise/data poisoning | External API returns false/malicious data | preserve raw evidence; source reputation; schema validation; confidence calibration; multi-source corroboration; never render raw HTML |
| Prompt injection | Evidence tells model to ignore policy or expose secrets | treat evidence as untrusted data; fixed system policy; tool allowlists; no collector credentials/model tools; structured cited outputs |
| AI hallucination | Unsupported relationship reported as fact | retrieval by authorized evidence IDs; claim schema; citation verifier; abstention; uncertainty; human approval for consequential reports |
| Secret leakage | Keys in logs, prompts, job payloads, exports | secret manager; short-lived injection; redaction; no secrets in broker/DB/logs; egress controls; rotation and scanning |
| Evidence tampering | Analyst/provider modifies raw source | content hash; immutable/versioned objects; append-only audit; signed report manifest; custody events |
| Replay/duplicate jobs | At-least-once delivery creates inconsistent facts | idempotency keys; unique constraints; observation upserts; leases; attempt records; deterministic normalization |
| Denial of service/cost abuse | Huge scans or model/provider spend | quotas; concurrency and rate limits; hard budgets; timeouts; queue priorities; backpressure; circuit breakers |
| Data exfiltration | Cross-tenant export or model prompt | scoped queries; export authorization; watermark/manifest; DLP; model data policy; regional routing; audit alerts |
| Supply-chain compromise | Malicious module/dependency/image | pinned hashes/digests; SBOM; signed builds; code review; SAST/SCA; isolated builds; staged upstream promotion |
| Audit repudiation | Operator denies scan/export | append-only actor/time/request/decision records; clock sync; protected signing/retention |

## Authorization model

Roles alone are insufficient. Every sensitive action requires:

`subject role` + `tenant membership` + `object ownership/access` + `authorized target scope` + `collection profile` + `provider policy` + `time validity`.

Suggested roles: organization admin, investigation lead, analyst, viewer, integration admin, compliance auditor, platform operator. Platform operators do not automatically receive evidence access.

An authorization record stores authorizer, legal/contract basis, target patterns and exclusions, passive/active permission, methods, start/end time, jurisdiction, evidence attachment, and revocation status. Scope matching must use canonical domain/IP/ASN/URL semantics; substring matching is forbidden.

## AI-specific invariants

- The model receives only evidence authorized for the current subject/investigation.
- Retrieved chunks include evidence IDs, provider, observation time, confidence, and content hash.
- Model output conforms to a schema with claim type, evidence IDs, confidence, uncertainty, and recommended action.
- A deterministic verifier rejects missing, cross-investigation, or semantically invalid citations.
- AI assessments never mutate observed facts; they are versioned claims.
- No autonomous active scan, alert dismissal, scope expansion, or external communication.

## Logging and privacy

Log identifiers and outcomes, not secrets or unnecessary raw evidence. Apply field allowlists, structured redaction, access-controlled debug mode, and short retention for high-volume technical logs. Evidence retention/deletion must account for legal hold, provider terms, subject requests, backups, and derived indexes.

## Verification plan

- abuse-case and negative authorization tests for every endpoint/job;
- module classification review and runtime egress tests;
- SSRF, parser sandbox, dependency, container, and API penetration tests;
- prompt-injection corpus plus citation-grounding/abstention evals;
- tenant-isolation tests at API and database layers;
- restore, key rotation, audit integrity, cancellation, and incident-response exercises.

## Residual risk

OSINT can be wrong, stale, invasive, or legally restricted; confidence controls do not eliminate that risk. External providers and model services remain supply-chain/data-processors. Active collectors have dual-use risk even when gated. Production certification therefore requires legal, privacy, security, and operational review beyond automated testing.

