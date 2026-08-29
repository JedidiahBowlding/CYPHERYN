# Canonical Data Model

## Principles

- PostgreSQL is the system of record; SpiderFoot/IntelOwl stores are source systems only.
- Raw immutable evidence, normalized observations, entities, relationships, and analyst/AI claims are separate.
- Every derived record cites evidence.
- Tenant and investigation scope are explicit on every security-relevant row.
- Observations are append-oriented; current state is a query/materialized view, not destructive overwrite.
- Use UUIDv7/ULID-style sortable IDs, UTC timestamps, canonical JSON, and SHA-256 evidence hashes.

## Core model

```text
Organization 1--* Membership *--1 User
Organization 1--* Investigation 1--* Target
Investigation 1--* CollectionJob 1--* JobAttempt
CollectionJob 1--* Observation *--1 Evidence
Observation *--1 Entity
Entity 1--* Relationship *--1 Entity
Relationship *--* Evidence
Investigation 1--* Finding *--* Evidence
Investigation 1--* Claim *--* Evidence
Investigation 1--* Alert
Investigation 1--* Report
all sensitive actions -> AuditEvent
```

## Tables and required fields

### Identity, tenancy, and scope

- `organizations(id, name, status, retention_policy_id, created_at)`
- `users(id, external_subject, status, created_at)`
- `memberships(organization_id, user_id, role, created_at)`
- `investigations(id, organization_id, owner_id, name, description, status, sensitivity, created_at, updated_at)`
- `authorizations(id, organization_id, authorizer_id, basis, passive_allowed, active_allowed, valid_from, valid_until, revoked_at, evidence_id)`
- `targets(id, investigation_id, authorization_id, entity_type, raw_value, canonical_value, include_descendants, exclusions_json, status)`

### Jobs and integrations

- `integrations(id, organization_id, provider, credential_ref, policy_id, enabled, config_json)`; `credential_ref` is a secret-manager reference, never a secret.
- `collection_jobs(id, investigation_id, target_id, provider, profile, status, idempotency_key, limits_json, queued_at, started_at, ended_at, cancellation_requested_at)`
- `job_attempts(id, job_id, attempt, worker_id, lease_until, status, started_at, ended_at, error_code, error_summary, usage_json)`
- `provider_calls(id, attempt_id, provider, operation, request_fingerprint, started_at, ended_at, status, quota_units, response_evidence_id)`

Job status enum: `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`. Attempts have their own terminal states; a partial job must explain missing providers/limits.

### Evidence and observations

- `evidence(id, organization_id, investigation_id, provider, source_uri, retrieved_at, media_type, object_key, evidence_hash, size_bytes, collector, collector_version, raw_reference, retention_class, classification, created_at)`
- `observations(id, investigation_id, job_id, entity_id, evidence_id, observation_type, normalized_value_json, observed_at, collected_at, confidence, provider, source_event_ref, normalization_version)`

`evidence_hash` is over exact stored bytes. A separate canonical payload hash may support deduplication. Access and custody events are append-only.

### Entities

- `entities(id, organization_id, entity_type, canonical_key, display_value, attributes_json, first_observed_at, last_observed_at, created_at, updated_at)`
- `investigation_entities(investigation_id, entity_id, first_observation_id, last_observation_id, status, analyst_label)`
- `entity_aliases(id, entity_id, alias_type, canonical_alias, evidence_id, confidence)`
- `entity_resolution_decisions(id, investigation_id, left_entity_id, right_entity_id, decision, method, confidence, evidence_json, model_version, decided_by, decided_at)`

Initial `entity_type` values: `ORGANIZATION`, `DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `ASN`, `URL`, `DNS_RECORD`, `CERTIFICATE`, `REPOSITORY`, `USERNAME`, `EMAIL_ADDRESS`, `FILE_HASH`, `MALWARE_INDICATOR`, `THREAT_INDICATOR`, `SERVICE`, `TECHNOLOGY`, `FINDING`, `EVIDENCE`.

Canonical uniqueness is `(organization_id, entity_type, canonical_key)`. Cross-tenant global identity must not leak existence.

### Relationships

- `relationships(id, organization_id, investigation_id, subject_entity_id, predicate, object_entity_id, claim_class, first_observed_at, last_observed_at, collected_at, confidence, derivation_method, derivation_version, status)`
- `relationship_evidence(relationship_id, evidence_id, observation_id, support_role)`

Initial predicates: `OWNS`, `RESOLVES_TO`, `HOSTED_ON`, `USES_CERTIFICATE`, `ASSOCIATED_WITH`, `OBSERVED_AT`, `REFERENCED_BY`, `REPORTED_BY`, `RELATED_TO`, `EXPOSES_SERVICE`, `USES_TECHNOLOGY`.

`claim_class` is one of `OBSERVED_FACT`, `DERIVED_RELATIONSHIP`, `AI_ASSESSMENT`. `ASSOCIATED_WITH` and `RELATED_TO` require a documented derivation method and must not be presented as ownership.

### Findings, claims, and risk

- `findings(id, investigation_id, title, category, severity, status, affected_entity_id, claim_class, confidence, first_seen_at, last_seen_at, remediation, created_by, created_at)`
- `finding_evidence(finding_id, evidence_id, observation_id, support_role)`
- `claims(id, investigation_id, claim_class, statement, confidence, uncertainty, method, model_run_id, status, created_by, created_at)`
- `claim_evidence(claim_id, evidence_id, observation_id, citation_label)`
- `risk_assessments(id, investigation_id, entity_id, finding_id, score, level, factors_json, method_version, assessed_at)`

AI claims cannot be promoted to observed fact. Analyst validation creates a new decision/audit event; it does not rewrite provenance.

### Monitoring and reports

- `asset_registrations(id, organization_id, entity_id, authorization_id, monitoring_profile, cadence, enabled)`
- `snapshots(id, registration_id, effective_at, completed_job_id, manifest_hash)`
- `changes(id, registration_id, prior_snapshot_id, current_snapshot_id, change_type, entity_id, relationship_id, significance, evidence_json)`
- `alerts(id, organization_id, investigation_id, change_id, finding_id, severity, status, dedupe_key, opened_at, acknowledged_at, closed_at)`
- `reports(id, investigation_id, format, template_version, status, object_key, manifest_hash, generated_by, generated_at)`
- `model_runs(id, investigation_id, purpose, provider, model, prompt_policy_version, retrieval_manifest_hash, input_tokens, output_tokens, status, created_at)`
- `audit_events(id, organization_id, actor_type, actor_id, action, object_type, object_id, decision, reason_code, request_id, source_ip, occurred_at, details_json, previous_hash, event_hash)`

## Normalization examples

- Domains/subdomains: lowercase U-label/A-label policy, remove terminal dot, validate public-suffix semantics, preserve input alias.
- IPs: canonical textual IPv4/IPv6; never merge private and public observations by display string alone.
- URLs: normalize scheme/host/default port and percent encoding conservatively; retain exact raw URL as evidence.
- Email: domain canonicalization; local part preserved unless provider-specific rules are explicitly enabled.
- ASN: unsigned integer canonical key such as `AS13335`.
- Certificates: SHA-256 fingerprint canonical key; store parsed fields as attributes backed by raw certificate evidence.
- File hashes: `(algorithm, lowercase digest)` with length validation.

## Deduplication and temporal semantics

Entity deduplication is deterministic by canonical key. Observation deduplication uses `(investigation, provider, evidence_hash, observation_type, normalized payload hash)` while preserving repeat sightings through an occurrence/count table if needed. Relationships deduplicate by typed endpoints, predicate, investigation, and derivation method; evidence links accumulate. `first_observed_at` and `last_observed_at` refer to source observation time; `collected_at` is acquisition time.

## Graph strategy and indexes

Store adjacency rows in `relationships`. Add indexes on `(investigation_id, subject_entity_id, predicate)`, `(investigation_id, object_entity_id, predicate)`, entity canonical uniqueness, observation time, evidence hash, job status/lease, alert dedupe key, and JSON fields only when query evidence justifies them. Use recursive CTEs with explicit depth and row caps. Benchmark p50/p95 for one-hop expansion, bounded 2–4 hop traversal, neighborhood filters, and timeline queries before considering another database.

## Data invariants

1. No observation without evidence and job/provenance.
2. No relationship/finding/claim without supporting evidence.
3. Organization and investigation IDs on referenced rows must match.
4. Evidence bytes must match `evidence_hash` at ingest and read verification.
5. Secrets never enter these tables.
6. Deletion/retention is policy-driven and produces audit events; legal holds override normal expiry.

