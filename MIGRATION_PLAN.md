# Migration Plan

## Goal

Transition from the current standalone SpiderFoot checkout to a standalone platform that consumes SpiderFoot without losing scan history, provenance, licenses, or upstream update capability.

## Repository migration

Preferred layout in a new platform repository:

```text
platform/
  api/
  worker/
  frontend/
  adapters/spiderfoot/
  adapters/intelowl/
  deploy/
  docs/
upstream/
  spiderfoot/   # pinned submodule, subtree, or separately built source
```

Do not bulk-rewrite this upstream history. Create a controlled mirror, add an `upstream` remote, pin builds to commit/image digest, and record local patches. If organizational constraints keep one repository, use a clearly bounded `upstream/spiderfoot` subtree and CODEOWNERS rules.

## Data migration phases

### Phase A — Preserve and inventory

- stop or snapshot writes for a migration rehearsal;
- copy each `spiderfoot.db` and evidence/cache directory to immutable storage;
- record SHA-256, size, schema version, SpiderFoot commit, scan counts, and timestamps;
- export JSON/GEXF only as secondary validation artifacts; SQLite remains the highest-fidelity source;
- never import provider credentials from `tbl_config` into application tables.

### Phase B — Extract

Read scan instances, configurations, results, logs, correlations, and correlation-event links with a versioned migration tool. Each source row gets a stable `legacy_source_ref` containing database manifest ID, table, scan GUID, and row/hash identity.

### Phase C — Normalize

- create organization/investigation mappings explicitly;
- map one legacy scan to one collection job plus attempt;
- store exact source values as evidence before normalization;
- map event types through a reviewed catalog to entities, observations, relationships, or quarantined unknowns;
- map module and source-event hash into provenance;
- map correlations to `DERIVED_RELATIONSHIP`/finding claims backed by their event evidence;
- do not infer missing ownership or authorization retroactively. Mark authorization provenance as `LEGACY_UNVERIFIED` and restrict active reuse.

### Phase D — Validate

For each scan compare:

- scan/job status and timestamps;
- source result count, imported observation count, quarantined/skipped count;
- event-type/module distribution;
- correlation and supporting-event counts;
- deterministic entity/relationship counts;
- random samples back to exact source rows and evidence hashes.

Generate a signed reconciliation report. No silent drops are allowed; every source row is imported, intentionally excluded with reason, or quarantined.

### Phase E — Cut over

- deploy platform read-only views of migrated investigations;
- run a canary new scan through the adapter;
- allow a temporary dual-read comparison, not uncontrolled dual-write;
- route all new jobs through the platform;
- keep legacy SpiderFoot UI internal/read-only for a defined rollback window;
- archive legacy databases under retention policy after acceptance.

## Mapping outline

| SpiderFoot source | Platform target |
|---|---|
| `tbl_scan_instance` | investigation import record + collection job/attempt |
| `tbl_scan_config` | redacted job configuration snapshot; secret values excluded |
| `tbl_scan_results` | immutable evidence + observation + entity/relationship mapping |
| result `module` | collector/provider provenance |
| `source_event_hash` | observation ancestry / supporting evidence reference |
| confidence/risk/generated | observation fields and legacy risk input |
| correlation tables | derived claim/finding + evidence join |
| `tbl_scan_log` | restricted migration/job diagnostic artifact, redacted |

## Unknown and sensitive data policy

Unknown event types enter `ingest_quarantine` with raw evidence, mapping status, and review reason. Raw data and logs must be scanned/redacted for credentials and sensitive content before broad access. Legacy secrets are rotated, not migrated. Access to legacy evidence is least-privilege and audited.

## Rollback

- Repository: redeploy the prior pinned SpiderFoot image/checkout.
- Data: migration is additive; source SQLite snapshots remain immutable. Disable platform reads for affected imports and delete/rebuild only platform-owned import partitions through an audited migration operation.
- Cutover: return routing to the internal legacy UI for authorized users while preserving new-platform jobs; do not reverse-write new canonical records into SQLite.

Rollback triggers include reconciliation mismatch, provenance loss, cross-tenant exposure, invalid authorization mapping, material performance regression, or inability to cancel/bound collector jobs.

## Completion criteria

- 100% source rows reconciled as imported/excluded/quarantined;
- evidence hashes and sampled lineage verified;
- no credentials migrated into PostgreSQL/logs;
- canary collection, cancellation, replay, and report provenance pass;
- rollback rehearsal completed;
- data owner and security sign the reconciliation report.

