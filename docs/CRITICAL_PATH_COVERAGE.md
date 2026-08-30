# Critical-Path Coverage Milestone

This `v0.9.0` milestone increases verification depth without expanding CYPHERYN's provider catalog or feature surface.

## Measured improvement

| Owned module | Previous | Current | Enforced gate |
| --- | ---: | ---: | ---: |
| Worker orchestration | 46% | 61.7% | 60% |
| Detection engine | 15% | 70.3% | 70% |
| Normalization | 21% | 94.4% | 90% |
| Report exports | 21% | 93.8% | 90% |
| Notifications | 30% | 83.2% | 80% |
| Malware analysis | 28% | 91.5% | 90% |
| Entire owned API | 56.4% | 62.5% | 60% |

Percentages come from deterministic Linux container execution with Python 3.13. They are enforced from coverage JSON in the macOS, Linux, and Windows CI matrix. Gates deliberately sit below the observed value to tolerate harmless interpreter/platform branch differences while still preventing meaningful regression.

## Behavior now proven

- Worker lease expiry transitions to cancellation, terminal failure, or safe retry according to durable state.
- Job claiming updates lease owner, heartbeat, attempt, and status atomically; a second worker cannot claim the same queued record.
- Safe mock execution remains idempotent at the entity/relationship layer.
- Findings open, enter verification, resolve only after two clean observations, and reopen when evidence returns.
- Direct verification distinguishes responded, refused, fixed-pending-confirmation, fixed, stale, and inconclusive states.
- Evidence comparison ignores volatile timestamps but records substantive redacted changes.
- Sigma and JSON-lines parsing reject malformed input; Suricata/Zeek ingestion normalizes severity, time, endpoints, and entity correlation.
- Every supported target class exercises valid and unsafe canonicalization boundaries, including public networks, explicit container tags, repository scope, and bounded SBOM files.
- JSON, CSV, timeline, and STIX exports preserve integrity metadata, deterministic manifest hashes, lifecycle records, relationships, and CSV quoting.
- Notification tests cover SSRF-resistant webhook validation, maintenance/quiet suppression, deduplication, transport success/failure, TLS, redirect refusal, and bounded delivery errors.
- Malware tests cover private quarantine permissions, MD5/SHA-1/SHA-256 calculation, absent scanners, infection signatures, YARA matches, scanner timeout, and non-revoked STIX hash correlation.

## Defect discovered

The new report tests found that timeline evidence records included `integrity_hash`, while `timeline_csv()` rejected any field outside its older schema. The exporter now includes the integrity hash column, and the behavior is permanently regression-tested.

## Remaining coverage risk

Worker orchestration is materially improved but remains below the long-term 75% target. The largest remaining branches are schedule/monitor enqueueing, full provider execution outcomes inside `process_one`, monitoring-summary regeneration, and scheduled report generation. These need database-failure, partial-result, retry/backoff, duplicate-execution, and report-generation tests in the next focused increment.

Coverage remains a proxy, not proof of correctness. Thresholds apply alongside behavior assertions, Ruff, type checking, dependency audits, container scans, and hosted cross-platform execution.
