# SignalTrace Operations and Observability

SignalTrace separates API readiness from worker readiness. `/health/ready` proves the API can reach its database. `/health/workers` reports whether at least one persisted worker heartbeat is newer than 45 seconds and includes safe queue state. An API may therefore be ready while collection is degraded because all workers are stale.

## Metrics

`GET /metrics` emits Prometheus-compatible text without requiring Prometheus to run locally. It includes worker health, queued/running/failed/cancelled jobs, retries, expired leases, oldest queued-job age, evidence count, and per-provider request/success/failure/timeout totals. The authenticated platform-assurance response includes provider readiness, circuit state, last successful collection, certification tier, and verification freshness.

Metrics contain provider names and operational counts, not credentials, raw evidence, targets, or secret settings. Operators should still treat investigation and organization labels as sensitive if adding them to external telemetry.

## Correlation and logs

Every HTTP request accepts or creates a bounded `X-Correlation-ID`, returns it in the response, and emits structured JSON with timestamp, service, severity, event type, path, status, and duration. Invalid correlation values are replaced. Structured logging rejects fields whose names indicate credentials, passwords, secrets, tokens, API keys, or raw payloads.

Job IDs remain the durable correlation handle from queue event through provider execution and evidence. External log collectors should index both correlation ID and job ID without ingesting raw provider payloads.

## Recommended alerts

| Condition | Starting threshold | Response |
| --- | --- | --- |
| Worker heartbeat stale | 45 seconds | Inspect worker logs, database connectivity, and restart policy. |
| Oldest queued job excessive | Longer than two normal collection deadlines | Check worker health, leases, quotas, and provider timeouts. |
| Provider failures spike | Five consecutive failures or circuit open | Validate credentials/quota/provider status; do not bypass the circuit. |
| Repeated scanner timeout | Three for the same scanner/target policy | Inspect limits and scanner image; do not broaden target scope. |
| Expired lease | Any recurring value | Look for worker crashes, database stalls, or duplicate execution. |
| Evidence-chain failure | Any | Stop affected exports, preserve state, and verify against the latest external anchor. |
| Notification failure | Retry exhaustion | Check SMTP/webhook reachability and secret configuration. |

These are operational starting points, not universal SLOs. Tune them from measured queue and provider behavior.

## Commands

```bash
curl http://localhost:8000/health/ready
curl http://localhost:8000/health/workers
curl http://localhost:8000/metrics
docker compose logs -f worker api
```

If the API is ready but the worker is degraded, inspect `docker compose ps worker`, worker logs, PostgreSQL health, stale leases, and memory pressure. Never paste complete logs into public issues until they have been checked for private targets or evidence.
