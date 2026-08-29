# SignalTrace application

This directory contains the SignalTrace product runtime.

| Path | Responsibility |
| --- | --- |
| `frontend/` | React/Vinext investigation console, evidence graph, findings, reports, settings, and monitoring UI |
| `api/` | FastAPI authorization, tenancy, evidence, provider policy, reporting, alerts, and durable worker |
| `taxii/` | Local TAXII 2.1 server, STIX collection, and trusted-feed updater |
| `greenbone/` | Optional local Greenbone/OpenVAS integration for authorized vulnerability scans |
| `tools/` | Optional locally installed collector tooling; generated environments are not portable artifacts |

SignalTrace uses PostgreSQL as its system of record. Collection requests are durable database jobs with leases, retries, deadlines, cancellation, heartbeats, recovery, evidence snapshots, and comparison. Provider credentials are organization-scoped and encrypted before persistence.

The supported cross-platform entry point is the root `compose.yaml` and `scripts/setup.py`. See the root README rather than starting individual services unless doing advanced development.

The Python import package remains `intel_platform` for schema and migration compatibility; the installed distribution, API title, Compose project, UI, reports, and public product identity are SignalTrace.
