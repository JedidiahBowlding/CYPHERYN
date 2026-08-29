# SignalTrace API and worker

The SignalTrace backend owns authentication, organizations, authorization scope, investigations, targets, provider policy, durable jobs, normalized evidence, entities, relationships, findings, monitoring, alerts, reports, and audit history.

## Runtime behavior

- FastAPI serves a versioned HTTP API and OpenAPI documentation.
- SQLAlchemy persists the canonical model in PostgreSQL.
- The API initializes and upgrades the current schema during startup.
- A separate worker claims queued jobs with expiring leases and heartbeats.
- Interrupted work can be recovered and retried within recorded policy.
- Provider credentials are encrypted with a Fernet key and are never returned in plaintext.
- Provider execution is controlled by enablement, authorization, quotas, deadlines, failure thresholds, circuit breakers, and an emergency kill switch.

## Advanced native development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
uvicorn intel_platform.main:app --reload --port 8000
```

Run the worker in a second terminal with the same configuration:

```bash
python -m intel_platform.worker
```

PowerShell activates the environment with `.venv\Scripts\Activate.ps1`. The recommended cross-platform workflow remains the root Docker Compose stack.

## Authentication

Production uses an OIDC issuer, audience, and JWKS endpoint. Development header identity is disabled by default in the package and cannot be enabled when `PLATFORM_ENVIRONMENT=production`.

## Providers

Built-in adapters cover passive discovery, threat intelligence, TAXII/STIX, identity, web posture, domain security, source code, supply chain, local verification, and authorized vulnerability scanning. Optional executables are detected at runtime rather than assumed to exist on every host.
