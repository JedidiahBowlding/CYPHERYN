# Agent Egress Firewall repository audit

Date: 2026-09-30
Branch: `feature/agent-egress-firewall`

## Existing architecture

- The API is FastAPI with SQLAlchemy and PostgreSQL. Development tests use SQLite.
- The UI is React 19 through Vinext/Next-compatible app routes.
- Authentication uses OIDC bearer tokens in production and an explicitly enabled local development identity. Organization membership supplies RBAC.
- The normal worker has no Docker socket. Active scanners go through the separately trusted scanner orchestrator, which creates disposable, restricted containers.
- Collection jobs, worker heartbeats, provider runtime state, findings, evidence sources, audit events, notifications, and report artifacts already exist.
- Audit events and evidence sources use SHA-256 chains, PostgreSQL transaction locks, and optional externally signed Ed25519 checkpoints.
- Provider readiness is represented separately from provider support; successful collection is required for live verification.
- Core Compose binds the API and frontend to loopback. Production routes are protected by Auth0/oauth2-proxy and Caddy.
- Tests use pytest, Ruff, TypeScript, ESLint, rendered-route tests, Compose health checks, dependency audits, image scanning, secret scanning, and SBOM generation.

## Reused components

| Requirement | Existing component reused |
| --- | --- |
| Identity and RBAC | `auth.py`, `User`, `Membership`, `MembershipRole` |
| Tamper-evident operations | `AuditEvent`, `record_audit`, integrity-chain transaction locking |
| Findings | Existing finding conventions; isolated `EgressFinding` avoids fabricating an investigation |
| Metrics and safe logging | `observability.py`, `structured_log`, Prometheus endpoint |
| Local/private network posture | Core Compose loopback binding and production OIDC gateway |
| Scanner lifecycle | Existing Supported → Installed → Configured → Healthy → Live Verified vocabulary |
| Quarantine storage | Existing `/data/quarantine` named volume |

## Gaps requiring egress-specific records

The repository had no protected-agent identity, exact outbound-action record, versioned egress policy, artifact classification record, or single-use action approval. These are not duplicates of collection authorizations: collection authorization proves permission to test a target, while egress approval permits one exact outbound publication action.

The current repository does not use Alembic. Startup calls `Base.metadata.create_all` and an additive compatibility upgrader for legacy columns. New egress tables therefore use declarative metadata and are created without modifying legacy tables. Adopting Alembic remains recommended before multi-node production schema changes.

## Implementation plan and file map

1. Add egress tables and enums in `platform/api/src/intel_platform/models.py`; preserve all legacy tables.
2. Add deterministic scanning, normalization, policy evaluation, and event sealing in `egress.py`.
3. Add a bounded GitHub command parser in `github_mediation.py`; it parses but never executes.
4. Add authenticated organization routes, approval separation, evidence export, and execution verification in `egress_api.py` and register its router in `main.py`.
5. Extend privacy-safe metrics in `observability.py` and settings in `config.py`/`.env.example`.
6. Install the local OCR dependency in the existing API image; retain read-only root and quarantine volume boundaries.
7. Add `/egress` to the existing dashboard and production route map.
8. Verify policy, scanning, approval, replay, mismatch, and integrity behavior in `test_egress_firewall.py`; run the complete API and frontend gates.
9. Supply a synthetic demonstration and explicit operations, incident, limitation, and rollback documentation.

## Deployment finding

The MVP is implemented inside the authenticated CYPHERYN API rather than as a public microservice. This preserves the existing identity and audit boundary. Core Compose publishes the API only on `127.0.0.1`; production exposure is behind the authenticated gateway. A separately deployable guard process is a future hardening option, not a current claim.

## Constraints and non-claims

- GitHub mediation currently parses and evaluates a bounded `gh`/`git` subset. It does not transparently intercept every process on the host.
- The API never executes GitHub commands. The caller must evaluate, execute only an allowed action, then submit observed state for verification.
- Built-in pattern scanning is operational. Tesseract is installed in the API image, but it is reported as operational only after an image scan succeeds.
- PDF and unknown binary parsing fail closed into quarantine; hardened PDF parsing is planned.
- GitHub discovery and automatic containment are planned. No destructive repository action is implemented.
