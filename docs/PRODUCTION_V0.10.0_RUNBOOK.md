# CYPHERYN v0.10.0 production runbook

This runbook is an operator checklist. It does not authorize deployment. The
trusted-egress and pilot profiles remain off until every preflight gate passes
and an authorized operator approves the canary.

## Required evidence

- Release tag resolves to the reviewed commit.
- Every `CYPHERYN_*_IMAGE` value is a GHCR `@sha256:` reference from the release's
  `image-digests.txt`.
- GitHub build-provenance attestations, SPDX SBOMs and High/Critical Trivy gates
  pass for all seven shipped images.
- Production PKI, monitoring and rollback owners have signed the change record.

## Backup and restore gate

On the production host, create a custom-format dump to a root-owned directory:

```bash
sudo install -d -m 0700 /var/lib/cypheryn/backups
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo sh -c "docker exec cypheryn-postgres-1 pg_dump \
  --username cypheryn --dbname cypheryn --format custom \
  > '/var/lib/cypheryn/backups/${stamp}-pre-v0.10.0.dump'"
sudo chmod 0600 "/var/lib/cypheryn/backups/${stamp}-pre-v0.10.0.dump"
sudo sha256sum "/var/lib/cypheryn/backups/${stamp}-pre-v0.10.0.dump"
sudo docker run --rm \
  -v /var/lib/cypheryn/backups:/backups:ro postgres:17-alpine \
  pg_restore --list "/backups/${stamp}-pre-v0.10.0.dump" >/dev/null
```

Copy the encrypted backup off-host and restore it into an isolated PostgreSQL 17
instance. Record the restore command, row counts and integrity-check result in
the deployment evidence. A readable dump without a successful restore test does
not satisfy the gate.

## Migration gate

Confirm the legacy `20260930_agent_egress_firewall.sql` objects first. Run the
release API image through Compose so the migration uses the same immutable image
that will serve production. Keep PostgreSQL running, but do not start upgraded
application services yet:

```bash
cd /opt/cypheryn
sudo docker compose --env-file /etc/cypheryn/production.env \
  -f compose.yaml -f compose.production.yaml \
  run --rm --no-deps api alembic stamp 20260930_egress_baseline
sudo sh -c 'docker compose --env-file /etc/cypheryn/production.env \
  -f compose.yaml -f compose.production.yaml \
  run --rm --no-deps api alembic upgrade head --sql \
  > /root/cypheryn-v0.10.0-upgrade.sql'
sudo less /root/cypheryn-v0.10.0-upgrade.sql
sudo docker compose --env-file /etc/cypheryn/production.env \
  -f compose.yaml -f compose.production.yaml \
  run --rm --no-deps api alembic upgrade head
sudo docker compose --env-file /etc/cypheryn/production.env \
  -f compose.yaml -f compose.production.yaml \
  run --rm --no-deps api alembic current
```

The expected head is `20261006_egress_proxy_receipts`. Review the offline SQL
before the online upgrade. The baseline stamp is only valid after an operator
has verified that all baseline objects already exist; stamping an incomplete
database would hide a broken schema. Never use the destructive downgrade as an
emergency application rollback.

## PKI gate

Provision a control-plane server certificate, proxy-client CA, a unique client
certificate for each proxy replica and overlap trust bundles for rotation. Keys
must be outside Git and normal database records, read-only in containers, and
`0600` or narrowly group-readable `0640`. Verify SAN, EKU, chain, expiration and
rejection of an untrusted or retired client. Configure expiry monitoring before
starting the profile.

## Deployment order

1. Verify backup/restore evidence and immutable image digests.
2. Apply the additive migrations and verify the exact head.
3. Deploy core v0.10.0 services with protected profiles off and `--no-build`.
4. Verify API, worker, frontend, TAXII, scanner and authentication health.
5. Start `trusted-egress`; Compose targets three proxy replicas.
6. Verify all replicas, mTLS, metrics and invalid-client rejection.
7. Verify the protected network is internal/default-deny.
8. Run the IPv4, IPv6, DNS, HTTPS, RFC1918, metadata and alternate-port bypass matrix.
9. Start only the read-only `trusted-egress-pilot` canary.
10. Execute one approved request, verify its receipt, and observe the canary.

Use `docker compose -f compose.yaml -f compose.production.yaml --no-build ...` so
production cannot silently build a different local image.

## Monitoring gate

Load `deploy/monitoring/cypheryn-protected-agent.rules.yml` into the production
Prometheus-compatible collector. Scrape every proxy replica separately. Connect
the certificate-expiry probe and network-policy sensor before treating their
alerts as active. Route critical notifications to the on-call operator and test
one synthetic alert before canary enablement.

## Rollback

1. Stop new protected operations.
2. Remove the pilot while retaining the internal/default-deny network.
3. Disable the trusted-egress profiles if necessary.
4. Roll core services back to their previous immutable digests.
5. Retain the additive schema, decisions, receipts and audit evidence.
6. Verify existing CYPHERYN health before closing the incident.

Never give the protected workload direct internet access as a fallback.
