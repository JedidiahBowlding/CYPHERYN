# Production drift inventory

Inventory captured 2026-08-31 UTC from `/opt/cypheryn` at base commit
`4528552474c47029f96034baa21da53bb12181dc`. No item was deleted or reset.

| Classification | Production paths | Disposition |
| --- | --- | --- |
| Application source | `platform/api/Dockerfile`, `platform/api/src/intel_platform/{docker_api_scanner,provider_safety,scanner_isolation,scanner_orchestrator,scanner_orchestrator_client,worker}.py`, provider adapters under `providers/` | Preserve and review as scanner/provider PR |
| Frontend/landing | `platform/frontend/app/**`, `DashboardNav.tsx`, `public/robots.txt`, `public/sitemap.xml` | Preserve and review as frontend/web PR |
| Reverse proxy | `deploy/production/Caddyfile` | Preserve and review with web/domain controls |
| Scanner configuration | `compose*.yaml`, `deploy/production/configure-scanner-egress.sh`, `cypheryn-scanner-egress.service`, `platform/scanners/**` | Preserve and review as scanner-runtime PR |
| OpenVAS/Greenbone | API OpenVAS adapter and Greenbone bridge/configuration represented in the synchronized engineering tree | Preserve and review as provider PR |
| Ollama | production environment/runtime override; repository template `deploy/production/ollama-override.conf` exists locally | Preserve configuration without committing secrets |
| Secrets/runtime state | `/etc/cypheryn/*`, database volumes, key/allowlist files | Never commit; inventory metadata only |
| Generated/runtime artifacts | `backups/**`, `testssl/**`, `zap-passive/**`, timestamped Caddy backup | Move out of Git worktree after verified backup; never commit |

Production remains unreproducible until the legitimate changes are reviewed, merged,
built from exact `main`, and redeployed with a signed/hashed deployment manifest.

## Exact deployment manifest

After deployment, create the manifest from the clean checkout and running Compose
project. The environment file is used only for Compose interpolation; its values
are never copied into the manifest.

```bash
sudo python3 scripts/deployment_manifest.py \
  --repository /opt/cypheryn \
  --output /var/lib/cypheryn/deployments/$(date -u +%Y%m%dT%H%M%SZ)-manifest.json \
  --operator newblockdev \
  --version 0.9.0 \
  --database-migration-state sqlalchemy-metadata-at-HEAD \
  --env-file /etc/cypheryn/production.env \
  --compose-file /opt/cypheryn/compose.yaml \
  --compose-file /opt/cypheryn/compose.production.yaml \
  --caddy-file /opt/cypheryn/deploy/production/Caddyfile
```

The command refuses a dirty Git tree and writes the manifest with mode `0600`.
Keep generated manifests outside the checkout, as shown above, so recording a
deployment cannot make the production Git tree dirty.
Record the database schema mechanism honestly: CYPHERYN currently initializes
SQLAlchemy metadata at startup and does not claim an Alembic revision.
