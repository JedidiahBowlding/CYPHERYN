# CYPHERYN troubleshooting

Start with:

```bash
python scripts/doctor.py
docker compose ps
docker compose logs --tail=200 api worker frontend postgres taxii
```

Use `py scripts/doctor.py` in Windows PowerShell.

## Docker is missing or stopped

Install/start Docker Desktop and confirm `docker version` and `docker compose version`. On Windows confirm `wsl --status`; use `wsl --install` in an elevated PowerShell if WSL2 is absent, then reboot if Windows requests it.

## Trusted scanner orchestrator is unavailable

The core platform works without active scanner containers. To enable them, first run
`python3 scripts/setup.py --check`, configure explicit images in `PLATFORM_SCANNER_IMAGES`, and
start `docker compose --profile scanner up -d --build`. Diagnose with
`docker compose --profile scanner ps` and
`docker compose --profile scanner logs scanner-orchestrator`. A missing token, unavailable Docker
socket, unsupported provider, unpinned image, excessive execution policy, or disabled profile fails
closed. Never solve this by mounting the Docker socket into `worker`.

## Port already in use

Change `FRONTEND_PORT`, `API_PORT`, `TAXII_PORT`, or `SPIDERFOOT_PORT` in `.env`, then run `docker compose up -d`. On macOS/WSL inspect with `lsof -nP -iTCP:3000`; on PowerShell use `Get-NetTCPConnection -LocalPort 3000`.

## Database fails or API repeatedly restarts

Run `docker compose logs postgres` and `docker compose logs api`. Confirm `.env` has non-placeholder `POSTGRES_PASSWORD` and `PLATFORM_PROVIDER_ENCRYPTION_KEY`. Do not change a database password after its volume has initialized unless you update PostgreSQL itself. Preserve data and use the backup procedure before any reset.

## Frontend cannot reach API

Open `http://localhost:8000/health/ready`. A healthy response is `{"status":"ready"}`. Rebuild the frontend after changing `API_PORT` because the browser API URL is embedded at build time: `docker compose up -d --build frontend`.

## TAXII unavailable

Run `docker compose logs taxii` and open `http://localhost:9000/health`. Confirm `TAXII_TOKEN` is present. The token is confidential and must not be pasted into reports or committed.

## Redis fails

CYPHERYN core does not use Redis. A Redis error belongs to the optional Greenbone stack; diagnose it from `platform/greenbone` with that stack's Compose logs.

## SpiderFoot unavailable

SpiderFoot is disabled by default and is not called by CYPHERYN. Start it only when needed with `docker compose --profile spiderfoot up -d spiderfoot`, then inspect `docker compose logs spiderfoot`.

## IntelOwl unavailable

IntelOwl is not implemented in this repository. There is no IntelOwl container or setting to repair.

## Provider key invalid

Open Settings, update the named provider, and use its connection test. Keys are not read from root `.env`. Check provider account permissions, quota, endpoint status, and clock accuracy. Never print the key while diagnosing it; rotate any exposed credential.

## Apple Silicon image error

Run `docker image inspect IMAGE --format '{{.Architecture}}'`. Core images are multi-architecture and must not need `platform: linux/amd64`. Optional legacy/Greenbone images may differ; update the image or use controlled amd64 emulation only for that optional service, with slower performance expected.

## WSL2 or Windows bind-mount slowness

The core stack uses named volumes. If doing native/advanced development with source bind mounts, cloning inside the WSL filesystem (for example `~/projects/cypheryn`) usually improves Linux-container file I/O. Keep Docker Desktop's WSL integration enabled for that distribution.

## Permissions or CRLF errors

Run shell scripts only in macOS Terminal or WSL. `.gitattributes` keeps shell scripts LF. Re-clone or run `git add --renormalize .` after introducing Git if existing files have incorrect line endings.

## Reset (destructive)

`python scripts/reset_dev.py` removes the local database, TAXII state, quarantine, and other Compose volumes after explicit confirmation. It cannot be undone without a backup.
