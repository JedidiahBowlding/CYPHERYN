# SignalTrace development

The supported default is Docker Compose from the repository root. It keeps PostgreSQL and Linux-only dependencies out of the host environment.

## Docker workflow

```bash
python3 scripts/setup.py --start
docker compose ps
python3 scripts/doctor.py
```

On Windows PowerShell use `py scripts/setup.py --start` and `py scripts/doctor.py`. Edit code, then rebuild the affected service with `docker compose up -d --build api worker` or `docker compose up -d --build frontend`.

Run API tests in the built image:

```bash
docker compose run --rm --no-deps api pytest
```

Run frontend tests:

```bash
docker compose run --rm --no-deps frontend npm test
```

## Advanced native API

Requires Python 3.12+ and a reachable PostgreSQL database. From `platform/api`, create a virtual environment, install `.[dev]`, set the documented `PLATFORM_` variables in an environment file, then run:

```bash
python -m uvicorn intel_platform.main:app --reload --port 8000
python -m intel_platform.worker
pytest
ruff check .
```

On PowerShell activate with `.venv\Scripts\Activate.ps1`; on macOS/WSL use `source .venv/bin/activate`. The database schema is initialized/upgraded on API startup.

## Advanced native frontend

Requires Node.js 22.13+ and npm. From `platform/frontend`:

```bash
npm ci
npm run dev -- --host 0.0.0.0
npm test
npm run lint
```

The scripts use `cross-env`, so the same npm commands work in PowerShell, macOS, and WSL.

## Provider-free development

Paid providers are optional. Create investigations with local/passive capabilities or use test fixtures. Provider secrets belong in Settings and are encrypted before database storage; never add them to source, test snapshots, terminal transcripts, or `.env.example`.

## Contributor workflow

1. Fork the eventual GitHub repository and clone your fork.
2. Create a branch: `git switch -c feature/short-description`.
3. Run `python scripts/setup.py --start`.
4. Run the relevant API/frontend tests above.
5. Commit without `.env`, databases, reports, or provider keys.
6. Push the branch and open a pull request describing behavior and tests.

## Database operations

The API owns schema initialization. Back up before upgrades:

```bash
docker compose exec -T postgres pg_dump -U signaltrace -d signaltrace > signaltrace-backup.sql
```

Restore into an empty development database:

```bash
docker compose exec -T postgres psql -U signaltrace -d signaltrace < signaltrace-backup.sql
```

PowerShell restore:

```powershell
Get-Content .\signaltrace-backup.sql | docker compose exec -T postgres psql -U signaltrace -d signaltrace
```

`python scripts/reset_dev.py` deletes all local Compose volumes only after the operator types `DELETE`.
