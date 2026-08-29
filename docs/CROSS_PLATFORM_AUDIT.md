# SignalTrace cross-platform audit

Audited 2026-08-29 on macOS 26.5.2 (Intel), Docker Desktop 29.1.3, Compose 5.0.0, Python 3.13.7, and host Node 22.11.0. Windows and Apple Silicon conclusions below are inspection-based unless explicitly stated.

## Product boundary

SignalTrace is the application in `platform/`. The repository root also contains the inherited SpiderFoot 4 Python application. SpiderFoot is available as an optional standalone Compose profile; SignalTrace does not currently call it. IntelOwl is not implemented and is not a dependency. Redis is used only by the separate optional Greenbone stack, not by SignalTrace core.

## Runtime inventory

| Component | Implementation | Required | Port / health |
| --- | --- | --- | --- |
| Frontend | React 19, TypeScript, Vinext/Vite, npm, Node >=22.13 | Yes | 3000, `/` |
| API | Python >=3.12, FastAPI, SQLAlchemy, Uvicorn | Yes | 8000, `/health/live`, `/health/ready`, docs `/api/docs` |
| Worker | Same Python package as API; database-backed durable jobs | Yes | Internal only |
| Database | PostgreSQL 17 | Yes in Compose | Internal 5432 |
| TAXII | Local Python TAXII 2.1 server and bundled STIX data | Yes in core Compose | 9000, `/health` |
| Ollama | Host-local optional AI | No | 11434 |
| SpiderFoot | Inherited Python OSINT application | No | profile port 5001 |
| Greenbone | Separate upstream Compose stack with its own PostgreSQL/Redis | No | See `platform/greenbone/` |

The API creates/upgrades its schema at startup; there is no Alembic migration command or seed command. Provider credentials are configured in the UI and encrypted in PostgreSQL. Supported provider adapters include VirusTotal, Shodan, GreyNoise, AlienVault OTX, AbuseIPDB, Censys, URLhaus, abuse.ch ThreatFox, TAXII, source-code/supply-chain sources, and installed local tools. None is required for core startup.

## Portability findings

| Severity | Finding | Effect | Resolution / status |
| --- | --- | --- | --- |
| High | The old root `docker-compose.yml` launched only SpiderFoot | Users started the wrong product | Archived as explicit `compose.spiderfoot.yaml`; root `compose.yaml` is canonical |
| High | `start-signaltrace.sh` and Greenbone helpers require Bash | Cannot run in native PowerShell | Docker Compose and Python setup/doctor/reset are the supported cross-platform entry points; Bash launcher remains macOS/WSL-only |
| High | Frontend npm scripts used Unix inline environment assignment | Native Windows npm commands failed | Added `cross-env` to all Vinext scripts |
| High | `.env` and generated runtime paths were not comprehensively ignored | Credential/data disclosure risk | Root and platform env/runtime paths are ignored; `.env.example` remains tracked |
| Medium | Frontend declared Node >=22.13; audit host has 22.11 | Native build emits engine warnings/fails unpredictably | Docker pins Node 22.14; native docs require >=22.13 |
| Medium | Frontend had a direct macOS x64 Rolldown binding | Broke other OS/architectures | Removed direct binding; Rolldown chooses its optional platform package |
| Medium | Build contexts included `node_modules` and local virtual environments | Slow builds and non-portable native binaries | Added component `.dockerignore` files |
| Medium | `platform/tools/maigret-venv` contains absolute `/Users/blockdev/...` paths | Cannot be reused elsewhere | Ignored as generated state; recreate locally. It is not used by core Compose |
| Medium | Legacy SpiderFoot test scripts and certificate helper use Bash/chmod | Native PowerShell cannot run them | Classified as legacy/advanced; core CI and workflow do not call them on Windows |
| Medium | Legacy `Dockerfile.full` uses Debian packages and Linux paths | Container-only, potentially architecture-limited tools | Not used by SignalTrace core; standalone basic SpiderFoot profile uses `Dockerfile` |
| Medium | Greenbone startup/status/stop are Bash scripts and upstream images vary by architecture | Windows native and ARM experience differs | Optional separate stack; run inside WSL/macOS terminal and consult its upstream image support |
| Low | Linux container paths `/tmp`, `/data`, `/var/lib/postgresql` occur in Compose | None on host when named volumes are used | Intentional container-internal paths; no host path separator dependency |
| Low | Root has inherited case-sensitive module/file names | Potential case-only conflicts on default macOS/Windows filesystems | No case-only collision was found in current first-party SignalTrace paths |

## Architecture assessment

Core images (`python:3.13-slim`, `node:22.14-bookworm-slim`, `postgres:17-alpine`) publish standard amd64 and arm64 variants and the Dockerfiles contain no architecture pin. Intel macOS was built directly. Apple Silicon is supported by this unpinned multi-architecture core stack but was not hardware-tested here. Optional legacy/Greenbone tooling may require upstream-specific inspection or amd64 emulation; no emulation is forced in the core stack.

## Linux assumptions that remain intentionally

Containers use Linux users, ownership, `/tmp`, `/data`, and Debian-based images. These remain inside the container or named volumes—whether Docker runs natively on Linux or in Docker Desktop's Linux VM—and do not require matching host paths. The legacy SpiderFoot and Greenbone shell utilities remain available for Linux, macOS, or WSL users but are not part of the Windows PowerShell quick start.

## Native Linux host support

The canonical `compose.yaml` also runs directly on a 64-bit Linux host with Docker Engine and the Compose v2 plugin; Docker Desktop is not required. The bootstrap and doctor utilities use Python and platform-neutral path/process APIs. Named volumes avoid SELinux bind-mount labeling and host path-separator issues in the core stack.

Ubuntu is covered by the CI matrix for API tests, frontend lint/build/tests, utility compilation, and Compose validation. A live clean-host installation was not performed on Debian, Fedora, RHEL, or an ARM Linux machine in the available environment, so those systems are documented as expected-compatible rather than hardware-tested. Third-party optional stacks retain their upstream Linux and architecture constraints.

The Compose file publishes the frontend, API, and TAXII ports on the host. A workstation can access these through `localhost`; a remote Linux deployment must add firewall restrictions or an authenticated TLS reverse proxy rather than expose the development endpoints directly to the Internet.

## Verification performed

- Python utilities and TAXII server passed bytecode compilation.
- `python scripts/setup.py --check` generated a private `.env` and validated Compose without revealing secrets.
- `docker compose config --quiet` passed.
- Core API, worker, TAXII, and frontend images were built on Intel macOS.
- Frontend production compilation discovered and built all application routes.

Windows 11/WSL2 and Apple Silicon require CI or hardware acceptance runs; this document does not represent them as directly tested.
