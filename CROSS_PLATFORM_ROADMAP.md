# SignalTrace Cross-Platform Local Setup Roadmap

Status: approved for implementation  
Target hosts: macOS (Apple Silicon and Intel) and Windows 11 (Docker Desktop with WSL2)  
Primary outcome: a new contributor can clone, configure, start, verify, test, and stop SignalTrace using repository documentation alone.

## Implementation checkpoint — 2026-08-29

Implemented: canonical core Compose stack; API/worker/frontend/TAXII images; generated and validated `.env`; cross-platform setup, doctor, and destructive-reset guards; Git line-ending and secret/runtime exclusions; SignalTrace-first README; macOS/Windows development and troubleshooting guides; multi-OS CI; provider-availability portability tests; and vulnerability attack/remediation hover guidance.

Verified on Intel macOS: image builds, live core startup, PostgreSQL/API/frontend/TAXII health, 22 API tests, 2 rendered frontend tests, and frontend lint with no errors. Core Python, Node, and PostgreSQL manifests contain both `linux/amd64` and `linux/arm64` variants. Windows 11/WSL2 and Apple Silicon hardware acceptance remain intentionally unclaimed until those CI/hardware runs execute. The final clone URL remains pending because this directory intentionally has no Git repository or remote yet.

## Initial audited repository baseline

This records the state found before implementation, not the conceptual service list in the master prompt. Items described as “current” in this section are historical baseline facts; the implementation checkpoint above records the new state.

- The repository root still contains the upstream Python-based SpiderFoot 4 code, its legacy Dockerfiles, and a SpiderFoot-only `docker-compose.yml` exposing port `5001`.
- The current SignalTrace product is under `platform/`.
- The SignalTrace API uses Python 3.12+ and currently builds with Python 3.13.
- The API is FastAPI, SQLAlchemy, Uvicorn, and PostgreSQL-capable; native development has also used SQLite.
- The frontend is React 19, TypeScript, Vinext/Vite, npm, and Node.js 22.13+.
- The frontend runs on port `3000`; the API runs on port `8000` with docs at `/api/docs` and health endpoints at `/health/live` and `/health/ready`.
- Local TAXII runs on port `9000`.
- Ollama is optional and currently expected on port `11434`.
- Greenbone/OpenVAS is an optional separate Compose stack. Its Redis and PostgreSQL services are internal to Greenbone; SignalTrace does not currently require application-level Redis.
- SpiderFoot code exists locally, but the platform README describes a future adapter boundary. Its actual platform integration must be verified before it is advertised as a required SignalTrace service.
- IntelOwl is not currently implemented in the platform and must not be added to Compose or README as though it exists.
- The current root README is the upstream SpiderFoot README and does not document the SignalTrace product.
- `start-signaltrace.sh` is Bash-only and therefore is not a native PowerShell entry point.
- `platform/compose.yaml` currently includes only the API and PostgreSQL. It does not start the frontend, worker, TAXII server, Ollama, SpiderFoot, or Greenbone.
- No repository URL can be inferred from Git metadata because this working copy intentionally has no `.git` directory. The real URL must be supplied before final clone instructions are written.

## Delivery principles

- [ ] Docker Compose is the recommended cross-platform workflow.
- [ ] Native development is documented as an advanced workflow.
- [ ] Only real, required services are included in the default Compose stack.
- [ ] Optional services use explicit Compose profiles and remain disabled by default.
- [ ] No paid provider key is required to start the core application.
- [ ] Commands are tested before documentation is marked complete.
- [ ] macOS and Windows instructions always identify the shell being used.
- [ ] Credentials are never committed, printed by validators, or embedded in images.
- [ ] Active scanning remains gated by explicit authorization.

---

## Phase 1 — Full cross-platform repository audit

Deliverable: `docs/CROSS_PLATFORM_AUDIT.md`

- [ ] Inventory every language, framework, runtime, package manager, database, service, port, health endpoint, build command, test command, and environment variable.
- [ ] Separate the legacy SpiderFoot application from the SignalTrace platform architecture.
- [ ] Determine whether the root SpiderFoot service is currently called by SignalTrace or remains unintegrated source.
- [ ] Confirm that IntelOwl is absent and record it as a future optional integration rather than a current dependency.
- [ ] Document that Redis is only present inside the optional Greenbone stack unless application code changes.
- [ ] Inventory local AI behavior and document Ollama as optional unless the architecture changes.
- [ ] Audit `start-signaltrace.sh`, Greenbone shell scripts, `generate-certificate`, Dockerfiles, Compose files, Python utilities, and npm scripts.
- [ ] Search first-party source while excluding generated virtual environments, `node_modules`, caches, logs, databases, and downloaded feed data.
- [ ] Record Bash-only syntax, `chmod`, `/tmp`, `/var`, `/home`, `apt`, `apk`, Linux user/group commands, loopback assumptions, and host-path assumptions.
- [ ] Identify the committed `platform/tools/maigret-venv` absolute macOS paths as non-portable generated artifacts and plan their removal from source control.
- [ ] Check case-only filename conflicts and path-separator assumptions for Windows filesystems.
- [ ] Audit image architectures and upstream multi-architecture manifests for PostgreSQL, Greenbone, and any optional services.
- [ ] Record each incompatibility with severity, affected workflow, proposed fix, and verification method.

Exit gate:

- [ ] The audit accounts for every first-party startup path and does not claim SpiderFoot, IntelOwl, Redis, or Ollama requirements without code evidence.

## Phase 2 — Define the supported architecture and Compose boundary

Primary deliverable: root `compose.yaml`

- [ ] Choose the root `compose.yaml` as the canonical SignalTrace development stack.
- [ ] Rename or clearly archive the legacy SpiderFoot-only Compose files to prevent users from starting the wrong product.
- [ ] Define the default core services based on actual requirements:
  - [ ] `frontend`
  - [ ] `api`
  - [ ] `worker`
  - [ ] `postgres`
  - [ ] `taxii` if local TAXII remains a required default
- [ ] Decide whether local TAXII feed refresh is an init job, scheduled job, or optional profile.
- [ ] Keep SpiderFoot optional until a real SignalTrace adapter is proven and tested.
- [ ] Keep Greenbone/OpenVAS in an explicit optional profile or separate documented stack.
- [ ] Do not add IntelOwl until a real adapter and configuration contract exist.
- [ ] Do not add application Redis unless durable application code actually consumes it.
- [ ] Add internal networking, named volumes, restart policies, health checks, and health-based dependencies.
- [ ] Do not expose PostgreSQL publicly by default.
- [ ] Make host ports configurable with `.env` values.
- [ ] Use service DNS names inside containers instead of `127.0.0.1` or `localhost` for cross-container calls.
- [ ] Ensure frontend-to-API URL handling works from the browser and during container builds.
- [ ] Provide persistent volumes for PostgreSQL, TAXII feed state, quarantine data, and other real durable data.
- [ ] Apply non-root users, `no-new-privileges`, read-only filesystems, and bounded writable mounts where compatible.

Exit gate:

- [ ] `docker compose config` succeeds with a copied `.env` on macOS and Windows-compatible paths.
- [ ] `docker compose up -d` starts the complete core SignalTrace workflow.

## Phase 3 — Container images and architecture compatibility

- [ ] Create or update a frontend Dockerfile using the real npm lockfile and Node.js 22.13+.
- [ ] Update the API image to install the actual runtime and worker requirements.
- [ ] Create a worker service from the same immutable API image.
- [ ] Containerize local TAXII without relying on host-only paths.
- [ ] Pin appropriate major image versions and document the update policy.
- [ ] Inspect all default images for `linux/amd64` and `linux/arm64` manifests.
- [ ] Test or inspect Apple Silicon compatibility for PostgreSQL and each core image.
- [ ] Identify Greenbone images that lack native ARM support.
- [ ] Use `platform: linux/amd64` only for confirmed incompatible optional services.
- [ ] Document emulation performance and memory implications.
- [ ] Verify Intel Mac compatibility independently from Apple Silicon notes.

Exit gate:

- [ ] The core stack has no unnecessary architecture pin.
- [ ] Any emulation requirement is isolated to an optional profile and documented.

## Phase 4 — Environment configuration and validation

Deliverable: root `.env.example`

- [ ] Consolidate the existing `platform/.env.example`, API settings, frontend variables, Compose variables, TAXII settings, SMTP settings, local AI settings, and port overrides.
- [ ] Categorize every variable as required, generated, or optional.
- [ ] Include real core variables only, including at minimum:
  - [ ] `FRONTEND_PORT`
  - [ ] `API_PORT`
  - [ ] `TAXII_PORT`
  - [ ] PostgreSQL database, user, password, and `PLATFORM_DATABASE_URL`
  - [ ] `PLATFORM_PROVIDER_ENCRYPTION_KEY`
  - [ ] development identity and CORS configuration
  - [ ] frontend public API URL
- [ ] Include optional Ollama, SMTP, OIDC, Greenbone, and supported threat-provider variables only when code consumes them.
- [ ] Do not invent `OPENAI_API_KEY`, SpiderFoot URL, IntelOwl URL, or Redis URL variables unless implementation requires them.
- [ ] Keep provider secrets optional and prefer the existing encrypted in-app provider configuration workflow over plaintext `.env` storage.
- [ ] Add startup validation with concise remediation messages for missing core configuration.
- [ ] Validate malformed URLs, weak/default secrets, invalid ports, and production use of development identity.
- [ ] Ensure validators never display secret values.
- [ ] Ensure `.env` and platform-specific environment files are ignored by Git.

Exit gate:

- [ ] A missing required variable produces an actionable one-line error pointing to `.env.example`.
- [ ] The core application starts without optional paid-provider credentials.

## Phase 5 — Cross-platform bootstrap and doctor utilities

Proposed deliverables:

- `scripts/setup.py`
- `scripts/doctor.py`
- `scripts/reset_dev.py`

- [ ] Implement `scripts/setup.py` using only the Python standard library where practical.
- [ ] Detect Python, Git, Docker, Docker Compose v2, available ports, `.env`, and Docker daemon state.
- [ ] Copy `.env.example` to `.env` without overwriting an existing file.
- [ ] Generate development-only encryption/database secrets using `secrets`, not fixed defaults.
- [ ] Create required directories using `pathlib`.
- [ ] Validate Compose and optionally start the stack.
- [ ] Print actual application, API, documentation, TAXII, SpiderFoot, and Greenbone URLs only when those services are enabled.
- [ ] Implement `scripts/doctor.py` with PASS/WARN/FAIL results for core and optional components.
- [ ] Support both macOS Terminal and Windows PowerShell invocation: `python scripts/doctor.py`.
- [ ] Never print `.env` values or stored provider keys.
- [ ] Implement `scripts/reset_dev.py` with an explicit confirmation and a prominent data-loss warning.
- [ ] Keep `start-signaltrace.sh` as an advanced macOS/Linux native helper or replace its orchestration role with cross-platform utilities.
- [ ] Do not require native Windows users to run Bash.

Exit gate:

- [ ] Setup and doctor tests pass on macOS, Windows, and Linux CI runners.

## Phase 6 — Database lifecycle

- [ ] Decide and document PostgreSQL as the Docker default.
- [ ] Decide whether SQLite remains supported for native development and tests.
- [ ] Replace ad hoc additive schema upgrades with a documented migration strategy if production-style upgrades are expected.
- [ ] Add a safe migration command and test it against an existing development database.
- [ ] Document initial creation performed by Compose and API startup.
- [ ] Add tested backup commands using the actual PostgreSQL service and credentials.
- [ ] Add tested restore commands.
- [ ] Add a destructive reset command through `scripts/reset_dev.py` and `docker compose down -v` with explicit warnings.
- [ ] Never recommend resetting the database as a normal update step.

Exit gate:

- [ ] Fresh initialization, migration, backup, restore, and reset are each documented and tested.

## Phase 7 — File, shell, and line-ending portability

Deliverables: `.gitattributes`, updated `.gitignore`

- [ ] Add `.gitattributes` rules that keep shell scripts LF and support appropriate Python, JavaScript, TypeScript, YAML, JSON, Markdown, and PowerShell line endings.
- [ ] Ensure CRLF cannot break Linux-container entrypoints.
- [ ] Remove committed virtual environments, generated binaries, runtime databases, logs, feed output, quarantine contents, and machine-specific activation scripts.
- [ ] Extend `.gitignore` for `.env`, `platform/api/.env`, `node_modules`, platform runtime state, virtual environments, and build output.
- [ ] Replace host path concatenation with `pathlib.Path` in Python and platform-neutral APIs in Node code.
- [ ] Remove hard-coded `/Users/blockdev/...` paths from all first-party and committed generated files.
- [ ] Keep Linux container paths inside Dockerfiles and Compose where appropriate; document that they are container paths, not host prerequisites.
- [ ] Replace shell-only cleanup or secret-generation operations in the supported cross-platform path.

Exit gate:

- [ ] A clean checkout contains no developer-specific absolute paths or committed virtual environment.

## Phase 8 — CI and cross-platform regression coverage

- [ ] Preserve the existing SpiderFoot test workflow while separating it from SignalTrace tests.
- [ ] Add a SignalTrace CI workflow with `ubuntu-latest`, `macos-latest`, and `windows-latest`.
- [ ] Test `scripts/setup.py --check`, `scripts/doctor.py --offline`, environment parsing, and path handling on all three systems.
- [ ] Run API lint and tests with a supported Python version.
- [ ] Run frontend install, lint, tests, and production build with the locked Node.js version.
- [ ] Run `docker compose config` in CI.
- [ ] Add a Linux Compose smoke test for PostgreSQL, API, worker, TAXII, and frontend.
- [ ] Verify `/health/live`, `/health/ready`, API docs, and frontend response.
- [ ] Do not require paid provider keys or active scanning in CI.
- [ ] Use mocks and disabled optional integrations for contributor workflows.

Exit gate:

- [ ] Platform-independent setup utilities pass on Windows, macOS, and Linux.
- [ ] The core Compose smoke test passes on Linux.

## Phase 9 — Documentation set

Deliverables:

- `README.md`
- `docs/DEVELOPMENT.md`
- `docs/TROUBLESHOOTING.md`
- `docs/CROSS_PLATFORM_AUDIT.md`

- [ ] Replace the upstream-only root README with a SignalTrace-first README while preserving clear attribution and links for bundled SpiderFoot code.
- [ ] Obtain the actual future GitHub repository URL before writing clone commands.
- [ ] Use the approved README structure:
  - [ ] Project name and short description
  - [ ] Features
  - [ ] Architecture
  - [ ] Requirements
  - [ ] Quick Start
  - [ ] Installation — macOS
  - [ ] Apple Silicon notes
  - [ ] Intel Mac notes
  - [ ] Installation — Windows 11
  - [ ] Docker Desktop and WSL2
  - [ ] PowerShell setup
  - [ ] Optional WSL/Ubuntu workflow
  - [ ] Environment configuration
  - [ ] Running and available services
  - [ ] Optional intelligence integrations
  - [ ] Development and testing
  - [ ] Updating and stopping
  - [ ] Resetting development data
  - [ ] Troubleshooting
  - [ ] Security and authorized use
  - [ ] License and contributing
- [ ] Clearly label Docker Compose as Recommended and native dependency setup as Advanced.
- [ ] Verify every README command against a real script, package command, Compose service, or implemented utility.
- [ ] Include separate macOS Terminal, Windows PowerShell, and Windows WSL/Ubuntu command blocks.
- [ ] Include `wsl --status`, conditional `wsl --install`, reboot guidance, and Docker Desktop WSL2 setup.
- [ ] Recommend a WSL filesystem clone only if measured bind-mount performance or file watching justifies it.
- [ ] Document exact URLs and configurable ports.
- [ ] Document first-run behavior based on actual images, migrations, feed initialization, and service startup.
- [ ] Add a real optional-provider table covering the 43 registered SignalTrace adapters by category without requiring all credentials.
- [ ] Explain that SpiderFoot and Greenbone are optional unless enabled; state plainly that IntelOwl is not integrated.
- [ ] Document start, stop, restart, logs, rebuild, update, health-check, backup, restore, and reset commands.
- [ ] Include Bash and PowerShell health checks and the expected healthy JSON response.
- [ ] Document contributor fork, branch, dependency, test, and pull-request workflow.
- [ ] Document credential hygiene, `.env` protection, key rotation, passive versus active collection, and authorization boundaries.

Exit gate:

- [ ] A reader never has to guess which shell, directory, service, or port a command targets.

## Phase 10 — Troubleshooting verification

Deliverable: `docs/TROUBLESHOOTING.md`

- [ ] Docker command not found.
- [ ] Docker daemon not running.
- [ ] Docker Compose plugin missing or outdated.
- [ ] Port `3000`, `8000`, `9000`, `11434`, or optional `5001` already in use.
- [ ] PostgreSQL unhealthy or migration failure.
- [ ] Frontend cannot reach API because of browser URL or CORS configuration.
- [ ] Worker or TAXII repeatedly restarting.
- [ ] Apple Silicon image or emulation error.
- [ ] Windows WSL2, virtualization, Docker integration, or filesystem performance issue.
- [ ] CRLF or executable-bit failure inside Linux containers.
- [ ] Missing or invalid required environment variable.
- [ ] SpiderFoot unavailable when its optional profile is enabled.
- [ ] Greenbone/OpenVAS initialization or internal Redis failure.
- [ ] IntelOwl requested even though no adapter exists.
- [ ] Ollama unavailable or model missing.
- [ ] External provider key invalid, rate-limited, or disabled.
- [ ] Container restart loop and targeted log commands.
- [ ] Safe diagnostics that never expose secrets.

Exit gate:

- [ ] Every troubleshooting entry includes symptoms, diagnostic commands, likely cause, and a tested recovery path.

## Phase 11 — Acceptance testing

### macOS acceptance workflow

- [ ] Test Docker Desktop on an available macOS host.
- [ ] Verify the actual host architecture with `uname -m`.
- [ ] Test Apple Silicon natively where available; otherwise record image-manifest inspection and the untested limitation.
- [ ] Test Intel Mac directly where available; otherwise record image-manifest inspection and the untested limitation.
- [ ] Clone or use a clean exported checkout.
- [ ] Copy `.env.example` to `.env`.
- [ ] Run setup validation.
- [ ] Start with `docker compose up -d`.
- [ ] Verify Compose health, frontend, API, docs, worker processing, and TAXII.
- [ ] Run documented API and frontend tests.
- [ ] Stop without deleting data.
- [ ] Restart and confirm data persists.

### Windows 11 acceptance workflow

- [ ] Verify WSL2 and Docker Desktop prerequisites from PowerShell.
- [ ] Test a clean checkout using Windows PowerShell commands.
- [ ] Test the documented WSL/Ubuntu path if it remains recommended.
- [ ] Copy `.env.example` with `Copy-Item`.
- [ ] Run `python scripts/doctor.py` without Bash.
- [ ] Start with `docker compose up -d`.
- [ ] Verify services with PowerShell and browser checks.
- [ ] Run documented platform-independent tests.
- [ ] Stop and restart the stack.
- [ ] Confirm line endings, bind mounts, file watching, and persistent volumes behave correctly.

### Evidence requirements

- [ ] Record OS version, CPU architecture, Docker Desktop version, Compose version, commands run, results, and any deviations.
- [ ] Do not claim direct Windows or Intel/Apple Silicon testing where only inspection or CI was possible.

## Phase 12 — Release and handoff

- [ ] Confirm all required deliverables exist:
  - [ ] `README.md`
  - [ ] `.env.example`
  - [ ] `.gitignore`
  - [ ] `.gitattributes`
  - [ ] `compose.yaml`
  - [ ] `docs/CROSS_PLATFORM_AUDIT.md`
  - [ ] `docs/DEVELOPMENT.md`
  - [ ] `docs/TROUBLESHOOTING.md`
- [ ] Include justified utilities:
  - [ ] `scripts/setup.py`
  - [ ] `scripts/doctor.py`
  - [ ] `scripts/reset_dev.py`
- [ ] Confirm no real credentials, tokens, generated secrets, local databases, or virtual environments are tracked.
- [ ] Confirm the documented repository URL is correct.
- [ ] Re-run backend tests, frontend tests/build, doctor tests, Compose validation, and health checks.
- [ ] Produce the final implementation report with:
  - [ ] Files changed
  - [ ] macOS support
  - [ ] Windows support
  - [ ] Apple Silicon support
  - [ ] Docker changes
  - [ ] New setup commands
  - [ ] Environment variables
  - [ ] Known limitations
  - [ ] Tests performed
  - [ ] Remaining platform-specific issues

## Definition of done

This roadmap is complete only when an unfamiliar developer can use the tested README to:

1. clone the correct repository;
2. copy and validate environment configuration;
3. start the core application on macOS or Windows 11;
4. open the frontend;
5. verify API and service health;
6. run tests without paid provider credentials;
7. stop and restart without losing data; and
8. diagnose common failures without help from the original developer.

Documentation completion is not sufficient by itself. Each support claim must be backed by direct host testing, cross-platform CI, image-manifest inspection, or an explicitly stated limitation.
