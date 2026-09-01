# Trusted scanner orchestrator

CYPHERYN active scanners can run through a separately trusted service that owns Docker
access. The API and normal worker do not mount the Docker socket. This boundary limits a
compromised scanner process and prevents ordinary collection code from directly controlling
the host container runtime.

## Trust topology

```text
API / PostgreSQL
       |
       v
Normal worker (no Docker socket)
       |
       | authenticated, job-scoped submit/status/cancel
       v
Trusted scanner orchestrator (Docker socket)
       |
       v
One disposable, policy-bounded scanner container per execution
```

The orchestrator is an optional Compose profile and has no published host port. It is reachable
only on the internal `backend` network. A generated bearer token authenticates the worker.
Neither the API container nor scanner containers receive that token.

## Enable it

Run the cross-platform setup utility once after upgrading. It adds a missing orchestrator token
without changing existing values:

```bash
python3 scripts/setup.py --check
```

Windows PowerShell uses:

```powershell
py scripts/setup.py --check
```

Configure explicit scanner images in `.env`. The orchestrator accepts only known provider names,
and it resolves the image server-side. Never use `latest`.

```env
PLATFORM_SCANNER_IMAGES={"nmap":"your-registry/cypheryn-nmap:1.0.0"}
```

The image must contain the expected scanner executable. CYPHERYN does not publish or silently
download third-party scanner images. Review, pin, scan, and license each image before enabling it.

Production mode is deliberately stricter. Every image must use an immutable digest, the unrestricted
Docker `bridge` network is rejected, and active scanners must use a `cypheryn-egress-*` network
whose Docker metadata asserts `cypheryn.egress-policy=enforced`:

```env
PLATFORM_ENVIRONMENT=production
PLATFORM_SCANNER_IMAGES={"nmap":"registry.example/cypheryn-nmap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

For images reviewed and built directly on a single trusted scanner node, an immutable local image
ID (`sha256:<64 hex characters>`) is also accepted. Registry digests remain preferable for fleets
because every node can independently pull and verify the same artifact.

The label is a fail-closed deployment assertion, not an egress firewall. Create and label that
network only after an external gateway or dedicated scanner node actually enforces the authorized
destination policy. CYPHERYN refuses an absent, inaccessible, or unlabeled managed network.

The remote-execution allowlist covers output-stream-compatible adapters: Subfinder,
ProjectDiscovery HTTPX, Naabu, Nmap, RustScan, Masscan, Nuclei, Katana, DNS Twist, TestSSL, and
ZAP Passive. CYPHERYN's TestSSL and ZAP Passive scanner images use narrow wrappers that emit their
bounded JSON report on stdout, so no worker directory or host path is mounted. Adapters that still
require host-side temporary files (authenticated Katana, Nikto, and ZAP Active) remain fail-closed
until they gain the same artifact contract.

Start the profile:

```bash
docker compose --profile scanner up -d --build
docker compose --profile scanner ps
docker compose --profile scanner logs -f scanner-orchestrator
```

## Enforced controls

The orchestrator:

- authenticates every submit, status, and cancellation request with constant-time comparison;
- chooses images from its own provider-to-image allowlist;
- binds each provider to an expected executable and rejects shell substitution;
- requires an authorization identifier for active scanners;
- rejects excessive CPU, memory, PID, time, output, and temporary-storage requests;
- caps concurrent executions;
- launches one container per job with a read-only root, all capabilities dropped, and
  `no-new-privileges`;
- provides bounded `tmpfs`, output, runtime, and forced cancellation cleanup;
- labels every managed scanner container with a Compose-project namespace and removes its managed
  children during shutdown and startup;
- passes no application environment, provider credentials, repository mount, host mount, or
  Docker socket into scanner containers;
- returns only job-scoped status and bounded output to the worker.

The worker fails closed when the orchestrator is missing, unreachable, unauthenticated, or rejects
the provider, image, command, authorization, or policy.

## Verify socket separation

```bash
docker inspect cypheryn-worker --format '{{json .Mounts}}'
docker inspect cypheryn-scanner-orchestrator --format '{{json .Mounts}}'
```

Only `scanner-orchestrator` should show `/var/run/docker.sock`. Scanner child containers never
receive it.

## Security boundary

The Docker socket is effectively host-level control. The orchestrator is therefore a privileged
trust component even though its own filesystem is read-only and its scanner children are
restricted. Do not publish its port, share its token, or place unrelated workloads in this
container.

The bearer token authenticates the trusted worker; it does not independently prove the end user's
authorization. CYPHERYN revalidates the persisted target authorization immediately before the
worker submits an active execution and sends the resulting authorization ID for correlation.

Docker Desktop and a plain Docker bridge cannot enforce destination-level egress policy. Production
operators should place scanner traffic behind a policy-aware egress gateway or run the orchestrator
on a dedicated scanner node. `PLATFORM_ENVIRONMENT=production` prevents version-tagged images,
generic bridge networking, and active execution on an unattested network. The default development
profile is appropriate for controlled local use, not a hostile multi-tenant environment.
