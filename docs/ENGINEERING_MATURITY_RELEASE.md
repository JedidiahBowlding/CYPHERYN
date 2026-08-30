# SignalTrace Engineering Maturity Release

This milestone proves and hardens existing behavior. It does not expand the provider catalog.

## Scanner isolation architecture

High-risk local adapters fail closed unless `PLATFORM_SCANNER_IMAGES` maps the provider name to an explicit versioned image or digest. One job launches one short-lived container. The separately trusted orchestrator applies a read-only root, dropped Linux capabilities, `no-new-privileges`, bounded CPU/memory/PIDs/output/deadline/tmpfs, an empty scanner environment, no host mounts, and no Docker socket inside the scanner. Timeout and cancellation forcibly remove the container, and namespaced cleanup runs during execution, shutdown, and startup.

Authorization remains checked immediately before provider execution. If authorization expires after a scan has begun, the current execution is terminated only when cancellation/deadline/policy requests it; expiration always prevents a new execution or retry. Scanner audit events must record provider/version/image, target and authorization identifiers, timing, outcome, limits, and policy—not secrets or raw credentials.

Docker Desktop cannot enforce destination-level egress ACLs with a plain bridge alone. `network=none` is the safe default. Network scanners require an explicitly selected bridge or SignalTrace-managed network plus application-level public-target validation. Production deployments should put that network behind an egress-policy gateway or isolated worker node.

## Observability model

Workers persist identity, version, heartbeat, last successful poll, active-job count, and bounded failure information. `/health/workers` distinguishes a healthy API from a dead worker. `/metrics` provides dependency-free Prometheus exposition for worker, queue, evidence, and provider outcomes. HTTP requests use returned correlation IDs and structured redacted logs. See `docs/OBSERVABILITY.md` for metrics, alerts, privacy, and troubleshooting.

## Provider certification

Provider tiers are independent of runtime readiness:

- `SUPPORTED`: maintained and covered by the complete deterministic support contract.
- `EXPERIMENTAL`: functioning SignalTrace-native integration whose complete support contract is not yet certified.
- `ADAPTER_ONLY`: an adapter exists, but installation/service availability and certification are not guaranteed.
- `INHERITED`: upstream behavior retained for compatibility and not claimed as SignalTrace-supported.

The current supported contract set is VirusTotal, Shodan, AlienVault OTX, Censys, and ThreatFox. No live third-party call runs in ordinary CI. Runtime display separately reports adapter presence, installation, configuration, health, contract status, Live Verified timestamp, version, and failure reason.

Live verification is fresh for seven days, aging from day 7 through day 29, and stale at day 30. This policy balances typical weekly defensive review with the volatility of Internet intelligence; deployments may use stricter operational policy. Health never creates a Live Verified timestamp—only a successful collection does.

## Critical coverage policy

Coverage gates focus on owned security/integrity modules: integrity and redaction at 90%, provider controls at 85%, process termination and scanner isolation at 80%, observability at 85%, and an initial external-anchor threshold of 60% while deterministic destination and rotation coverage expands. A global 50% floor prevents broad regression. Inherited SpiderFoot is excluded from SignalTrace-native thresholds.

The low-coverage orchestration, detection, normalization, report, notification, and malware modules remain explicit pre-`0.9.0` work. The project will raise thresholds only alongside behavior-focused tests, never meaningless line execution.

## External integrity anchoring

SignalTrace can calculate a versioned checkpoint containing scope, chain head, record count, first/last record IDs, timestamp, application version, and SHA-256 algorithm. An external Ed25519 private key signs its canonical JSON. Anchors contain a key identifier and public key; private keys are files or external signer inputs and never ordinary database records.

The provider-neutral destination contract currently includes filesystem storage suitable for a separately mounted or synchronized trust domain. S3 Object Lock, immutable cloud storage, transparency services, or customer verification endpoints can implement the same interface. The offline verifier checks signature, optional expected key identity, record hashes, chain continuity, head, count, and scope.

```bash
cd platform/api
python -m intel_platform.integrity_anchor generate-key /secure/signaltrace-anchor.pem
python -m intel_platform.integrity_anchor verify export.json checkpoint.anchor.json \
  --expected-key-id ed25519:<trusted-id>
```

Anchoring detects divergence from the independently retained checkpoint. It does not protect unanchored history, prevent database writes, or survive compromise of both the application and anchor trust domains. Key rotation uses a new key identifier; retain prior public keys for historical verification.

## Governance and releases

The repository now includes contribution, conduct, security, changelog, issue/PR, and dependency-update policy. A version tag runs tests, focused coverage, lint/type/build/render, dependency audits, shipped-image scans, SBOM generation, source packaging, SHA-256 checksums, GitHub provenance attestation, and GitHub Release publication.

Recommended `main` protection must be configured by the repository owner: require pull requests and review, require Tests, SignalTrace cross-platform, Security and supply chain, and CodeQL, dismiss stale approvals, block force pushes/deletion, and require conversation resolution. Repository settings are an external control and cannot be proven by files alone.

## Known limitations

- Scanner isolation depends on the Docker daemon and configured, reviewed scanner images.
- The default Compose worker is intentionally denied the Docker socket. The optional `scanner` Compose profile now deploys the authenticated, backend-only trusted orchestrator; active adapters fail closed when it is disabled or unhealthy.
- Container network destination enforcement needs an environment-specific gateway for strong egress policy.
- Scanner image signatures/digests should be required operationally even though explicit version tags are accepted for local development.
- Signed anchors only add independence when exported outside the application administrator's trust domain.
- Provider certification currently covers five priority providers; all others are labeled truthfully.
- Critical orchestration coverage remains below the long-term target and is reported rather than hidden.
