# Changelog

SignalTrace follows [Semantic Versioning](https://semver.org/) before and after `1.0.0`.

## [Unreleased]

### Added

- Separately trusted, authenticated scanner orchestrator with server-side image/binary allowlists, job-scoped execution, hard policy ceilings, cancellation, and an optional Compose deployment profile.
- Critical-path regression coverage for worker lease recovery and lifecycle transitions, detection ingestion, target normalization, report integrity exports, notification transport handling, and malware-analysis safety behavior.
- Disposable scanner-container policy and execution boundary with explicit resource, filesystem, environment, network, deadline, cancellation, and cleanup controls.
- Worker/queue/provider operational telemetry, structured correlation IDs, worker health, and Prometheus-compatible metrics.
- Objective provider support tiers and timestamp-based verification freshness.
- Signed external evidence-chain checkpoints and offline verification.
- Automatic on-change and scheduled evidence anchoring with exclusive checkpoint bundles,
  retained Ed25519 key rotation, read-only API visibility, and JSON/PDF export references.
- Open-source governance, dependency automation, critical coverage policy, and reproducible release automation.

### Changed

- Raised the owned API coverage floor from 50% to 60% and added enforceable module gates for worker, detection, normalization, reports, notifications, and malware analysis.
- Active local scanner adapters fail closed unless a disposable scanner image is explicitly configured.

### Fixed

- Timeline CSV exports now include evidence integrity hashes instead of rejecting evidence timeline records containing integrity metadata.
- Local repository targets now recognize absolute Windows drive paths before URL parsing; platform-specific permission assertions run only where POSIX modes are meaningful.

### Security

- Scanner containers receive no application environment, Docker socket, host mounts, or repository access.
- Integrity signing keys remain external to ordinary application database records.
- The API never receives the private signing-key mount; only the worker can read it, and
  only the worker can write the separately mounted anchor destination.

### Known limitations

- Docker Desktop cannot enforce destination-level scanner egress policy without an additional policy-aware gateway.
- External anchors are only independent when retained in a separately controlled trust domain.

## [0.8.0] - Unreleased

### Added

- Provider readiness ladder and priority provider contract tests.
- Linked SHA-256 evidence and audit integrity chains.
- Hard process-tree termination and bounded output for local tools.

### Fixed

- Frontend rendered-logo test for optimized images.
- Actionable OpenSSL findings in the API image.

### Security

- Mandatory dependency, secret, CodeQL, container, and SBOM gates.

### Known limitations

- Process groups are not hostile-code sandboxes.
- Database-local chains are tamper-evident but not independently anchored in `0.8.0`.
