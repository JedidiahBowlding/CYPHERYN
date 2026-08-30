# CYPHERYN Verification and Hardening Release

This release focuses on proving and protecting existing capabilities rather than expanding the provider catalog.

## Verified improvements

- Frontend and Python security dependencies are upgraded and security audits are mandatory in CI.
- TypeScript validation is a first-class build gate.
- Platform CI runs against `main` and verifies API tests, coverage, lint, frontend types, builds, rendered routes, Compose health, secrets, container vulnerabilities, and an SBOM.
- Provider status uses the progressive states **Supported → Installed → Configured → Healthy → Live Verified**. A provider is never described as live verified without a recorded successful collection timestamp.
- Priority threat-intelligence provider contracts cover request construction, missing credentials, authentication failures, throttling, malformed payloads, timeouts, and security-signal normalization.
- Local active tools run in new process groups with hard timeout termination, bounded captured output, and a reduced environment that does not inherit unrelated application secrets.
- Evidence sources and audit events carry linked integrity hashes. PostgreSQL transaction locks serialize chain creation per investigation or organization.

## Release gate closure

- The rendered landing-page test validates Vinext's optimized CYPHERYN logo URL and passes with the production build.
- The API image upgrades Debian security packages during the build. OpenSSL resolves to the fixed `3.5.7-1~deb13u2` packages.
- Trivy reports zero unsuppressed HIGH or CRITICAL findings for the rebuilt API image.
- Two reviewed Trivy exceptions cover pip-vendored `msgpack` and `setuptools` source metadata; runtime package inspection confirms neither distribution is installed. The real OpenSSL findings are remediated, not suppressed.

## Important boundaries

Integrity chains make accidental or unsophisticated modification detectable. A database administrator who can rewrite the full history and application code can still recompute a chain. For stronger independent verification, export signed chain anchors to storage controlled by a separate trust domain.

Local process-group isolation is a hard termination boundary, not a complete hostile-code sandbox. High-risk active scanners should ultimately run in short-lived containers or isolated worker nodes with explicit CPU, memory, filesystem, and egress policies.

`Live Verified` records a successful provider collection; it is not a guarantee that the external provider will remain available. The timestamp lets analysts judge freshness.
