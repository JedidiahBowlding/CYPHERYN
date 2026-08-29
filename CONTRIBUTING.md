# Contributing to SignalTrace

Thank you for improving SignalTrace. Contributions must preserve authorization boundaries, evidence provenance, credential secrecy, and local-first operation.

## Workflow

1. Fork the repository and clone your fork.
2. Create a focused branch from `main`.
3. Follow the Docker quick start in `README.md` or the native setup in `docs/DEVELOPMENT.md`.
4. Add deterministic tests. Paid credentials and live third-party calls are not required for normal development.
5. Run the checks below before opening a pull request.

```bash
cd platform/api
python -m pytest --cov=intel_platform --cov-report=json:coverage.json
python ../../scripts/check_critical_coverage.py coverage.json
python -m ruff check src tests

cd ../frontend
npm ci
npm run lint
npm run typecheck
npm test
```

Also run `python scripts/doctor.py` from the repository root after starting Compose.

## Provider changes

- Do not classify an adapter as `SUPPORTED` until its deterministic contract suite covers authentication, errors, throttling, malformed/partial data, timeouts, cancellation, redaction, normalization, provenance, hashing, circuit breaking, and Live Verified timestamp behavior.
- Never put live credentials or unredacted customer responses in fixtures.
- Live verification is timestamped point-in-time evidence, not adapter presence or a healthy status endpoint.

## Evidence and privacy

- Preserve raw-response hashes, source metadata, authorization references, redaction policy, and integrity links.
- Logs, exceptions, tests, screenshots, and reports must not disclose credentials or sensitive raw evidence.
- AI output is advisory. It must not expand targets, replace provenance, or become the authoritative evidence record.

## Pull requests

Keep changes small enough to review, explain security implications and migrations, update documentation, and identify any test that cannot run in ordinary CI. A maintainer may request threat-model notes for scanner, authorization, credential, notification, or integrity changes.
