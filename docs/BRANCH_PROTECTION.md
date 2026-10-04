# Main Branch Protection

The GitHub `main` branch is an external security boundary and cannot be represented by
repository files alone. The repository owner configures it through GitHub's branch
protection API after the exact release-hardening commit passes hosted CI.

The required policy is:

- Pull requests are required before merging.
- At least one approving review is required.
- Stale approvals are dismissed when new commits are pushed.
- Approval of the most recent reviewable push is required.
- All review conversations must be resolved.
- Administrators are included in enforcement.
- Force pushes and branch deletion are disabled.
- Status checks must be current with `main` before merge.

Required checks:

- `build (3.10, ubuntu-latest)`
- `build (3.10, macos-latest)`
- `build (3.10, windows-latest)`
- `utilities-api (ubuntu-latest)`
- `utilities-api (macos-latest)`
- `utilities-api (windows-latest)`
- `frontend (ubuntu-latest)`
- `frontend (macos-latest)`
- `frontend (windows-latest)`
- `compose`
- `dependencies`
- `secrets`
- `container-and-sbom`
- `Analyze (python)`
- `Analyze (javascript-typescript)`
- `concurrency`
- `independence`
- `PostgreSQL authority and migrations`

The Ubuntu `utilities-api` check installs Tesseract so the OCR classification test
is executed rather than skipped. `PostgreSQL authority and migrations` provisions
an isolated PostgreSQL 17 service, executes the single-use/concurrency test, verifies
upgrade from the previous baseline, exercises the supported development downgrade and
re-upgrade path, and validates clean-development initialization. The two federation
checks remain independently required so a green generic API matrix cannot hide a
database race or two-node regression.

Repository administrators should review this list whenever workflow job names change.
Renaming a required job without updating branch protection can block legitimate merges;
removing a check from protection can silently weaken the release boundary.
