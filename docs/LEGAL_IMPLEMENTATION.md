# CYPHERYN Legal and Responsible-Use Implementation

The operator reported qualified-counsel approval for the v1.0 production release on September 3, 2026. This document describes product controls, not legal advice or a guarantee against liability.

## Existing system audit

Before this change, CYPHERYN used a Next-compatible React frontend (vinext), FastAPI/SQLAlchemy backend, PostgreSQL in production, and Auth0 Universal Login mediated by OAuth2 Proxy and Caddy. The API automatically provisioned a `users` row on the first authenticated request. It had organization-scoped, dated authorization records; separate passive and active permissions; administrator-only active authorization; an extra per-run administrator approval for ZAP Active; audit events; and evidence provenance tied to authorization.

The landing page had a responsible-use sentence and links to repository security documents. It did not have public `/terms`, `/responsible-use`, `/privacy`, or `/security` application pages, versioned acceptance records, a first-login acceptance gate, or consistent legal navigation. Auth0 owns the hosted identity registration/login screen; there is no native password-registration form in this repository.

## Public pages and routes

- `/terms` — Terms of Service v1.0
- `/responsible-use` — plain-language Responsible Use Policy v1.0
- `/privacy` — behavior-aligned privacy disclosure v1.0
- `/security` — responsible disclosure and authorized-testing expectations
- `/legal-acceptance` — authenticated, affirmative first-access acceptance screen

Caddy explicitly permits the four reading routes without authentication on both the apex and application domains. They are included in `public/sitemap.xml`. The acceptance route requires Auth0 authentication but not prior agreement acceptance.

## Agreement release configuration

`platform/api/src/intel_platform/legal.py` is authoritative for the current Terms version, Responsible Use version, effective date, and last-updated date. Do not scatter version literals through business logic.

For a material update:

1. Obtain qualified legal review of the revised text.
2. Update the page text and the relevant version/date in `CURRENT_AGREEMENTS`.
3. Update rendered-page and API tests.
4. Deploy the API before or atomically with the frontend.
5. Users without a record matching both current versions will be required to accept again.

## Database and acceptance records

`legal_acceptances` stores `user_id`, `terms_version`, `responsible_use_version`, and `accepted_at`. A unique constraint makes acceptance idempotent for a given pair of versions. No client IP, user agent, or extra personal data is collected for acceptance.

The repository currently uses SQLAlchemy metadata creation plus an additive schema upgrader rather than Alembic. New deployments receive the table through `Base.metadata.create_all`. `platform/api/migrations/20260903_legal_acceptances.sql` is the explicit additive PostgreSQL migration for controlled/manual deployment workflows.

The acceptance record is itself the dedicated legal audit event. It is deliberately not copied into organization-scoped `audit_events`, because acceptance occurs before a user necessarily belongs to an organization and fabricating an organization would weaken tenant semantics.

## Server-side enforcement

Authentication first resolves or provisions a provisional identity. `/api/v1/legal/status` and `/api/v1/legal/acceptance` are the only account-flow endpoints that use that provisional identity. All existing protected endpoints continue to depend on `get_current_user`, which now rejects users without a record for the current agreement versions with HTTP 403 and code `legal_acceptance_required`.

The POST endpoint requires:

- an explicit `accepted: true` value;
- the exact current Terms version; and
- the exact current Responsible Use version.

Unchecked, missing, or stale-version submissions cannot create an acceptance record. Repeating the same valid acceptance is idempotent.

## Frontend and Auth0 flow

Because Auth0 Universal Login is external to this repository, CYPHERYN does not falsely claim to control its registration checkbox. After Auth0 authenticates a new or existing identity, `LegalAcceptanceGate` checks server status before protected application use and sends an unaccepted user to `/legal-acceptance`. The checkbox is unchecked by default, labeled for assistive technology, and the button remains disabled until checked. Policy links open separately so form state is retained.

Operators may additionally add legal links to Auth0 Universal Login branding, but that is an external tenant configuration and does not replace CYPHERYN's server-side acceptance.

## Active-scan safeguards

Existing controls remain in force: dated organization authorization, distinct passive/active scope, administrator approval for active scope, target-type enforcement, and separate per-run administrator approval for ZAP Active. `AuthorizationCreate` now also requires `active_scope_confirmed: true` whenever `active_allowed` is true. The new-investigation interface states that the user owns the target or has authorization and sends the confirmation independently of the active toggle.

Passive collection is not burdened with repeated scan confirmations.

## Privacy alignment

The Privacy Policy describes actual account identifiers, session cookies, organizations, targets, authorizations, provider queries, findings, evidence, audit and operational records, notifications, reports, AI processing choices, retention, backups, and third-party services. It does not claim zero collection or absolute security. Deployment-specific retention periods and controller/contact identity still require operator and counsel input.

## Tests

Automated tests cover rejection before acceptance, rejection of an unchecked submission, stale-version rejection, successful version/timestamp recording, access after acceptance, and server rejection of active authorization without the specific scope confirmation. Frontend rendered tests cover all public legal routes, policy text, acceptance controls, and footer links.

## Remaining legal-review items

- Governing law, venue, operator legal identity, age/eligibility, termination, warranty, indemnity, export/sanctions, and paid-service terms are intentionally not fabricated.
- Deployment-specific privacy controller, contact, retention schedule, subprocessors, international transfers, and statutory rights need jurisdiction-aware review.
- Auth0 Universal Login branding should link to the published policies.
- Preserve counsel's approved copy and release record outside the application repository, and obtain renewed review before material policy changes.
