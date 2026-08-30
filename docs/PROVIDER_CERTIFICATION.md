# Supported Provider Certification

CYPHERYN uses `SUPPORTED` as a test-backed engineering claim, not as a synonym for
"an adapter exists." The five providers in the supported set are VirusTotal, Shodan,
AlienVault OTX, Censys, and abuse.ch ThreatFox.

## Certification contract

Every supported provider must independently pass the same deterministic contract:

| Control | Required proof |
| --- | --- |
| Request construction | HTTPS endpoint, correct target encoding, expected credential placement, and no credential in the static endpoint |
| Missing credentials | Collection refuses to construct an authenticated request |
| Authentication | HTTP 401 and 403 are rejected and represented by a credential-safe error |
| Throttling | HTTP 429 is rejected and remains visible to retry/observability controls |
| Invalid transport data | Non-JSON success responses are rejected |
| Invalid provider schema | Provider-specific malformed JSON objects are rejected even when HTTP status is 200 |
| Timeout | Transport timeouts propagate and expired deadlines fail before network I/O |
| Cancellation | Cancellation fails before network I/O and interrupts response streaming |
| Normalization | A realistic provider response produces provider-specific security meaning |
| Redaction | Credentials are absent from normalized evidence and persisted error text |
| Provenance | Results retain provider, target, target type, non-synthetic status, and a SHA-256 response fingerprint |

The matrix is enforced by
`platform/api/tests/test_provider_contracts.py`. Its first test compares the cases with
`SUPPORTED_CONTRACT_PROVIDERS`; adding a provider to the supported tier without a complete
case fails CI. Ordinary tests use `httpx.MockTransport` and never call third parties.

## Security-signal normalization

- VirusTotal records verdict counts, reputation context, categories, and tags.
- Shodan records public TCP services, CVE associations, organization, ASN, country, and
  observation time.
- AlienVault OTX records pulse matches and malware-family associations.
- Censys records public services, software, network ownership, location, operating system,
  DNS names, and candidate findings for unexpected exposure.
- ThreatFox records IOC matches, threat type, confidence, malware associations, tags, and
  source references.

Provider payloads are bounded to 1 MB and associations are bounded before persistence.
An HTTP 200 is insufficient: each supported adapter validates the minimum response shape
needed by its normalizer.

## Readiness is separate

Certification does not mean a provider is currently usable. The UI and API continue to
report the operational progression independently:

**Supported → Installed → Configured → Healthy → Live Verified**

`Live Verified` still requires a successful real collection and retains its timestamp.
Deterministic certification neither creates nor refreshes that timestamp.

## Running the certification suite

From `platform/api`:

```bash
.venv/bin/pytest tests/test_provider_contracts.py
```

The complete API suite runs the same tests in hosted CI. No real provider credentials are
required and test credential values are synthetic.

## Controlled live verification

Live verification is an operational check and must never run in ordinary pull-request CI.
Use a dedicated non-production provider account with least-privilege credentials, provider
spend/rate limits, and an owned or explicitly authorized benign indicator. Never use a real
person's identity, an unrelated public IP, malware, or customer data merely to refresh a
status badge.

For each supported provider:

1. Confirm the provider terms permit the planned query and record the target authorization.
2. Save the credential through CYPHERYN's provider configuration; never put it in a shell
   command, test fixture, screenshot, ticket, or CI log.
3. Run one bounded collection against the controlled indicator and confirm that the job
   completes, provenance contains the expected provider and target, and persisted/logged
   output contains no credential.
4. Record the provider, account/environment, target class (not a secret target value), job
   ID, result, verifier, and UTC timestamp. The product's `Live Verified` timestamp must
   match the successful collection rather than the documentation date.
5. Exercise an invalid synthetic credential only in a disposable provider account when the
   provider permits it; otherwise rely on the deterministic authentication contract test.

Run this procedure before a release candidate and at least every 30 days for providers
represented as Live Verified. A failed or stale check must not be hidden: retain the last
success timestamp, expose the current health result, investigate the failure, and avoid
claiming continued availability. Revoke the dedicated credentials when verification is no
longer required.
