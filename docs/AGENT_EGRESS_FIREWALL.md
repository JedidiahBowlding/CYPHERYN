# Agent Egress Firewall

The Agent Egress Firewall evaluates development-agent outbound actions before publication. It is deterministic, local-first, organization-scoped, and independent of model prompts.

## Enforcement sequence

1. Register a protected agent with a human owner.
2. Normalize a supported GitHub CLI command or submit a structured action.
3. Submit artifact bytes for local scanning as base64. The API verifies MIME magic and never trusts the extension.
4. Receive `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, `ALLOW_WITH_REDACTION`, or `QUARANTINE`.
5. If required, an organization administrator other than the requester approves the exact action.
6. Execute outside CYPHERYN using least-privilege credentials only when permitted.
7. Submit observed repository, visibility, artifact locations, and object identifiers.
8. Export and independently compare the recorded SHA-256 event evidence.

## Local setup

Configure `.env` from `.env.example`, then rebuild the API so Tesseract is present:

```bash
docker compose up -d --build postgres api frontend
curl -H 'X-Dev-Subject: local-operator' \
  http://127.0.0.1:8000/api/v1/egress/health
```

The development header works only when development identity is explicitly enabled. The core API binding is loopback-only. Do not publish the guard directly. Production requests must pass through CYPHERYN OIDC and organization RBAC.

Important settings:

- `PLATFORM_EGRESS_GUARD_ENABLED`
- `PLATFORM_EGRESS_MAX_ARTIFACT_BYTES`
- `PLATFORM_EGRESS_SCAN_TIMEOUT_SECONDS`
- `PLATFORM_EGRESS_RATE_LIMIT_PER_MINUTE`
- `PLATFORM_EGRESS_MANDATORY_SCANNERS`
- `PLATFORM_EGRESS_ORGANIZATION_PATTERNS`

Patterns are regular expressions, not secret values. Optional templates for AI Grant Hub, Nova Steward, Veloryn/Tokenquity, and CYPHERYN are created disabled in the default policy and must be deliberately configured and activated.

## GitHub integration

The verified parser recognizes:

- `gh repo create`
- `gh repo edit --visibility`
- `gh release create` and `gh release upload`
- `gh api`
- `gh pr create`
- `gh issue create`
- `git push`

Call `POST /api/v1/egress/github/normalize` with the raw command. This parser does not run the command. Submit the returned structure to `POST /api/v1/egress/evaluate` with any artifacts. Unsupported syntax returns 422 and must not be executed through the protected path.

## Approval and evidence

An approval binds the agent, actor, action type, destination, repository, requested visibility, artifact hashes, working directory, correlation ID, and policy version through canonical hashing. The API stores only the approval-token hash. Tokens expire and are consumed once. Mutation, expiry, replay, and self-approval fail closed.

`GET /api/v1/egress/events/{id}/evidence` returns machine-readable evidence plus the event hash and previous hash. Human-readable event detail is available on the Egress dashboard. Raw secret values are intentionally absent.

## Retention and incident response

Egress records follow the deployment database retention policy. Quarantine references point into the protected quarantine volume; an operator must separately define deletion and backup periods appropriate to their organization.

For an execution mismatch:

1. Disable or rotate the agent credential.
2. Preserve the event export and signed integrity checkpoint.
3. Review the external repository or release without deleting evidence.
4. Change visibility or remove an artifact only with explicit human approval.
5. Investigate whether the client bypassed mediation.
6. Close the high-severity egress finding after verified containment.

## Rollback

Stop clients from calling the egress routes before rolling back application code. Existing tables are additive and may remain for evidence retention. Do not drop egress tables until evidence has been exported and retention obligations are satisfied. If the feature is disabled, protected clients must fail closed rather than execute outbound actions.

## Troubleshooting

- `MANDATORY_SCANNER_UNHEALTHY`: restore the configured local scanner; do not bypass it.
- `ARTIFACT_UNINSPECTABLE`: check MIME, size, Tesseract availability, and timeout; keep the file quarantined.
- `UNKNOWN_OUTBOUND_DESTINATION`: an administrator must review policy; agents cannot add destinations.
- Approval rejected after a change: expected behavior; reevaluate the final payload.
- Integrity verification failed: preserve the database and logs, stop privileged writes, and validate external signed checkpoints.

## Limitations

This MVP does not guarantee detection of every sensitive artifact. It does not intercept unintegrated tools, automatically delete GitHub content, or claim live verification for scanners that have not completed a successful scan. PDF files are quarantined until a hardened parser worker is available. Combine the guard with least privilege, sandboxing, private repositories, credential isolation, branch protection, and network controls.
