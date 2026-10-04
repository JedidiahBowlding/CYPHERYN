# Security Execution Authority and Network Binding

## Purpose

CYPHERYN separates a policy decision from permission to execute a consequential operation. An
authoritative `ALLOW` may create a short-lived database-backed authorization lease. Before network
execution, the workload calls:

```text
POST /api/v1/security/decisions/{decision_id}/validate
```

The workload supplies the action, capability, environment, resource scope, intended destination,
and the exact IP address it will contact. Validation rechecks the current database state, current
DNS result, operation fingerprint, lease lifetime, and optional usage limit.

## Revocation generations

The lease snapshots monotonic generations for:

- workload client;
- protected agent;
- capability grant;
- security destination; and
- active deterministic policy.

Credential rotation, status changes, grant revocation, destination trust changes, and policy
replacement increment the applicable generation. A mismatch invalidates an earlier decision even
when its time limit has not expired.

## Validity and consumption

The default authorization lifetime is 60 seconds and the DNS binding lifetime is 30 seconds. Both
are configurable within intentionally narrow bounds. High-consequence capabilities
(`commerce.purchase`, `email.send`, `database.write`, and `code.execute`) receive at most one use
when policy has already produced an authoritative `ALLOW`. Validation uses a row lock before
consumption so concurrent replays cannot both consume a single-use lease.

SHADOW results, denials, quarantines, and approval-required results do not receive execution
authority. A shadow-mode effective `ALLOW` therefore cannot be promoted into an execution lease.

## Network enforcement contract

The client or a future CYPHERYN-controlled egress proxy must:

1. Evaluate the exact operation and destination.
2. Select one address from the receipt's approved address set.
3. Open or prepare a connection pinned to that address without independent DNS selection.
4. Send that exact address and operation to final validation immediately before use.
5. Verify that validation returns `valid: true`.
6. Use TLS hostname verification and SNI for the receipt's canonical hostname—not the IP literal.
7. Reject every cross-origin redirect and request a new CYPHERYN evaluation for the new origin.
8. For same-origin redirects, retain the same pinned address and repeat validation if the lease or
   DNS receipt may have expired.

The validator conservatively denies when any current DNS answer is non-public or when the current
address set differs from the receipt. This can deny legitimate DNS rotation, but it prevents the
client from selecting an unevaluated address.

## Redirect rules

- Same scheme, host, and port: the path may change; the connection remains bound to the approved
  address set and validity window.
- Any different scheme, host, or port: a new evaluation is mandatory.
- Public-to-private, loopback, link-local, RFC1918, IPv6 loopback, IPv6 unique-local, metadata, and
  mixed public/private resolutions: denied in full.

## TOCTOU boundaries

CYPHERYN guarantees that final validation checks current database authority, current policy
integrity, current DNS resolution, the exact operation fingerprint, and the proposed connected IP
inside one database transaction. It does not make a direct third-party network call atomic with
that transaction.

A revocation can still occur after final validation and before or during a connection made by an
untrusted client. The strongest deployment pattern is a CYPHERYN-controlled egress proxy that owns
both final validation and the pinned socket. Until that proxy exists, clients must minimize the
interval, pin the address, avoid connection reuse beyond lease expiry, and revalidate redirects.
Revocation after an external service has already accepted an operation cannot undo that external
side effect.

## Query-path review

The evaluator has no N+1 loop. Its reads cover workload identity, agent binding, idempotency,
nonce replay, destination, capability grant, and active policy. Its writes create the decision,
authorization lease, integrity links, audit event, and freshness timestamps.

Safe future reductions include combining idempotency and nonce lookups, rate-limiting freshness
timestamp writes, and sealing new records before their initial insert where database semantics
allow. Client, agent, grant, destination, and policy freshness reads must not be cached across final
authorization because doing so would weaken revocation behavior.

Performance measurements are diagnostic local baselines, not production SLOs. PostgreSQL load and
an egress-proxy implementation require their own capacity test before production enforcement.
