# ADR 011: Separately trusted Agent Egress Proxy

## Status

Accepted for opt-in certification. The proxy is feature-flagged and is not part of the default deployment.

## Context

The control plane already issues short-lived, DNS-bound execution authority and supports authoritative final validation. Client enforcement still left the last socket under the control of the protected workload. A compromised workload could validate one address and connect another way.

## Decision

CYPHERYN provides a separately deployable egress proxy. It authenticates the existing workload bearer token by presenting that token to the control plane, resolves and validates the destination itself, atomically consumes single-use authority through PostgreSQL-backed final validation, and then opens a socket pinned to one approved address. TLS still uses the canonical hostname for SNI and certificate verification.

The proxy accepts HTTPS only. `GET` and `HEAD` require `web.read`; mutating methods require `web.write`. Unsupported methods, sensitive outbound headers, secret or uninspectable bodies, non-public or mixed DNS results, cross-origin redirects, excessive responses, and unavailable authoritative services fail closed. Streaming is excluded from this phase.

Receipts are stored by the control plane. Identity, tenant, agent, decision, and canonical destination are derived from authoritative state rather than request fields. Receipts contain hashes, classifications, counts, status, timing, and outcomes—not credentials or private bodies.

## Trust assumptions

- The proxy runtime, its image, network namespace, CA store, and control-plane route are trusted.
- PostgreSQL provides serialization for single-use authority consumption.
- The OIDC issuer and control-plane workload authentication remain authoritative.
- Protected workloads cannot reach the public internet except through the proxy in enforcing deployments.
- DNS is untrusted input. Every answer must be public and the connected address must remain in the authorization binding.

## Network model

Protected workloads join an internal-only `protected-agents` network. The proxy joins that network, the internal control-plane network, and a dedicated `proxy-egress` network. Workloads must not join `edge` or `proxy-egress`. Kubernetes deployments apply default-deny egress and allow only DNS to an approved resolver plus TCP/8020 to the proxy. Host firewall changes are deliberately not made by development Compose.

## Remaining atomicity boundary

Final validation and single-use consumption occur immediately before the socket call in the same trusted process, with no asynchronous work between them. PostgreSQL transaction serialization prevents two replicas from consuming one authority. Revocation can still race in the final machine-instruction interval after validation commits and before `connect(2)`. Eliminating that interval would require a transactionally coupled network enforcement primitive; the proxy materially narrows and removes client control of the race but does not claim impossible atomicity.

## High availability and failure behavior

Proxy replicas are stateless. Correctness lives in the control plane and PostgreSQL. Control-plane, validation, receipt, DNS, TLS, or upstream failures never grant direct access. Receipt creation is required before validation; receipt finalization failure causes the caller to receive an error even if an upstream operation already completed, and operators reconcile the pending receipt through metrics and audit logs.

## Consequences

Protected mode adds DNS, validation, receipt, and TLS latency and requires explicit network-policy deployment. Existing client-enforced pin-and-validate remains available during migration. The feature flag avoids silently changing existing installations.
