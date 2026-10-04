# Trusted Agent Egress Proxy

## Purpose

The trusted proxy closes the gap between authorization and execution: the component that performs final validation also owns the approved TLS socket. It is not a generic forward proxy and it does not accept raw proxy credentials, arbitrary methods, private destinations, or unrestricted redirects.

## Opt-in startup

```bash
docker compose --profile trusted-egress up -d --build egress-proxy
```

The runtime is disabled by default. The Compose profile explicitly enables it only inside its separately hardened container. The optional `trusted-egress-pilot` profile supplies a generic read-only pilot agent. Agents continue using the existing client-enforced contract until their configuration points protected calls at `http://egress-proxy:8020/v1/proxy` and their network is isolated.

## Enforcement deployment

1. Place protected workloads only on the internal `protected-agents` network.
2. Do not attach them to `edge`, `proxy-egress`, host networking, or a public bridge.
3. Allow workload traffic to TCP/8020 on the proxy only.
4. Let only the proxy reach the control plane and public egress.
5. Apply equivalent default-deny Kubernetes NetworkPolicy or host policy in production.
6. Run at least two stateless proxy replicas. PostgreSQL remains the authority and serializes one-time consumption.

Core Compose demonstrates the network topology but does not attach an example untrusted workload and does not modify host firewall rules. Therefore host-level bypass resistance must be certified in the target orchestrator before production enforcement is claimed.

## Request contract

Calls require the normal OIDC client-credentials bearer token. Identity is never accepted from `agent_id`, a decision identifier, or authority metadata supplied by the caller. The request supplies the existing decision ID, exact action/capability/environment/resource scope, HTTPS URL, method, bounded headers/body, and correlation ID. The body is base64 encoded; streaming is intentionally unsupported. A non-empty body must match the `body_sha256` value included in the evaluated `resource_scope`, binding authorization to the exact bytes that are sent.

## Limits and outcomes

Request, response, header, redirect, connect, read, and validation limits are environment-configurable. The proxy exposes `/health` and secret-free Prometheus metrics at `/metrics`. Durable receipts appear in the Agent Egress dashboard. Cross-origin redirects return `REDIRECT_REQUIRES_REAUTHORIZATION`; clients must obtain a new evaluation for the new origin.

## Proxy service identity and mTLS

`egress-control-plane` is the only gateway from the proxy to the security endpoints. The proxy and gateway share an internal `proxy-control` network, while the API is not directly reachable from the proxy. The gateway requires a dedicated proxy client certificate, validates the proxy-client CA, and exposes only final validation, authority-consumption receipt, and receipt-completion routes. The proxy validates the server CA, service hostname, validity interval, and server EKU. There is no plaintext or `verify=false` fallback in production.

Create development certificates with `python scripts/egress_pki.py init platform/.runtime/egress-mtls`. The files must be readable by the proxy/gateway runtime UID 10001 without becoming world-readable; on Linux, provision the secret directory through the orchestrator or set owner/group and `0600`/`0640` modes before startup. For rotation, run `prepare-rotation`, deploy the generated overlap trust bundle plus new server and client leaf certificates, restart the gateway and proxies, and verify both generations. Then run `complete-rotation`, deploy the new-only trust bundle, restart, and confirm the old client is rejected. A compromised certificate requires immediate completion without an overlap window and revocation at the deployment trust layer.

HTTP connection pooling between the proxy and the control plane is intentionally disabled. A fresh verified mTLS connection for every final validation and receipt transition keeps certificate rotation and revocation behavior immediate and prevents connection state from outliving authorization changes. Upstream external connections are also not pooled; each single-use authority owns one bounded socket sequence.

## Pilot identity

The pilot is `protected-read-agent`, a non-root generic CYPHERYN-compatible workload using an OIDC client-credentials token mounted read-only at `/run/secrets/pilot-workload-token`. It has only `web.read`, may use only policy-approved HTTPS destinations, runs solely on the internal `protected-agents` network, and can reach external destinations only through `egress-proxy:8020`. Its expected traffic is an evaluation POST through the route-limited `agent-control-plane:8015` gateway followed by a proxy POST containing a GET/HEAD request. The API itself is not attached to the protected-agent network. The pilot has no host networking, Docker socket, repository mount, write capability, or direct egress network.

## Migration and rollback

Migrate one agent class at a time: enable the profiles, verify mTLS and receipt creation, enforce its proxy-only network, then remove direct egress. Safe rollback stops the protected workload or disables protected external operations while leaving the internal-only network in place. Never restore a public bridge, host networking, direct DNS, or direct internet as a rollback mechanism. Disabling the proxy never creates an automatic direct-access fallback.

## Recommended alerts

- All proxy replicas unavailable or fewer than the deployment minimum healthy.
- Control-plane mTLS/availability failures or sustained final-validation latency.
- Abnormal DENY, expired, consumed, revoked, policy-changed, or capability-changed rates.
- DNS safety, resolution-binding, TLS verification, or redirect reauthorization failures.
- Receipt start/completion persistence failures or a growing incomplete-receipt count.
- Protected-agent network flows to anything except the proxy service.
- Proxy p95 latency, CPU, memory, file descriptor, or database-wait degradation.
- Revocation tests that unexpectedly validate or old certificates accepted after cutover.

## Kubernetes example policy intent

Use namespace default-deny egress. Allow protected-agent pods to the proxy service on 8020 only. Allow proxy pods to the control-plane service, approved DNS, and the internet according to the cluster egress gateway policy. Namespace labels and service selectors must be deployment-specific; this repository does not ship permissive placeholder selectors.
