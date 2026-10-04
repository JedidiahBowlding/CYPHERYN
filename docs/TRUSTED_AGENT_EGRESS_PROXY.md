# Trusted Agent Egress Proxy

## Purpose

The trusted proxy closes the gap between authorization and execution: the component that performs final validation also owns the approved TLS socket. It is not a generic forward proxy and it does not accept raw proxy credentials, arbitrary methods, private destinations, or unrestricted redirects.

## Opt-in startup

```bash
docker compose --profile trusted-egress up -d --build egress-proxy
```

The runtime is disabled by default. The Compose profile explicitly enables it only inside its separately hardened container. Agents continue using the existing client-enforced contract until their configuration points protected calls at `http://egress-proxy:8020/v1/proxy` and their network is isolated.

## Enforcement deployment

1. Place protected workloads only on the internal `protected-agents` network.
2. Do not attach them to `edge`, `proxy-egress`, host networking, or a public bridge.
3. Allow workload traffic to TCP/8020 on the proxy only.
4. Let only the proxy reach the control plane and public egress.
5. Apply equivalent default-deny Kubernetes NetworkPolicy or host policy in production.
6. Run at least two stateless proxy replicas. PostgreSQL remains the authority and serializes one-time consumption.

Core Compose demonstrates the network topology but does not attach an example untrusted workload and does not modify host firewall rules. Therefore host-level bypass resistance must be certified in the target orchestrator before production enforcement is claimed.

## Request contract

Calls require the normal OIDC client-credentials bearer token. Identity is never accepted from `agent_id`, a decision identifier, or authority metadata supplied by the caller. The request supplies the existing decision ID, exact action/capability/environment/resource scope, HTTPS URL, method, bounded headers/body, and correlation ID. The body is base64 encoded; streaming is intentionally unsupported.

## Limits and outcomes

Request, response, header, redirect, connect, read, and validation limits are environment-configurable. The proxy exposes `/health` and secret-free Prometheus metrics at `/metrics`. Durable receipts appear in the Agent Egress dashboard. Cross-origin redirects return `REDIRECT_REQUIRES_REAUTHORIZATION`; clients must obtain a new evaluation for the new origin.

## Migration and rollback

Migrate one agent class at a time: enable the profile, verify receipt creation, enforce its proxy-only network, then remove direct egress. Roll back by restoring that workload's prior network policy and client-enforced pin-and-validate path; disabling the proxy never creates an automatic direct-access fallback.

## Kubernetes example policy intent

Use namespace default-deny egress. Allow protected-agent pods to the proxy service on 8020 only. Allow proxy pods to the control-plane service, approved DNS, and the internet according to the cluster egress gateway policy. Namespace labels and service selectors must be deployment-specific; this repository does not ship permissive placeholder selectors.
