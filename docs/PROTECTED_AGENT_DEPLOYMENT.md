# Protected Agent Deployment Checklist

This checklist is a release gate, not an automatic deployment script.

## Before rollout

- [ ] Build the exact tagged `cypheryn-egress-proxy` and `cypheryn-protected-agent-pilot` images.
- [ ] Record immutable image digests; generate SPDX SBOMs and pass fixable High/Critical scanning.
- [ ] Create a dedicated proxy service identity. Never use a human credential.
- [ ] Generate server and proxy-client certificates from separate, protected CA material.
- [ ] Store private keys outside the image and mount them read-only with least privilege.
- [ ] Verify secret ownership/mode lets runtime UID 10001 read keys without granting world read.
- [ ] Confirm server SAN, client EKU, chain, expiry, and rotation calendar.
- [ ] Deploy the route-limited mTLS control-plane gateway and validate its Caddy configuration.
- [ ] Confirm the gateway exposes only validation, authority consumption, and receipt routes.
- [ ] Create an internal/default-deny protected-agent network with only TCP/8020 to the proxy.
- [ ] Give proxy replicas backend/control-plane, protected-agent, approved DNS, and managed egress paths only.
- [ ] Confirm agents have no public bridge, host network, Docker socket, metadata route, or alternate resolver.
- [ ] Confirm PostgreSQL is healthy and migrations are current before enabling traffic.
- [ ] Configure at least three independent proxy replicas with distinct observable replica IDs.
- [ ] Enable the `trusted-egress` profile and only then the selected protected-agent profile.
- [ ] Validate `/health`, `/metrics`, control-plane health, receipts, and dashboard visibility.
- [ ] Run approved, denied, expired, revoked, DNS-failure, TLS-failure, and single-use tests.
- [ ] Run the network-bypass matrix from inside the actual protected-agent container.
- [ ] Configure the alerts documented in `TRUSTED_AGENT_EGRESS_PROXY.md`.

## Safe rollback

1. Stop new protected operations and drain in-flight work within its bounded deadline.
2. Stop the protected agent if the proxy or authoritative validation is unhealthy.
3. Keep the protected-agent network internal/default-deny.
4. Roll back proxy/gateway images or certificates, then repeat health and security probes.
5. Resume only after mTLS, final validation, receipt persistence, and network isolation pass.

Rollback must cause protected external operations to stop. It must never restore direct internet access.

## Hosted CI

Before merging, run the branch-protection workflows on the exact commit. Local checks cannot reproduce GitHub OIDC identity, hosted runner isolation, repository protection rules, provenance attestation, or release-event permissions; those remain hosted evidence requirements.
