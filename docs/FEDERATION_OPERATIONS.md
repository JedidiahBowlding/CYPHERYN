# Federation Operations

Status: **EXPERIMENTAL**.

Federation defaults to disabled. Enable it only on an isolated development node with
`PLATFORM_FEDERATION_ENABLED=true`, initialize the Ed25519 identity using
`python -m intel_platform.federation initialize <key-path>`, and protect that path as a
read-only runtime secret. Back it up encrypted and separately from the database.

The two-node laboratory runs with:

```bash
docker compose -f compose.federation.yaml up --build
```

Node A listens only on `127.0.0.1:8101`; Node B on `127.0.0.1:8102`. They use independent
PostgreSQL volumes and independent key volumes. Compare `/api/federation/v1/identity`
documents out of band before enrolling either peer. Change `pending` to `trusted` only after
node ID, key ID, and public key match.

Suspension immediately blocks new assertions and is reversible. Revocation records a time
and blocks current trust. Preserve the old public key and assertions for historical
verification. A rotated key is treated as a new node identity until an authenticated key-
transition protocol is implemented.

Back up databases and keys independently. A node restart retains replay nonces and received
assertions. Loss of a peer never blocks local CYPHERYN. Monitor `cypheryn_federation_*`
metrics and investigate signature, replay, expiration, and unknown-issuer failures without
logging payloads or keys beyond public identifiers.
