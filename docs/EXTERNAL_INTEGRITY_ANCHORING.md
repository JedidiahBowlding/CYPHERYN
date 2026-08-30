# External Integrity Anchoring

CYPHERYN automatically creates signed, independently retained checkpoints for every
investigation that contains evidence. This makes later evidence-chain rewriting detectable
against a checkpoint outside PostgreSQL.

## Runtime boundary

- `anchor-key-init` is a short-lived, capability-dropped initializer. It creates the first
  Ed25519 key only when no active key exists, then exits.
- The normal API never receives the private-key mount. It reads the anchor store read-only
  so JSON and PDF exports can reference the latest checkpoint.
- The worker receives the key directory read-only and the anchor destination read-write.
- Private keys never enter PostgreSQL, evidence payloads, logs, reports, or API responses.
- Anchor and integrity-export files are created exclusively and changed to read-only. A
  repeated filename is rejected rather than overwritten.

The default local paths are under `platform/.runtime/`, which is excluded from Git. For a
production trust boundary, set `PLATFORM_ANCHOR_STORE_DIR` to storage administered outside
the CYPHERYN host, such as an immutable NFS target, synchronized WORM volume, or a mount
backed by object-lock storage. Filesystem permissions are defense in depth; the external
storage system must enforce retention and deletion policy independently.

## Schedule

Anchoring is enabled by default in Compose. The worker checks on every supervisor cycle and
creates a checkpoint when an investigation first gains evidence, when its evidence-chain
head changes, or when the configured interval has elapsed. The default interval is 1,440
minutes (daily).

```env
PLATFORM_INTEGRITY_ANCHOR_ENABLED=true
PLATFORM_INTEGRITY_ANCHOR_INTERVAL_MINUTES=1440
PLATFORM_ANCHOR_KEY_DIR=./platform/.runtime/anchor-keys
PLATFORM_ANCHOR_STORE_DIR=./platform/.runtime/anchors
```

Each checkpoint consists of two immutable files:

- `*.anchor.json`: checkpoint digest, Ed25519 public key, key ID, and signature.
- `*.integrity.json`: the complete canonical evidence chain needed for offline verification.

The anchor file is written last and acts as the bundle commit marker.

## Rotate the signing key

Rotation generates a new active key without deleting prior keys. Historical anchors retain
their public keys and key identifiers, so they remain verifiable.

```bash
docker compose run --rm anchor-key-init \
  python -m intel_platform.integrity_anchor initialize /keys /anchors --rotate
docker compose restart worker
```

Back up old public keys or anchor files in the independent trust domain before rotating.
Never delete an old private key until the applicable evidence-retention period has passed
unless organizational policy deliberately makes historical re-signing impossible.

### Key operations runbook

1. Assign separate custodians for the signing-key store and independent anchor store. The
   worker service account may read the active private key but must not administer either
   store.
2. Before rotation, copy the current public key, its key ID, and the latest verified anchor
   bundle to independently administered, retention-locked storage. Private-key backups must
   be encrypted and access-controlled; do not place them in the database, repository, CI
   artifacts, or ordinary host backups.
3. Run the rotation command, restart the worker, force or await a new checkpoint, and verify
   it offline using the newly distributed expected key ID. Record the operator, time, old
   key ID, new key ID, verification result, and change ticket.
4. Distribute the public key and key ID through an authenticated channel independent of the
   CYPHERYN application. Verifiers should pin the expected key ID rather than trusting a key
   supplied only inside the bundle being checked.

If a private key may be compromised, disable anchoring, preserve the key and anchor stores
read-only for investigation, rotate from a trusted administration host, revoke the old key
in the external verifier registry, and publish the compromise interval. Never rewrite or
re-sign historical anchors to conceal the event.

At least quarterly, perform a restore drill on a separate machine: restore the public-key
registry and a random historical bundle, run offline verification, and record the result.
Also test recovery from loss of the active private key. Recovery creates a new key and a
documented continuity break; it must not silently impersonate the lost key.

## Offline verification

Copy an anchor bundle to a machine outside the CYPHERYN trust domain and run:

```bash
cd platform/api
python -m intel_platform.integrity_anchor verify \
  /independent-store/checkpoint.integrity.json \
  /independent-store/checkpoint.anchor.json \
  --expected-key-id ed25519:YOUR_TRUSTED_KEY_ID
```

Verification checks the Ed25519 signature, checkpoint digest, expected key identity,
record hashes, chain continuity, scope, record count, and chain head.

## Export behavior

Investigation JSON exports embed the latest public anchor metadata in
`data.integrity_anchor`. Technical PDF reports contain an External integrity anchor table
with the signing key, checkpoint time, chain head, record count, and filenames. The paired
integrity export remains in the independent store so an auditor can verify the report's
reference without access to the live database.

## Security limitation

Anchoring is tamper evidence, not absolute prevention. An attacker controlling CYPHERYN,
the signing key, and the external destination can replace future checkpoints. Independent
retention, restricted key access, monitored rotation, and periodic offline verification are
what create the separate trust domain.
