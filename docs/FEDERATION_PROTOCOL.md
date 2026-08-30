# Federation Protocol v1

Status: **EXPERIMENTAL**. Protocol identifier: `cypheryn-federation-v1`.

Endpoints use `/api/federation/v1/`. `identity`, `capabilities`, and `health` describe a
node. Organization-scoped peer endpoints require organization-administrator authentication.
Outbound creation requires the same local privilege. Inbound assertions authenticate by
their pinned issuer key and signature and never reuse general administrative endpoints.

Signatures cover UTF-8 JSON serialized with sorted keys and compact separators, excluding
only the `signature` field. The algorithm is Ed25519. Assertion and nonce IDs are unique.
Times are timezone-aware ISO 8601. Subject and evidence values are lowercase SHA-256
fingerprints; raw objects are outside the schema.

Delivery is at-least-once, while persistence is effectively once through assertion-ID and
issuer/nonce uniqueness. Duplicate delivery returns a replay rejection. Unknown protocol
versions, fields, keys, issuers, and algorithms are rejected. Version negotiation is not
implicit; a future version requires a new explicit verifier while v1 remains inspectable.

Corroboration groups equal subject fingerprints and reports independent issuers, source
diversity, ages, severities, and agreement. It never converts votes into truth or a
statistical confidence claim.
