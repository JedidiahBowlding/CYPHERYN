from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import FederatedAssertion, FederationPeer, FederationReplayNonce

PROTOCOL_VERSION = "cypheryn-federation-v1"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_ASSERTION_BYTES = 64 * 1024
MAX_LIFETIME = timedelta(days=30)
FINGERPRINT_FIELDS = {"subject_fingerprint", "evidence_fingerprint"}
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
ASSERTION_TYPES = {"indicator_assessment", "exposure_observation", "threat_association"}
SUBJECT_TYPES = {"domain", "ip_address", "url", "sha256", "certificate", "service"}


class FederationVerificationError(ValueError):
    pass


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(public_key_bytes(key)).decode("ascii")


def key_id(key: Ed25519PublicKey) -> str:
    return f"ed25519:{hashlib.sha256(public_key_bytes(key)).hexdigest()}"


def node_id(key: Ed25519PublicKey) -> str:
    return f"cypheryn-node:{hashlib.sha256(public_key_bytes(key)).hexdigest()}"


def decode_public_key(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32:
            raise ValueError("invalid Ed25519 public-key length")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise FederationVerificationError("Invalid peer public key") from exc


def generate_node_key(path: Path) -> dict[str, str]:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite node identity key: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass
    public_key = private_key.public_key()
    return {"node_id": node_id(public_key), "key_id": key_id(public_key)}


def load_node_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise FederationVerificationError("Node identity key must be Ed25519")
    return key


def identity_document(private_key: Ed25519PrivateKey, display_name: str) -> dict[str, Any]:
    public_key = private_key.public_key()
    return {
        "protocol_version": PROTOCOL_VERSION,
        "node_id": node_id(public_key),
        "display_name": display_name,
        "public_key": public_key_b64(public_key),
        "key_id": key_id(public_key),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "capabilities": ["signed-assertions-v1", "replay-protection-v1"],
    }


def _unsigned(assertion: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in assertion.items() if key != "signature"}


def _parse_time(value: Any, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise FederationVerificationError(f"Invalid {field}") from exc
    if parsed.tzinfo is None:
        raise FederationVerificationError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_shape(assertion: dict[str, Any]) -> None:
    required = {
        "protocol_version",
        "assertion_id",
        "issuer_node_id",
        "issuer_key_id",
        "issued_at",
        "expires_at",
        "assertion_type",
        "subject_type",
        "subject_fingerprint",
        "evidence_fingerprint",
        "source_category",
        "confidence",
        "severity",
        "observation_time",
        "nonce",
        "signature_algorithm",
        "signature",
    }
    if set(assertion) - (required | {"evidence_checkpoint"}):
        raise FederationVerificationError("Assertion contains unsupported fields")
    if required - set(assertion):
        raise FederationVerificationError("Assertion is missing required fields")
    if assertion["protocol_version"] != PROTOCOL_VERSION:
        raise FederationVerificationError("Unsupported federation protocol version")
    if assertion["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise FederationVerificationError("Unsupported signature algorithm")
    if assertion["assertion_type"] not in ASSERTION_TYPES:
        raise FederationVerificationError("Unsupported assertion type")
    if assertion["subject_type"] not in SUBJECT_TYPES:
        raise FederationVerificationError("Unsupported subject type")
    if assertion["severity"] not in SEVERITIES:
        raise FederationVerificationError("Unsupported severity")
    if not isinstance(assertion["confidence"], int) or not 0 <= assertion["confidence"] <= 100:
        raise FederationVerificationError("Confidence must be an integer from 0 to 100")
    for field in FINGERPRINT_FIELDS:
        value = assertion[field]
        if not isinstance(value, str) or len(value) != 64:
            raise FederationVerificationError(f"{field} must be a SHA-256 fingerprint")
        try:
            int(value, 16)
        except ValueError as exc:
            raise FederationVerificationError(f"{field} must be hexadecimal") from exc
    if not isinstance(assertion["nonce"], str) or not 16 <= len(assertion["nonce"]) <= 128:
        raise FederationVerificationError("Invalid assertion nonce")


def create_assertion(
    private_key: Ed25519PrivateKey,
    *,
    assertion_type: str,
    subject_type: str,
    subject_fingerprint: str,
    evidence_fingerprint: str,
    source_category: str,
    confidence: int,
    severity: str,
    observation_time: datetime,
    evidence_checkpoint: dict[str, Any] | None = None,
    now: datetime | None = None,
    lifetime: timedelta = timedelta(days=7),
) -> dict[str, Any]:
    issued_at = (now or datetime.now(UTC)).astimezone(UTC)
    if lifetime <= timedelta(0) or lifetime > MAX_LIFETIME:
        raise ValueError("Assertion lifetime must be positive and no longer than 30 days")
    public_key = private_key.public_key()
    assertion: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "assertion_id": f"urn:uuid:{uuid.uuid4()}",
        "issuer_node_id": node_id(public_key),
        "issuer_key_id": key_id(public_key),
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + lifetime).isoformat(),
        "assertion_type": assertion_type,
        "subject_type": subject_type,
        "subject_fingerprint": subject_fingerprint.lower(),
        "evidence_fingerprint": evidence_fingerprint.lower(),
        "source_category": source_category[:100],
        "confidence": confidence,
        "severity": severity,
        "observation_time": observation_time.astimezone(UTC).isoformat(),
        "nonce": secrets.token_urlsafe(24),
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }
    if evidence_checkpoint is not None:
        assertion["evidence_checkpoint"] = evidence_checkpoint
    _validate_shape({**assertion, "signature": "placeholder"})
    assertion["signature"] = base64.b64encode(private_key.sign(canonical_json(assertion))).decode(
        "ascii"
    )
    return assertion


def verify_assertion(
    assertion: dict[str, Any],
    *,
    trusted_public_key: str,
    expected_node_id: str,
    expected_key_id: str,
    now: datetime | None = None,
    clock_skew: timedelta = timedelta(minutes=5),
    max_bytes: int = MAX_ASSERTION_BYTES,
) -> dict[str, Any]:
    if len(canonical_json(assertion)) > max_bytes:
        raise FederationVerificationError("Federation assertion exceeds size limit")
    _validate_shape(assertion)
    public_key = decode_public_key(trusted_public_key)
    if node_id(public_key) != expected_node_id or assertion["issuer_node_id"] != expected_node_id:
        raise FederationVerificationError("Issuer node identity mismatch")
    if key_id(public_key) != expected_key_id or assertion["issuer_key_id"] != expected_key_id:
        raise FederationVerificationError("Issuer key identity mismatch")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    issued_at = _parse_time(assertion["issued_at"], "issued_at")
    expires_at = _parse_time(assertion["expires_at"], "expires_at")
    observation_time = _parse_time(assertion["observation_time"], "observation_time")
    if issued_at > current + clock_skew or observation_time > current + clock_skew:
        raise FederationVerificationError("Federation assertion timestamp is in the future")
    if expires_at <= current - clock_skew:
        raise FederationVerificationError("Federation assertion has expired")
    if expires_at <= issued_at or expires_at - issued_at > MAX_LIFETIME:
        raise FederationVerificationError("Invalid assertion validity interval")
    try:
        signature = base64.b64decode(assertion["signature"], validate=True)
        public_key.verify(signature, canonical_json(_unsigned(assertion)))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise FederationVerificationError("Federation assertion signature is invalid") from exc
    return {
        "payload_fingerprint": hashlib.sha256(canonical_json(assertion)).hexdigest(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "observation_time": observation_time,
    }


def corroborate(assertions: list[dict[str, Any]], *, now: datetime | None = None) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    issuers = {item["issuer_node_id"] for item in assertions}
    severities = {item["severity"] for item in assertions}
    sources = {item["source_category"] for item in assertions}
    fingerprints = {item["evidence_fingerprint"] for item in assertions}
    ages = [
        (current - _parse_time(item["observation_time"], "observation_time")).total_seconds()
        for item in assertions
    ]
    return {
        "independent_issuer_count": len(issuers),
        "source_diversity": len(sources),
        "agreement": len(severities) == 1,
        "severities": sorted(severities),
        "evidence_fingerprints": sorted(fingerprints),
        "oldest_age_seconds": max(ages, default=0),
        "newest_age_seconds": min(ages, default=0),
    }


def receive_assertion(
    db: Session,
    *,
    organization_id: str,
    peer: FederationPeer,
    assertion: dict[str, Any],
    now: datetime | None = None,
    max_bytes: int = MAX_ASSERTION_BYTES,
) -> FederatedAssertion:
    if peer.organization_id != organization_id:
        raise FederationVerificationError("Peer organization boundary mismatch")
    if peer.status != "trusted" or peer.revoked_at is not None:
        raise FederationVerificationError("Federation peer is not trusted")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    verification = verify_assertion(
        assertion,
        trusted_public_key=peer.public_key,
        expected_node_id=peer.node_id,
        expected_key_id=peer.key_id,
        now=current,
        max_bytes=max_bytes,
    )
    replay = db.scalar(
        select(FederationReplayNonce.id).where(
            FederationReplayNonce.issuer_node_id == peer.node_id,
            FederationReplayNonce.nonce == assertion["nonce"],
        )
    )
    existing = db.scalar(
        select(FederatedAssertion.id).where(
            FederatedAssertion.organization_id == organization_id,
            FederatedAssertion.assertion_id == assertion["assertion_id"],
        )
    )
    if replay or existing:
        raise FederationVerificationError("Federation assertion replay rejected")
    record = FederatedAssertion(
        organization_id=organization_id,
        assertion_id=assertion["assertion_id"],
        issuer_node_id=peer.node_id,
        issuer_key_id=peer.key_id,
        assertion_type=assertion["assertion_type"],
        subject_type=assertion["subject_type"],
        subject_fingerprint=assertion["subject_fingerprint"],
        evidence_fingerprint=assertion["evidence_fingerprint"],
        payload_fingerprint=verification["payload_fingerprint"],
        assertion=assertion,
        verification_status="verified",
        trust_state=peer.status,
        issued_at=verification["issued_at"],
        expires_at=verification["expires_at"],
        received_at=current,
    )
    db.add_all(
        [
            FederationReplayNonce(
                issuer_node_id=peer.node_id,
                nonce=assertion["nonce"],
                assertion_id=assertion["assertion_id"],
                expires_at=verification["expires_at"],
                received_at=current,
            ),
            record,
        ]
    )
    db.flush()
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="CYPHERYN federation identity utility")
    subparsers = parser.add_subparsers(dest="command", required=True)
    initialize = subparsers.add_parser("initialize")
    initialize.add_argument("key_path", type=Path)
    identity = subparsers.add_parser("identity")
    identity.add_argument("key_path", type=Path)
    identity.add_argument("--display-name", default="CYPHERYN Node")
    args = parser.parse_args()
    if args.command == "initialize":
        if args.key_path.exists():
            existing = load_node_key(args.key_path).public_key()
            result = {"node_id": node_id(existing), "key_id": key_id(existing), "created": False}
        else:
            result = {**generate_node_key(args.key_path), "created": True}
        print(json.dumps(result, sort_keys=True))
    elif args.command == "identity":
        print(
            json.dumps(
                identity_document(load_node_key(args.key_path), args.display_name),
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
