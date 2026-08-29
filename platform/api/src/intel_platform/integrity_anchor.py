from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from .integrity import _serialize_evidence, verify_evidence_source
from .models import EvidenceSource

CHECKPOINT_VERSION = "signaltrace-checkpoint-v1"
HASH_ALGORITHM = "sha256"


@dataclass(frozen=True)
class IntegrityCheckpoint:
    checkpoint_version: str
    scope_type: str
    scope_id: str
    chain_head: str
    record_count: int
    first_sequence: str
    last_sequence: str
    timestamp: str
    application_version: str
    hash_algorithm: str = HASH_ALGORITHM


class AnchorDestination(Protocol):
    def store(self, checkpoint_id: str, anchor: bytes) -> str: ...


class FileAnchorDestination:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def store(self, checkpoint_id: str, anchor: bytes) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
        destination = self.directory / f"{checkpoint_id}.anchor.json"
        destination.write_bytes(anchor)
        return str(destination.resolve())


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def create_evidence_checkpoint(
    db: Session, investigation_id: str, *, application_version: str
) -> tuple[IntegrityCheckpoint, list[dict]]:
    sources = list(
        db.scalars(
            select(EvidenceSource)
            .where(EvidenceSource.investigation_id == investigation_id)
            .order_by(EvidenceSource.retrieved_at, EvidenceSource.id)
        )
    )
    if not sources:
        raise ValueError("Cannot checkpoint an empty evidence chain")
    previous = None
    records: list[dict] = []
    for source in sources:
        if not verify_evidence_source(source):
            raise ValueError(f"Evidence record {source.id} failed integrity verification")
        if source.previous_integrity_hash != previous:
            raise ValueError(f"Evidence chain continuity failed at {source.id}")
        records.append({**_serialize_evidence(source), "integrity_hash": source.integrity_hash})
        previous = source.integrity_hash
    checkpoint = IntegrityCheckpoint(
        checkpoint_version=CHECKPOINT_VERSION,
        scope_type="investigation",
        scope_id=investigation_id,
        chain_head=str(sources[-1].integrity_hash),
        record_count=len(sources),
        first_sequence=sources[0].id,
        last_sequence=sources[-1].id,
        timestamp=datetime.now(UTC).isoformat(),
        application_version=application_version,
    )
    return checkpoint, records


def generate_signing_key(path: Path) -> str:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite signing key: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return signing_key_id(key.public_key())


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Integrity anchor key must be Ed25519")
    return key


def signing_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:24]}"


def sign_checkpoint(checkpoint: IntegrityCheckpoint, private_key: Ed25519PrivateKey) -> dict:
    payload = asdict(checkpoint)
    encoded = canonical_json(payload)
    public_key = private_key.public_key()
    public_raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "anchor_version": "signaltrace-anchor-v1",
        "checkpoint": payload,
        "checkpoint_sha256": hashlib.sha256(encoded).hexdigest(),
        "signing_key_id": signing_key_id(public_key),
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "signature": base64.b64encode(private_key.sign(encoded)).decode("ascii"),
    }


def export_chain(records: list[dict], checkpoint: IntegrityCheckpoint) -> dict:
    return {
        "export_version": "signaltrace-integrity-export-v1",
        "scope_type": checkpoint.scope_type,
        "scope_id": checkpoint.scope_id,
        "records": records,
        "manifest": {
            "hash_algorithm": checkpoint.hash_algorithm,
            "chain_head": checkpoint.chain_head,
            "record_count": checkpoint.record_count,
            "checkpoint_version": checkpoint.checkpoint_version,
            "verification_command": (
                "python -m intel_platform.integrity_anchor verify <export> <anchor>"
            ),
        },
    }


def verify_export_anchor(export: dict, anchor: dict, *, expected_key_id: str | None = None) -> dict:
    checkpoint = anchor.get("checkpoint")
    if not isinstance(checkpoint, dict):
        raise ValueError("Anchor checkpoint is missing")
    encoded = canonical_json(checkpoint)
    if hashlib.sha256(encoded).hexdigest() != anchor.get("checkpoint_sha256"):
        raise ValueError("Checkpoint digest does not match")
    public_raw = base64.b64decode(anchor["public_key"], validate=True)
    public_key = Ed25519PublicKey.from_public_bytes(public_raw)
    key_id = signing_key_id(public_key)
    if key_id != anchor.get("signing_key_id"):
        raise ValueError("Signing key identifier does not match public key")
    if expected_key_id and key_id != expected_key_id:
        raise ValueError("Anchor was not signed by the expected key")
    public_key.verify(base64.b64decode(anchor["signature"], validate=True), encoded)
    records = export.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("Integrity export contains no records")
    previous = None
    for record in records:
        if record.get("previous_integrity_hash") != previous:
            raise ValueError(f"Export chain continuity failed at {record.get('id')}")
        integrity_hash = record.get("integrity_hash")
        serialized = {key: value for key, value in record.items() if key != "integrity_hash"}
        digest = hashlib.sha256(canonical_json(serialized)).hexdigest()
        if digest != integrity_hash:
            raise ValueError(f"Export record hash failed at {record.get('id')}")
        previous = integrity_hash
    if checkpoint.get("chain_head") != previous:
        raise ValueError("Export chain head differs from anchor")
    if checkpoint.get("record_count") != len(records):
        raise ValueError("Export record count differs from anchor")
    if checkpoint.get("scope_id") != export.get("scope_id"):
        raise ValueError("Export scope differs from anchor")
    return {
        "valid": True,
        "scope_id": checkpoint["scope_id"],
        "chain_head": previous,
        "record_count": len(records),
        "signing_key_id": key_id,
        "checkpoint_timestamp": checkpoint["timestamp"],
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description="Generate keys or verify SignalTrace anchors")
    subparsers = parser.add_subparsers(dest="command", required=True)
    key_parser = subparsers.add_parser("generate-key")
    key_parser.add_argument("path", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("export", type=Path)
    verify_parser.add_argument("anchor", type=Path)
    verify_parser.add_argument("--expected-key-id")
    args = parser.parse_args()
    if args.command == "generate-key":
        print(generate_signing_key(args.path))
        return 0
    result = verify_export_anchor(
        json.loads(args.export.read_text(encoding="utf-8")),
        json.loads(args.anchor.read_text(encoding="utf-8")),
        expected_key_id=args.expected_key_id,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
