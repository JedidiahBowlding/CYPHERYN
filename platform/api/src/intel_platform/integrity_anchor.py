from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from .integrity import _serialize_evidence, verify_evidence_source
from .models import EvidenceSource, Investigation

CHECKPOINT_VERSION = "cypheryn-checkpoint-v1"
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
        with destination.open("xb") as handle:
            handle.write(anchor)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            destination.chmod(0o444)
        except OSError:
            pass
        return str(destination.resolve())

    def store_bundle(self, checkpoint_id: str, anchor: dict, export: dict) -> dict:
        self.directory.mkdir(parents=True, exist_ok=True)
        export_path = self.directory / f"{checkpoint_id}.integrity.json"
        with export_path.open("xb") as handle:
            handle.write(json.dumps(export, indent=2, sort_keys=True).encode())
            handle.flush()
            os.fsync(handle.fileno())
        try:
            export_path.chmod(0o444)
        except OSError:
            pass
        anchor_path = self.store(
            checkpoint_id, json.dumps(anchor, indent=2, sort_keys=True).encode()
        )
        return {"anchor_path": anchor_path, "export_path": str(export_path.resolve())}


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def create_evidence_checkpoint(
    db: Session, investigation_id: str, *, application_version: str
) -> tuple[IntegrityCheckpoint, list[dict]]:
    sources = list(
        db.scalars(
            select(EvidenceSource)
            .where(
                EvidenceSource.investigation_id == investigation_id,
                # Providers reserve a draft row before long-running external
                # execution so cancellation stays responsive. Only sealed
                # records are evidence and participate in the chain.
                EvidenceSource.integrity_hash.is_not(None),
            )
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


def rotate_signing_key(directory: Path) -> dict:
    """Create a new retained key and atomically select it for future checkpoints."""
    directory.mkdir(parents=True, exist_ok=True)
    filename = f"ed25519-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}.pem"
    path = directory / filename
    key_id = generate_signing_key(path)
    metadata = {
        "key_id": key_id,
        "filename": filename,
        "activated_at": datetime.now(UTC).isoformat(),
    }
    fd, temporary_name = tempfile.mkstemp(prefix="active-key-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, directory / "active-key.json")
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return metadata


def load_active_private_key(directory: Path) -> Ed25519PrivateKey:
    active = directory / "active-key.json"
    if not active.is_file():
        raise FileNotFoundError(
            f"No active integrity key in {directory}; run integrity_anchor rotate-key"
        )
    metadata = json.loads(active.read_text(encoding="utf-8"))
    filename = str(metadata.get("filename") or "")
    if Path(filename).name != filename or not filename.endswith(".pem"):
        raise ValueError("Active integrity key metadata is invalid")
    key = load_private_key(directory / filename)
    if signing_key_id(key.public_key()) != metadata.get("key_id"):
        raise ValueError("Active integrity key identifier does not match key material")
    return key


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
        "anchor_version": "cypheryn-anchor-v1",
        "checkpoint": payload,
        "checkpoint_sha256": hashlib.sha256(encoded).hexdigest(),
        "signing_key_id": signing_key_id(public_key),
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "signature": base64.b64encode(private_key.sign(encoded)).decode("ascii"),
    }


def export_chain(records: list[dict], checkpoint: IntegrityCheckpoint) -> dict:
    return {
        "export_version": "cypheryn-integrity-export-v1",
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


def latest_anchor_metadata(directory: Path, investigation_id: str) -> dict | None:
    candidates = sorted(directory.glob(f"{investigation_id}.*.anchor.json"), reverse=True)
    for path in candidates:
        try:
            anchor = json.loads(path.read_text(encoding="utf-8"))
            checkpoint = anchor["checkpoint"]
            if checkpoint.get("scope_id") != investigation_id:
                continue
            return {
                "anchor_version": anchor.get("anchor_version"),
                "checkpoint_sha256": anchor.get("checkpoint_sha256"),
                "signing_key_id": anchor.get("signing_key_id"),
                "public_key": anchor.get("public_key"),
                "signature": anchor.get("signature"),
                "checkpoint": checkpoint,
                "anchor_filename": path.name,
                "integrity_export_filename": path.name.replace(
                    ".anchor.json", ".integrity.json"
                ),
            }
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            continue
    return None


def create_and_store_anchor(
    db: Session,
    investigation_id: str,
    *,
    application_version: str,
    key_directory: Path,
    destination: FileAnchorDestination,
) -> dict:
    checkpoint, records = create_evidence_checkpoint(
        db, investigation_id, application_version=application_version
    )
    anchor = sign_checkpoint(checkpoint, load_active_private_key(key_directory))
    checkpoint_id = (
        f"{investigation_id}.{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}."
        f"{checkpoint.chain_head[:12]}"
    )
    locations = destination.store_bundle(checkpoint_id, anchor, export_chain(records, checkpoint))
    return {**latest_anchor_metadata(destination.directory, investigation_id), **locations}


def generate_due_anchors(
    session_factory,
    *,
    key_directory: Path,
    destination_directory: Path,
    interval_minutes: int,
    application_version: str,
    now: datetime | None = None,
) -> int:
    current = now or datetime.now(UTC)
    generated = 0
    destination = FileAnchorDestination(destination_directory)
    with session_factory() as db:
        investigations = list(db.scalars(select(Investigation).order_by(Investigation.id)))
        for investigation in investigations:
            latest_source = db.scalar(
                select(EvidenceSource)
                .where(EvidenceSource.investigation_id == investigation.id)
                .order_by(EvidenceSource.retrieved_at.desc(), EvidenceSource.id.desc())
            )
            if latest_source is None:
                continue
            previous = latest_anchor_metadata(destination_directory, investigation.id)
            checkpoint = previous.get("checkpoint", {}) if previous else {}
            timestamp = checkpoint.get("timestamp")
            anchored_at = datetime.fromisoformat(timestamp) if timestamp else None
            if anchored_at and anchored_at.tzinfo is None:
                anchored_at = anchored_at.replace(tzinfo=UTC)
            unchanged = checkpoint.get("chain_head") == latest_source.integrity_hash
            if unchanged and anchored_at and current < anchored_at + timedelta(
                minutes=max(1, interval_minutes)
            ):
                continue
            create_and_store_anchor(
                db,
                investigation.id,
                application_version=application_version,
                key_directory=key_directory,
                destination=destination,
            )
            generated += 1
    return generated


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
    parser = argparse.ArgumentParser(description="Generate keys or verify CYPHERYN anchors")
    subparsers = parser.add_subparsers(dest="command", required=True)
    key_parser = subparsers.add_parser("generate-key")
    key_parser.add_argument("path", type=Path)
    rotate_parser = subparsers.add_parser("rotate-key")
    rotate_parser.add_argument("directory", type=Path)
    ensure_parser = subparsers.add_parser("ensure-key")
    ensure_parser.add_argument("directory", type=Path)
    initialize_parser = subparsers.add_parser("initialize")
    initialize_parser.add_argument("key_directory", type=Path)
    initialize_parser.add_argument("destination_directory", type=Path)
    initialize_parser.add_argument("--worker-uid", type=int, default=10001)
    initialize_parser.add_argument("--rotate", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("export", type=Path)
    verify_parser.add_argument("anchor", type=Path)
    verify_parser.add_argument("--expected-key-id")
    args = parser.parse_args()
    if args.command == "generate-key":
        print(generate_signing_key(args.path))
        return 0
    if args.command == "rotate-key":
        print(json.dumps(rotate_signing_key(args.directory), indent=2, sort_keys=True))
        return 0
    if args.command == "ensure-key":
        active = args.directory / "active-key.json"
        result = (
            json.loads(active.read_text(encoding="utf-8"))
            if active.is_file()
            else rotate_signing_key(args.directory)
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "initialize":
        args.key_directory.mkdir(parents=True, exist_ok=True)
        args.destination_directory.mkdir(parents=True, exist_ok=True)
        active = args.key_directory / "active-key.json"
        result = (
            rotate_signing_key(args.key_directory)
            if args.rotate or not active.is_file()
            else json.loads(active.read_text(encoding="utf-8"))
        )
        for path in [args.key_directory, args.destination_directory, *args.key_directory.iterdir()]:
            try:
                os.chown(path, args.worker_uid, args.worker_uid)
            except (AttributeError, PermissionError):
                pass
        args.key_directory.chmod(0o750)
        args.destination_directory.chmod(0o770)
        print(json.dumps(result, indent=2, sort_keys=True))
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
