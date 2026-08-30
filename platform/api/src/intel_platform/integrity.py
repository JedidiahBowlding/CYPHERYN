from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import AuditEvent, EvidenceSource


def _time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _digest(payload: dict) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _serialize_audit(event: AuditEvent) -> dict:
    return {
        "id": event.id,
        "organization_id": event.organization_id,
        "actor_id": event.actor_id,
        "action": event.action,
        "object_type": event.object_type,
        "object_id": event.object_id,
        "decision": event.decision,
        "reason_code": event.reason_code,
        "occurred_at": _time(event.occurred_at),
        "previous_integrity_hash": event.previous_integrity_hash,
    }


def _serialize_evidence(source: EvidenceSource) -> dict:
    return {
        "id": source.id,
        "investigation_id": source.investigation_id,
        "job_id": source.job_id,
        "target_id": source.target_id,
        "authorization_id": source.authorization_id,
        "provider": source.provider,
        "provider_version": source.provider_version,
        "ruleset_version": source.ruleset_version,
        "query": source.query,
        "raw_response_hash": source.raw_response_hash,
        "redaction_policy": source.redaction_policy,
        "retrieved_at": _time(source.retrieved_at),
        "retain_until": _time(source.retain_until),
        "previous_integrity_hash": source.previous_integrity_hash,
    }


def _transaction_lock(db: Session, scope: str) -> None:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
            {"scope": f"cypheryn-integrity:{scope}"},
        )


def seal_audit_event(db: Session, event: AuditEvent) -> None:
    _transaction_lock(db, event.organization_id)
    previous = db.scalar(
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == event.organization_id,
            AuditEvent.id != event.id,
            AuditEvent.integrity_hash.is_not(None),
        )
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    event.previous_integrity_hash = previous.integrity_hash if previous else None
    event.integrity_hash = _digest(_serialize_audit(event))


def seal_evidence_source(db: Session, source: EvidenceSource) -> None:
    _transaction_lock(db, source.investigation_id)
    previous = db.scalar(
        select(EvidenceSource)
        .where(
            EvidenceSource.investigation_id == source.investigation_id,
            EvidenceSource.id != source.id,
            EvidenceSource.integrity_hash.is_not(None),
        )
        .order_by(EvidenceSource.retrieved_at.desc(), EvidenceSource.id.desc())
        .limit(1)
    )
    source.previous_integrity_hash = previous.integrity_hash if previous else None
    source.integrity_hash = _digest(_serialize_evidence(source))


def verify_evidence_source(source: EvidenceSource) -> bool:
    return bool(source.integrity_hash) and source.integrity_hash == _digest(
        _serialize_evidence(source)
    )


def verify_audit_event(event: AuditEvent) -> bool:
    return bool(event.integrity_hash) and event.integrity_hash == _digest(_serialize_audit(event))
