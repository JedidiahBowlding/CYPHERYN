from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .integrity import seal_audit_event
from .models import AuditEvent


def record_audit(
    db: Session,
    *,
    organization_id: str,
    actor_id: str,
    action: str,
    object_type: str,
    object_id: str,
    decision: str = "allowed",
    reason_code: str = "authorized",
) -> None:
    event = AuditEvent(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            object_type=object_type,
            object_id=object_id,
            decision=decision,
            reason_code=reason_code,
            occurred_at=datetime.now(UTC),
    )
    db.add(event)
    db.flush()
    seal_audit_event(db, event)
