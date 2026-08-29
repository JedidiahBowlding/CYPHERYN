from sqlalchemy.orm import Session

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
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            object_type=object_type,
            object_id=object_id,
            decision=decision,
            reason_code=reason_code,
        )
    )
