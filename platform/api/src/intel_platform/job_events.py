from sqlalchemy.orm import Session

from .models import CollectionJob, CollectionJobEvent, JobStatus


def append_job_event(
    db: Session,
    job: CollectionJob,
    event_type: str,
    to_status: JobStatus,
    *,
    from_status: JobStatus | None = None,
    message: str = "",
    details: dict | None = None,
) -> CollectionJobEvent:
    event = CollectionJobEvent(
        job_id=job.id,
        event_type=event_type,
        from_status=from_status.value if from_status else None,
        to_status=to_status.value,
        message=message,
        details=details or {},
    )
    db.add(event)
    return event
