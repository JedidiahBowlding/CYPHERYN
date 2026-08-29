from __future__ import annotations

import json
import logging
import math
import threading
from contextvars import ContextVar
from datetime import UTC, datetime
from statistics import mean
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import CollectionJob, EvidenceSource, JobStatus, ProviderRuntimeState, WorkerState

correlation_id_context: ContextVar[str] = ContextVar("correlation_id", default="")
logger = logging.getLogger("signaltrace")
WORKER_STALE_SECONDS = 45


def correlation_id(value: str | None = None) -> str:
    candidate = (value or "").strip()
    valid_characters = all(char.isalnum() or char in "-_." for char in candidate)
    if candidate and len(candidate) <= 128 and valid_characters:
        return candidate
    return str(uuid4())


def structured_log(event_type: str, *, severity: str = "info", **fields: object) -> None:
    blocked = {"credentials", "password", "secret", "token", "api_key", "raw_payload"}
    safe = {
        key: value
        for key, value in fields.items()
        if key.lower() not in blocked and not any(word in key.lower() for word in blocked)
    }
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "signaltrace-api",
        "severity": severity,
        "correlation_id": correlation_id_context.get(),
        "event_type": event_type,
        **safe,
    }
    getattr(logger, severity if severity in {"debug", "info", "warning", "error"} else "info")(
        json.dumps(payload, sort_keys=True, default=str)
    )


def heartbeat_worker(
    db: Session,
    worker_id: str,
    *,
    version: str,
    active_jobs: int = 0,
    failure: str | None = None,
) -> WorkerState:
    now = datetime.now(UTC)
    state = db.get(WorkerState, worker_id)
    if state is None:
        state = WorkerState(id=worker_id, version=version, started_at=now)
        db.add(state)
    state.version = version
    state.last_heartbeat_at = now
    state.last_successful_poll_at = now
    state.active_jobs = max(0, active_jobs)
    if failure:
        state.last_failure_at = now
        state.last_failure = failure[:500]
    db.commit()
    return state


def worker_heartbeat_loop(
    session_factory,
    worker_id: str,
    *,
    version: str,
    stop: threading.Event,
    interval_seconds: float = 10.0,
) -> None:
    while not stop.is_set():
        try:
            with session_factory() as db:
                active_jobs = (
                    db.scalar(
                        select(func.count(CollectionJob.id)).where(
                            CollectionJob.lease_owner == worker_id,
                            CollectionJob.status == JobStatus.RUNNING,
                        )
                    )
                    or 0
                )
                heartbeat_worker(
                    db,
                    worker_id,
                    version=version,
                    active_jobs=active_jobs,
                )
        except Exception as exc:  # heartbeat failure must not hide worker execution state
            structured_log(
                "worker.heartbeat_failure",
                severity="error",
                worker_id=worker_id,
                error=str(exc)[:500],
            )
        stop.wait(interval_seconds)


def operational_snapshot(db: Session) -> dict:
    now = datetime.now(UTC)
    workers = list(db.scalars(select(WorkerState).order_by(WorkerState.id)))
    jobs = list(db.scalars(select(CollectionJob)))
    queued = [job for job in jobs if job.status == JobStatus.QUEUED]
    completed = [job for job in jobs if job.status in {JobStatus.COMPLETED, JobStatus.PARTIAL}]
    waits = [
        (job.started_at - job.created_at).total_seconds()
        for job in jobs
        if job.started_at is not None
    ]
    durations = [
        (job.ended_at - job.started_at).total_seconds()
        for job in completed
        if job.started_at is not None and job.ended_at is not None
    ]
    providers: dict[str, dict] = {}
    for job in jobs:
        metric = providers.setdefault(
            job.provider,
            {
                "requests": 0,
                "successes": 0,
                "failures": 0,
                "timeouts": 0,
                "throttled": 0,
                "authentication_failures": 0,
                "cancellations": 0,
                "latencies": [],
            },
        )
        metric["requests"] += 1
        error = (job.error_summary or "").lower()
        if job.status in {JobStatus.COMPLETED, JobStatus.PARTIAL}:
            metric["successes"] += 1
        elif job.status == JobStatus.FAILED:
            metric["failures"] += 1
            if "timeout" in error or "timed out" in error:
                metric["timeouts"] += 1
            if "429" in error or "throttl" in error or "rate limit" in error:
                metric["throttled"] += 1
            if any(term in error for term in ("401", "403", "credential", "authentication")):
                metric["authentication_failures"] += 1
        elif job.status == JobStatus.CANCELLED:
            metric["cancellations"] += 1
        if job.started_at and job.ended_at:
            metric["latencies"].append((job.ended_at - job.started_at).total_seconds())
    runtime_states = {state.provider: state for state in db.scalars(select(ProviderRuntimeState))}
    for provider, metric in providers.items():
        latencies = sorted(metric.pop("latencies"))
        p95_index = max(0, math.ceil(len(latencies) * 0.95) - 1)
        runtime = runtime_states.get(provider)
        metric.update(
            {
                "average_latency_seconds": round(mean(latencies), 3) if latencies else None,
                "p95_latency_seconds": (
                    round(latencies[p95_index], 3) if len(latencies) >= 5 else None
                ),
                "circuit_breaker": (
                    "open"
                    if runtime and runtime.circuit_open_until and runtime.circuit_open_until > now
                    else "closed"
                ),
                "last_successful_collection": (
                    runtime.last_success_at.isoformat()
                    if runtime and runtime.last_success_at
                    else None
                ),
            }
        )
    return {
        "generated_at": now.isoformat(),
        "worker_healthy": any(
            (now - _aware(worker.last_heartbeat_at)).total_seconds() <= WORKER_STALE_SECONDS
            for worker in workers
        ),
        "workers": [
            {
                "id": worker.id,
                "version": worker.version,
                "last_heartbeat": worker.last_heartbeat_at.isoformat(),
                "last_successful_poll": worker.last_successful_poll_at.isoformat()
                if worker.last_successful_poll_at
                else None,
                "last_failure": worker.last_failure,
                "active_jobs": worker.active_jobs,
                "stale": (now - _aware(worker.last_heartbeat_at)).total_seconds()
                > WORKER_STALE_SECONDS,
            }
            for worker in workers
        ],
        "queue": {
            "queued": len(queued),
            "running": sum(job.status == JobStatus.RUNNING for job in jobs),
            "failed": sum(job.status == JobStatus.FAILED for job in jobs),
            "cancelled": sum(job.status == JobStatus.CANCELLED for job in jobs),
            "retries": sum(max(0, job.attempt - 1) for job in jobs),
            "expired_leases": sum(
                job.status == JobStatus.RUNNING
                and job.lease_expires_at is not None
                and _aware(job.lease_expires_at) < now
                for job in jobs
            ),
            "oldest_queued_age_seconds": max(
                ((now - _aware(job.created_at)).total_seconds() for job in queued), default=0
            ),
            "average_wait_seconds": round(mean(waits), 3) if waits else None,
            "average_execution_seconds": round(mean(durations), 3) if durations else None,
        },
        "providers": providers,
        "evidence_count": db.scalar(select(func.count(EvidenceSource.id))) or 0,
    }


def prometheus_metrics(snapshot: dict) -> str:
    queue = snapshot["queue"]
    lines = [
        "# HELP signaltrace_worker_healthy Whether at least one worker heartbeat is fresh.",
        "# TYPE signaltrace_worker_healthy gauge",
        f"signaltrace_worker_healthy {1 if snapshot['worker_healthy'] else 0}",
    ]
    for key in ("queued", "running", "failed", "cancelled", "retries", "expired_leases"):
        lines.append(f"signaltrace_jobs_{key} {queue[key]}")
    lines.append(f"signaltrace_oldest_queued_job_seconds {queue['oldest_queued_age_seconds']}")
    lines.append(f"signaltrace_evidence_total {snapshot['evidence_count']}")
    for provider, metric in sorted(snapshot["providers"].items()):
        safe = provider.replace("\\", "\\\\").replace('"', '\\"')
        for key in (
            "requests",
            "successes",
            "failures",
            "timeouts",
            "throttled",
            "authentication_failures",
            "cancellations",
        ):
            lines.append(f'signaltrace_provider_{key}{{provider="{safe}"}} {metric[key]}')
    return "\n".join(lines) + "\n"


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
