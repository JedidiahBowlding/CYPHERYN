from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .audit import record_audit
from .auth import (
    get_current_user,
    membership_for,
    require_organization_admin,
    require_writer,
)
from .config import Settings, get_settings
from .database import get_db
from .egress import (
    KNOWN_DESTINATIONS,
    POLICY_ID,
    POLICY_VERSION,
    digest,
    evaluate_policy,
    normalize_action,
    scan_artifact,
    seal_event,
    status_for,
    store_artifact,
    verify_event,
)
from .github_mediation import UnsupportedGitHubCommand, parse_github_command
from .models import (
    EgressApproval,
    EgressArtifact,
    EgressDecision,
    EgressEvent,
    EgressEventStatus,
    EgressFinding,
    EgressPolicy,
    MembershipRole,
    ProtectedAgent,
    SecurityDestination,
    User,
)
from .observability import record_egress_event, structured_log
from .security_contracts import normalize_classifications

router = APIRouter(prefix="/api/v1/egress", tags=["agent-egress-firewall"])
_rate_lock = threading.Lock()
_rate_windows: dict[str, deque[float]] = defaultdict(deque)


class ArtifactInput(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1)


class EvaluationRequest(BaseModel):
    organization_id: str
    agent_id: str
    action_type: str
    destination: str
    repository: str = ""
    requested_visibility: str = ""
    working_directory: str = ""
    correlation_id: str = ""
    artifacts: list[ArtifactInput] = Field(default_factory=list, max_length=20)
    approval_token: str = ""


class AgentCreate(BaseModel):
    organization_id: str
    name: str = Field(min_length=1, max_length=200)
    agent_type: str = "development_agent"
    runtime: str = "unknown"
    workspace: str = ""
    credential_reference: str = Field(default="", max_length=300, pattern=r"^[A-Za-z0-9._:/-]*$")


class ApprovalDecision(BaseModel):
    approve: bool
    expires_in_minutes: int = Field(default=30, ge=1, le=1440)


class VerificationRequest(BaseModel):
    approval_token: str = ""
    observed_repository: str = ""
    observed_owner: str = ""
    observed_visibility: str = ""
    artifact_locations: list[str] = Field(default_factory=list)
    object_identifiers: list[str] = Field(default_factory=list)


class CommandParseRequest(BaseModel):
    organization_id: str
    agent_id: str
    command: str = Field(min_length=1, max_length=8192)
    correlation_id: str = ""


def _limit(request: Request, settings: Settings) -> None:
    key = request.client.host if request.client else "local"
    now = time.monotonic()
    with _rate_lock:
        window = _rate_windows[key]
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= settings.egress_rate_limit_per_minute:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS, "Egress endpoint rate limit exceeded"
            )
        window.append(now)


def _serialize_event(event: EgressEvent, *, integrity_valid: bool | None = None) -> dict:
    return {
        "event_id": event.id,
        "agent_id": event.agent_id,
        "actor_id": event.actor_id,
        "correlation_id": event.correlation_id,
        "action_type": event.action_type,
        "destination": event.destination,
        "repository": event.repository,
        "decision": event.decision.value,
        "reason_codes": event.reason_codes,
        "human_readable_reason": event.human_reason,
        "policy_id": POLICY_ID,
        "policy_version": event.policy_version,
        "approval_id": event.approval_id,
        "status": event.status.value,
        "request_hash": event.request_hash,
        "event_hash": event.event_hash,
        "previous_event_hash": event.previous_event_hash,
        "integrity_valid": verify_event(event) if integrity_valid is None else integrity_valid,
        "execution_result": event.execution_result,
        "verification_result": event.verification_result,
        "created_at": event.created_at.isoformat(),
        "executed_at": event.executed_at.isoformat() if event.executed_at else None,
        "verified_at": event.verified_at.isoformat() if event.verified_at else None,
    }


def _ensure_default_policy(db: Session, organization_id: str, user_id: str) -> EgressPolicy:
    policy = db.scalar(
        select(EgressPolicy).where(
            EgressPolicy.organization_id == organization_id,
            EgressPolicy.name == POLICY_ID,
            EgressPolicy.version == POLICY_VERSION,
        )
    )
    if policy:
        return policy
    rules = {
        "public_repository": "block",
        "private_to_public": "block",
        "unknown_destination": "block",
        "verified_secret": "block",
        "repository_creation": "require_approval",
        "external_publication": "require_approval",
        "templates": {
            "ai_grant_hub": {"enabled": False},
            "nova_steward": {"enabled": False},
            "veloryn_tokenquity": {"enabled": False},
            "cypheryn": {"enabled": False},
        },
    }
    policy = EgressPolicy(
        organization_id=organization_id,
        name=POLICY_ID,
        version=POLICY_VERSION,
        scope={"agents": "all", "destinations": "all"},
        rules=rules,
        state="active",
        integrity_hash=digest({"name": POLICY_ID, "version": POLICY_VERSION, "rules": rules}),
        created_by_id=user_id,
        approved_by_id=user_id,
        activated_at=datetime.now(UTC),
    )
    db.add(policy)
    db.flush()
    for hostname in sorted({"github.com", "api.github.com", "uploads.github.com"}):
        destination = db.scalar(
            select(SecurityDestination).where(
                SecurityDestination.organization_id == organization_id,
                SecurityDestination.environment == "production",
                SecurityDestination.hostname == hostname,
            )
        )
        if destination is None:
            db.add(
                SecurityDestination(
                    organization_id=organization_id,
                    canonical_identifier=f"https://{hostname}",
                    destination_type="https",
                    hostname=hostname,
                    environment="production",
                    trust_state="trusted",
                    reputation_metadata={"source": "cypheryn-github-compatibility"},
                    created_by_id=user_id,
                )
            )
    return policy


@router.get("/health")
def health(
    settings: Settings = Depends(get_settings),
    _user: User = Depends(get_current_user),
) -> dict:
    return {
        "status": "healthy" if settings.egress_guard_enabled else "disabled",
        "bind_host": settings.egress_guard_bind_host,
        "policy_engine": "healthy" if settings.egress_guard_enabled else "unavailable",
        "scanners": {"builtin-patterns": "healthy", "tesseract": "optional"},
    }


@router.post("/agents", status_code=201)
def register_agent(
    payload: AgentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    require_writer(db, user.id, payload.organization_id)
    agent = ProtectedAgent(
        organization_id=payload.organization_id,
        name=payload.name,
        agent_type=payload.agent_type,
        owner_id=user.id,
        runtime=payload.runtime,
        workspace=payload.workspace,
        credential_reference=payload.credential_reference,
        last_seen_at=datetime.now(UTC),
    )
    db.add(agent)
    _ensure_default_policy(db, payload.organization_id, user.id)
    record_audit(
        db,
        organization_id=payload.organization_id,
        actor_id=user.id,
        action="egress.agent.register",
        object_type="protected_agent",
        object_id=agent.id,
    )
    db.commit()
    return {"id": agent.id, "name": agent.name, "status": agent.status}


@router.post("/github/normalize")
def normalize_github(
    payload: CommandParseRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership_for(db, user.id, payload.organization_id)
    agent = db.get(ProtectedAgent, payload.agent_id)
    if not agent or agent.organization_id != payload.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Protected agent not found")
    try:
        return parse_github_command(
            payload.command,
            agent_id=agent.id,
            actor_id=user.id,
            correlation_id=payload.correlation_id,
        )
    except UnsupportedGitHubCommand as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


@router.post("/artifacts/scan")
def artifact_scan(
    payload: ArtifactInput,
    organization_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> dict:
    membership_for(db, user.id, organization_id)
    _limit(request, settings)
    try:
        result = scan_artifact(
            filename=payload.filename, content_base64=payload.content_base64, settings=settings
        )
    except ValueError as exc:
        record_egress_event("scanner_failure")
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    record_egress_event("artifact_scanned", sensitive=bool(result.classification))
    return {
        **result.__dict__,
        "canonical_classification": normalize_classifications(result.classification),
    }


@router.post("/evaluate", status_code=201)
def evaluate(
    payload: EvaluationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> dict:
    _limit(request, settings)
    membership_for(db, user.id, payload.organization_id)
    agent = db.get(ProtectedAgent, payload.agent_id)
    if not agent or agent.organization_id != payload.organization_id or agent.status != "active":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Active protected agent not found")
    policy = _ensure_default_policy(db, payload.organization_id, user.id)
    scan_results = []
    classifications: list[str] = []
    scanner_healthy = settings.egress_guard_enabled
    try:
        for artifact in payload.artifacts:
            result = scan_artifact(
                filename=artifact.filename,
                content_base64=artifact.content_base64,
                settings=settings,
            )
            scan_results.append(result)
            classifications.extend(result.classification)
    except (ValueError, OSError) as exc:
        scanner_healthy = False
        structured_log("egress.scan_failed", severity="warning", error_type=type(exc).__name__)
    action = normalize_action(
        {
            **payload.model_dump(exclude={"artifacts", "approval_token"}),
            "actor_id": user.id,
            "artifact_hashes": [item.sha256 for item in scan_results],
        }
    )
    approved_repositories = list(policy.rules.get("approved_private_repositories", []))
    approved_destinations = set(KNOWN_DESTINATIONS) | {
        item.hostname
        for item in db.scalars(
            select(SecurityDestination).where(
                SecurityDestination.organization_id == payload.organization_id,
                SecurityDestination.trust_state.in_(["trusted", "approved"]),
            )
        )
    }
    decision, reasons, reason = evaluate_policy(
        action,
        artifact_classifications=classifications,
        approved_private_repositories=approved_repositories,
        mandatory_scanners_healthy=scanner_healthy,
        approved_destinations=approved_destinations,
    )
    if not scanner_healthy:
        status_value = EgressEventStatus.FAILED_CLOSED
    else:
        status_value = status_for(decision)
    event = EgressEvent(
        organization_id=payload.organization_id,
        agent_id=agent.id,
        actor_id=user.id,
        correlation_id=action["correlation_id"]
        or request.headers.get("X-Correlation-ID", "")[:128]
        or secrets.token_hex(16),
        action_type=action["action_type"],
        destination=action["destination"],
        repository=action["repository"],
        normalized_request=action,
        request_hash=digest(action),
        decision=EgressDecision(decision),
        reason_codes=reasons,
        human_reason=reason,
        policy_id=policy.id,
        policy_version=policy.version,
        status=status_value,
    )
    db.add(event)
    db.flush()
    for result in scan_results:
        db.add(store_artifact(event.id, result))
    seal_event(db, event)
    record_audit(
        db,
        organization_id=payload.organization_id,
        actor_id=user.id,
        action=f"egress.evaluate.{decision.lower()}",
        object_type="egress_event",
        object_id=event.id,
        decision=decision,
        reason_code=",".join(reasons),
    )
    db.commit()
    record_egress_event(decision.lower(), sensitive=bool(classifications))
    return _serialize_event(event)


@router.post("/events/{event_id}/approvals", status_code=201)
def decide_approval(
    event_id: str,
    payload: ApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> dict:
    _limit(request, settings)
    event = db.get(EgressEvent, event_id)
    if not event:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Egress event not found")
    require_organization_admin(db, user.id, event.organization_id)
    if event.actor_id == user.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Agents and requesters cannot approve their own action"
        )
    if event.decision != EgressDecision.REQUIRE_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, "This event does not require approval")
    raw_token = secrets.token_urlsafe(32) if payload.approve else ""
    approval = EgressApproval(
        event_id=event.id,
        requested_by_id=event.actor_id,
        decided_by_id=user.id,
        action_hash=event.request_hash,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest()
        if raw_token
        else hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        state="approved" if payload.approve else "rejected",
        expires_at=datetime.now(UTC) + timedelta(minutes=payload.expires_in_minutes),
        decided_at=datetime.now(UTC),
    )
    db.add(approval)
    db.flush()
    event.approval_id = approval.id
    event.status = EgressEventStatus.APPROVED if payload.approve else EgressEventStatus.BLOCKED
    record_audit(
        db,
        organization_id=event.organization_id,
        actor_id=user.id,
        action=f"egress.approval.{'approve' if payload.approve else 'reject'}",
        object_type="egress_approval",
        object_id=approval.id,
    )
    db.commit()
    return {
        "approval_id": approval.id,
        "state": approval.state,
        "expires_at": approval.expires_at.isoformat(),
        "approval_token": raw_token,
    }


@router.post("/executions/{event_id}/verify")
def verify_execution(
    event_id: str,
    payload: VerificationRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    event = db.get(EgressEvent, event_id)
    if not event:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Egress event not found")
    membership_for(db, user.id, event.organization_id)
    if event.decision == EgressDecision.BLOCK or event.status == EgressEventStatus.FAILED_CLOSED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Blocked events cannot be executed")
    if event.approval_id:
        approval = db.get(EgressApproval, event.approval_id)
        supplied = hashlib.sha256(payload.approval_token.encode()).hexdigest()
        now = datetime.now(UTC)
        if (
            not approval
            or approval.state != "approved"
            or approval.consumed_at
            or approval.expires_at.replace(tzinfo=approval.expires_at.tzinfo or UTC) <= now
            or approval.action_hash != event.request_hash
            or not secrets.compare_digest(approval.token_hash, supplied)
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Approval is invalid, expired, mutated, or already used"
            )
        approval.consumed_at = now
        approval.state = "consumed"
    expected = event.normalized_request
    observed = payload.model_dump(exclude={"approval_token"})
    mismatches = []
    if expected.get("repository") and payload.observed_repository.lower() != expected["repository"]:
        mismatches.append("repository")
    if (
        expected.get("requested_visibility")
        and payload.observed_visibility.lower() != expected["requested_visibility"]
    ):
        mismatches.append("visibility")
    event.execution_result = {
        "recorded": True,
        "object_identifiers": payload.object_identifiers[:50],
    }
    event.verification_result = {
        "matched": not mismatches,
        "mismatched_fields": mismatches,
        "observed": observed,
    }
    event.executed_at = datetime.now(UTC)
    event.verified_at = datetime.now(UTC)
    if mismatches:
        event.status = EgressEventStatus.MISMATCHED
        db.add(
            EgressFinding(
                organization_id=event.organization_id,
                event_id=event.id,
                title="Egress execution differed from approved action",
                description=(
                    "Observed GitHub state did not match the approved repository or visibility."
                ),
            )
        )
        record_egress_event("verification_mismatch")
    else:
        event.status = EgressEventStatus.VERIFIED
    record_audit(
        db,
        organization_id=event.organization_id,
        actor_id=user.id,
        action="egress.execution.verify",
        object_type="egress_event",
        object_id=event.id,
        decision=event.status.value,
        reason_code="EXECUTION_MISMATCH" if mismatches else "EXECUTION_MATCH",
    )
    db.commit()
    return _serialize_event(event)


@router.get("/events")
def list_events(
    organization_id: str,
    decision: str = "",
    destination: str = "",
    limit: int = 100,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    membership_for(db, user.id, organization_id)
    query = select(EgressEvent).where(EgressEvent.organization_id == organization_id)
    if decision:
        query = query.where(EgressEvent.decision == decision)
    if destination:
        query = query.where(EgressEvent.destination.ilike(f"%{destination[:200]}%"))
    events = db.scalars(
        query.order_by(EgressEvent.created_at.desc()).limit(min(max(limit, 1), 500))
    )
    return [_serialize_event(event) for event in events]


@router.get("/events/{event_id}")
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    event = db.get(EgressEvent, event_id)
    if not event:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Egress event not found")
    membership_for(db, user.id, event.organization_id)
    artifacts = list(db.scalars(select(EgressArtifact).where(EgressArtifact.event_id == event.id)))
    response = _serialize_event(event)
    response["normalized_request"] = event.normalized_request
    response["artifacts"] = [
        {
            "id": item.id,
            "filename": item.filename,
            "verified_mime_type": item.verified_mime_type,
            "size": item.size,
            "sha256": item.sha256,
            "classification": item.classification,
            "canonical_classification": normalize_classifications(item.classification),
            "findings": item.findings,
            "ocr_status": item.ocr_status,
            "quarantined": bool(item.quarantine_reference),
        }
        for item in artifacts
    ]
    return response


@router.get("/events/{event_id}/evidence")
def export_evidence(
    event_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    detail = get_event(event_id, db, user)
    return {
        "format": "cypheryn-egress-evidence-v1",
        "exported_at": datetime.now(UTC).isoformat(),
        "event": detail,
        "integrity": {
            "algorithm": "SHA-256",
            "valid": detail["integrity_valid"],
            "event_hash": detail["event_hash"],
            "previous_event_hash": detail["previous_event_hash"],
        },
    }


@router.get("/overview")
def overview(
    organization_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    membership_for(db, user.id, organization_id)
    events = list(
        db.scalars(select(EgressEvent).where(EgressEvent.organization_id == organization_id))
    )
    event_ids = [event.id for event in events]
    sensitive_artifacts = 0
    if event_ids:
        artifacts = db.scalars(select(EgressArtifact).where(EgressArtifact.event_id.in_(event_ids)))
        sensitive_artifacts = sum(bool(artifact.classification) for artifact in artifacts)
    return {
        "protected_agents": db.scalar(
            select(func.count(ProtectedAgent.id)).where(
                ProtectedAgent.organization_id == organization_id
            )
        )
        or 0,
        "evaluated_actions": len(events),
        "allowed_actions": sum(item.decision == EgressDecision.ALLOW for item in events),
        "blocked_actions": sum(
            item.decision in {EgressDecision.BLOCK, EgressDecision.QUARANTINE} for item in events
        ),
        "pending_approvals": sum(
            item.decision == EgressDecision.REQUIRE_APPROVAL and item.approval_id is None
            for item in events
        ),
        "sensitive_artifacts": sensitive_artifacts,
        "unexpected_public_repositories": sum(
            "PUBLIC_REPOSITORY_PROHIBITED" in item.reason_codes for item in events
        ),
        "enforcement_failures": sum(item.status == EgressEventStatus.MISMATCHED for item in events),
        "provider_health": {
            "builtin-patterns": "Live Verified",
            "tesseract": "Installed check at scan time",
        },
    }


@router.get("/policies")
def list_policies(
    organization_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[dict]:
    membership = membership_for(db, user.id, organization_id)
    policies = db.scalars(
        select(EgressPolicy)
        .where(EgressPolicy.organization_id == organization_id)
        .order_by(EgressPolicy.created_at.desc())
    )
    return [
        {
            "id": item.id,
            "name": item.name,
            "version": item.version,
            "state": item.state,
            "enforcement_mode": item.enforcement_mode,
            "integrity_hash": item.integrity_hash,
            "rules": item.rules
            if membership.role == MembershipRole.ORGANIZATION_ADMIN
            else {"summary": "Administrator-managed policy"},
        }
        for item in policies
    ]
