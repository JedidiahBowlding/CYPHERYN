from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import record_audit
from .auth import get_current_user, membership_for
from .config import get_settings
from .database import get_db
from .federation import (
    FederationVerificationError,
    canonical_json,
    create_assertion,
    decode_public_key,
    identity_document,
    key_id,
    load_node_key,
    node_id,
    receive_assertion,
)
from .models import (
    FederatedAssertion,
    FederationPeer,
    FederationRateWindow,
    MembershipRole,
    User,
)
from .observability import record_federation_event
from .schemas import (
    FederatedAssertionCreate,
    FederatedAssertionRead,
    FederationPeerCreate,
    FederationPeerRead,
    FederationPeerStatusUpdate,
)

router = APIRouter(prefix="/api/federation/v1", tags=["federation"])


def _enabled():
    settings = get_settings()
    if not settings.federation_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Federation is disabled")
    return settings


def _admin(db: Session, user: User, organization_id: str) -> None:
    membership = membership_for(db, user.id, organization_id)
    if membership.role != MembershipRole.ORGANIZATION_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Organization admin required")


def _federation_actor(db: Session, peer: FederationPeer) -> User:
    subject = f"federation:{peer.node_id}"
    user = db.scalar(select(User).where(User.external_subject == subject))
    if user is None:
        user = User(external_subject=subject)
        db.add(user)
        db.flush()
    return user


def _enforce_rate_limit(
    db: Session, organization_id: str, issuer_node_id: str, limit: int
) -> None:
    now = datetime.now(UTC)
    window = db.scalar(
        select(FederationRateWindow)
        .where(
            FederationRateWindow.organization_id == organization_id,
            FederationRateWindow.issuer_node_id == issuer_node_id,
        )
        .with_for_update()
    )
    if window is None:
        db.add(
            FederationRateWindow(
                organization_id=organization_id,
                issuer_node_id=issuer_node_id,
                window_started_at=now,
                request_count=1,
            )
        )
        db.flush()
        return
    started = window.window_started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    if now - started >= timedelta(minutes=1):
        window.window_started_at = now
        window.request_count = 1
    elif window.request_count >= max(1, limit):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Federation rate limit exceeded")
    else:
        window.request_count += 1
    db.flush()


@router.get("/identity")
def federation_identity() -> dict:
    settings = _enabled()
    path = Path(settings.federation_key_path)
    if not path.is_file():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Node identity is not initialized")
    return identity_document(load_node_key(path), settings.federation_display_name)


@router.get("/capabilities")
def federation_capabilities() -> dict:
    _enabled()
    return {
        "protocol_versions": ["cypheryn-federation-v1"],
        "capabilities": ["signed-assertions-v1", "replay-protection-v1"],
        "central_dependency": False,
    }


@router.get("/health")
def federation_health() -> dict:
    settings = _enabled()
    return {
        "status": "ready" if Path(settings.federation_key_path).is_file() else "identity_missing",
        "federation_enabled": True,
    }


@router.get(
    "/organizations/{organization_id}/peers", response_model=list[FederationPeerRead]
)
def list_peers(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _enabled()
    membership_for(db, user.id, organization_id)
    return list(
        db.scalars(
            select(FederationPeer)
            .where(FederationPeer.organization_id == organization_id)
            .order_by(FederationPeer.created_at)
        )
    )


@router.post(
    "/organizations/{organization_id}/peers",
    response_model=FederationPeerRead,
    status_code=201,
)
def enroll_peer(
    organization_id: str,
    payload: FederationPeerCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _enabled()
    _admin(db, user, organization_id)
    public_key = decode_public_key(payload.public_key)
    if node_id(public_key) != payload.node_id or key_id(public_key) != payload.key_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Peer identity mismatch")
    peer = FederationPeer(
        organization_id=organization_id,
        node_id=payload.node_id,
        display_name=payload.display_name,
        base_url=str(payload.base_url) if payload.base_url else "",
        public_key=payload.public_key,
        key_id=payload.key_id,
        protocol_version=payload.protocol_version,
        capabilities=payload.capabilities,
        status="pending",
        enrolled_by_id=user.id,
    )
    try:
        db.add(peer)
        db.flush()
        record_audit(
            db,
            organization_id=organization_id,
            actor_id=user.id,
            action="federation.peer.added",
            object_type="federation_peer",
            object_id=peer.id,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Peer is already enrolled") from exc
    db.refresh(peer)
    return peer


@router.patch(
    "/organizations/{organization_id}/peers/{peer_id}", response_model=FederationPeerRead
)
def update_peer_status(
    organization_id: str,
    peer_id: str,
    payload: FederationPeerStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _enabled()
    _admin(db, user, organization_id)
    peer = db.scalar(
        select(FederationPeer).where(
            FederationPeer.id == peer_id, FederationPeer.organization_id == organization_id
        )
    )
    if peer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Peer not found")
    peer.status = payload.status
    peer.updated_at = datetime.now(UTC)
    if payload.status == "revoked":
        peer.revoked_at = datetime.now(UTC)
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action=f"federation.peer.{payload.status}",
        object_type="federation_peer",
        object_id=peer.id,
    )
    db.commit()
    db.refresh(peer)
    return peer


@router.post(
    "/organizations/{organization_id}/assertions",
    response_model=dict,
    status_code=201,
)
def create_outbound_assertion(
    organization_id: str,
    payload: FederatedAssertionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    settings = _enabled()
    _admin(db, user, organization_id)
    path = Path(settings.federation_key_path)
    if not path.is_file():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Node identity is not initialized")
    assertion = create_assertion(load_node_key(path), **payload.model_dump())
    fingerprint = hashlib.sha256(canonical_json(assertion)).hexdigest()
    record = FederatedAssertion(
        organization_id=organization_id,
        assertion_id=assertion["assertion_id"],
        issuer_node_id=assertion["issuer_node_id"],
        issuer_key_id=assertion["issuer_key_id"],
        assertion_type=assertion["assertion_type"],
        subject_type=assertion["subject_type"],
        subject_fingerprint=assertion["subject_fingerprint"],
        evidence_fingerprint=assertion["evidence_fingerprint"],
        payload_fingerprint=fingerprint,
        assertion=assertion,
        verification_status="locally_signed",
        trust_state="local",
        issued_at=datetime.fromisoformat(assertion["issued_at"]),
        expires_at=datetime.fromisoformat(assertion["expires_at"]),
    )
    db.add(record)
    db.flush()
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action="federation.assertion.created",
        object_type="federated_assertion",
        object_id=record.id,
    )
    db.commit()
    return assertion


@router.post(
    "/organizations/{organization_id}/assertions/inbound",
    response_model=FederatedAssertionRead,
    status_code=202,
)
def accept_assertion(
    organization_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    settings = _enabled()
    content_length = int(request.headers.get("content-length", "0") or 0)
    if content_length > settings.federation_max_assertion_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Assertion exceeds size limit")
    issuer = str(payload.get("issuer_node_id", ""))
    _enforce_rate_limit(
        db,
        organization_id,
        issuer[:96],
        settings.federation_rate_limit_per_minute,
    )
    peer = db.scalar(
        select(FederationPeer).where(
            FederationPeer.organization_id == organization_id,
            FederationPeer.node_id == issuer,
        )
    )
    if peer is None:
        record_federation_event("malformed")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown federation issuer")
    try:
        record = receive_assertion(
            db,
            organization_id=organization_id,
            peer=peer,
            assertion=payload,
            max_bytes=settings.federation_max_assertion_bytes,
        )
    except FederationVerificationError as exc:
        db.rollback()
        message = str(exc).lower()
        reason = "malformed"
        if "signature" in message or "identity mismatch" in message:
            reason = "signature_failure"
        elif "replay" in message:
            reason = "replay"
        elif "expired" in message:
            reason = "expired"
        elif "not trusted" in message:
            reason = "revoked_peer"
        record_federation_event(reason)
        actor = _federation_actor(db, peer)
        record_audit(
            db,
            organization_id=organization_id,
            actor_id=actor.id,
            action="federation.assertion.rejected",
            object_type="federated_assertion",
            object_id=str(payload.get("assertion_id", "unknown"))[-36:],
            decision="denied",
            reason_code="verification_failed",
        )
        db.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    actor = _federation_actor(db, peer)
    record_federation_event("accepted")
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=actor.id,
        action="federation.assertion.received",
        object_type="federated_assertion",
        object_id=record.id,
    )
    db.commit()
    db.refresh(record)
    return record


@router.get(
    "/organizations/{organization_id}/assertions",
    response_model=list[FederatedAssertionRead],
)
def list_assertions(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _enabled()
    membership_for(db, user.id, organization_id)
    return list(
        db.scalars(
            select(FederatedAssertion)
            .where(FederatedAssertion.organization_id == organization_id)
            .order_by(FederatedAssertion.received_at.desc())
        )
    )
