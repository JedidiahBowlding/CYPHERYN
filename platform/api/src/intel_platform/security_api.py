from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import record_audit
from .auth import (
    WorkloadPrincipal,
    get_current_user,
    get_workload_principal,
    membership_for,
    require_organization_admin,
)
from .config import Settings, get_settings
from .database import get_db
from .destination_security import UnsafeDestination, canonicalize_destination
from .egress import digest, seal_event, status_for, verify_event
from .models import (
    AgentCapability,
    AgentCapabilityGrant,
    DecisionAuthorization,
    EgressDecision,
    EgressEvent,
    EgressPolicy,
    ProtectedAgent,
    ProxyExecutionReceipt,
    SecurityClient,
    SecurityDestination,
    User,
)
from .security_contracts import (
    AgentStatus,
    ClientStatus,
    DataClassification,
    DestinationTrust,
    GrantStatus,
    PolicyMode,
    PublicSecurityDecision,
    internal_decision,
    normalize_classifications,
    public_decision,
)
from .security_control import (
    active_grant,
    default_policy,
    ensure_default_capabilities,
    evaluate_generic_policy,
    policy_integrity,
)

router = APIRouter(prefix="/api/v1/security", tags=["agent-security-control-plane"])
CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$")
SENSITIVE_METADATA_KEYS = {"authorization", "credential", "password", "secret", "token"}


def _serialize_idempotent_evaluation(
    db: Session, *, security_client_id: str, idempotency_hash: str
) -> None:
    """Serialize equal PostgreSQL idempotency keys before checking/inserting them.

    A unique constraint remains the final integrity boundary. The transaction-scoped
    advisory lock makes concurrent retries deterministic: once the first transaction
    commits, every waiter observes and returns its receipt instead of racing through
    the nonce check or the insert path and intermittently returning HTTP 409.
    """
    if db.get_bind().dialect.name != "postgresql":
        return
    material = f"cypheryn-security-evaluation:{security_client_id}:{idempotency_hash}"
    lock_key = int.from_bytes(hashlib.sha256(material.encode()).digest()[:8], "big", signed=True)
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})


def _safe_metadata(value: dict, label: str) -> dict:
    def inspect(item, depth: int = 0) -> None:
        if depth > 4:
            raise ValueError(f"{label} nesting is too deep")
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = str(key).lower()
                if any(word in normalized for word in SENSITIVE_METADATA_KEYS):
                    raise ValueError(f"{label} must not contain credentials or secrets")
                inspect(nested, depth + 1)
        elif isinstance(item, list):
            if len(item) > 100:
                raise ValueError(f"{label} lists are too large")
            for nested in item:
                inspect(nested, depth + 1)
        elif isinstance(item, str) and len(item) > 1000:
            raise ValueError(f"{label} values are too long")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValueError(f"{label} contains an unsupported value")

    inspect(value)
    if len(json.dumps(value, sort_keys=True, separators=(",", ":"))) > 16_384:
        raise ValueError(f"{label} is too large")
    return value


class SecurityClientCreate(BaseModel):
    organization_id: str
    external_client_id: str = Field(
        min_length=3, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    name: str = Field(min_length=1, max_length=200)
    environment: str = Field(default="production", min_length=1, max_length=80)
    credential_reference: str = Field(default="", max_length=300, pattern=r"^[A-Za-z0-9._:/-]*$")


class AgentCreate(BaseModel):
    organization_id: str
    security_client_id: str
    name: str = Field(min_length=1, max_length=200)
    agent_type: str = Field(default="ai_agent", max_length=80)
    environment: str = Field(default="production", max_length=80)
    owner_metadata: dict = Field(default_factory=dict, max_length=50)

    @field_validator("owner_metadata")
    @classmethod
    def safe_owner_metadata(cls, value: dict) -> dict:
        return _safe_metadata(value, "owner_metadata")


class StatusUpdate(BaseModel):
    status: str


class CapabilityCreate(BaseModel):
    organization_id: str
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=500)
    risk_level: str = Field(default="standard", max_length=30)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not CAPABILITY_PATTERN.fullmatch(normalized):
            raise ValueError("Capability names must use a dotted lower-case namespace")
        return normalized


class GrantCreate(BaseModel):
    organization_id: str
    capability: str
    environment: str = Field(default="production", max_length=80)
    resource_scope: dict = Field(default_factory=dict)
    expires_at: datetime | None = None

    @field_validator("resource_scope")
    @classmethod
    def safe_resource_scope(cls, value: dict) -> dict:
        return _safe_metadata(value, "resource_scope")


class DestinationCreate(BaseModel):
    organization_id: str
    destination: str = Field(min_length=1, max_length=2048)
    destination_type: str = Field(default="https", max_length=60)
    service_identity: str = Field(default="", max_length=255)
    environment: str = Field(default="production", max_length=80)
    trust_state: DestinationTrust = DestinationTrust.UNKNOWN
    reputation_metadata: dict = Field(default_factory=dict, max_length=50)

    @field_validator("reputation_metadata")
    @classmethod
    def safe_reputation_metadata(cls, value: dict) -> dict:
        return _safe_metadata(value, "reputation_metadata")


class DestinationTrustUpdate(BaseModel):
    trust_state: DestinationTrust


class ClientCredentialRotation(BaseModel):
    credential_reference: str = Field(max_length=300, pattern=r"^[A-Za-z0-9._:/-]+$")


class GenericPolicyRules(BaseModel):
    model_config = {"extra": "forbid"}
    deny_destination_states: list[DestinationTrust] = Field(default_factory=list)
    deny_sensitive_to_states: list[DestinationTrust] = Field(default_factory=list)
    sensitive_classifications: list[DataClassification] = Field(default_factory=list)
    require_approval_destination_states: list[DestinationTrust] = Field(default_factory=list)
    require_approval_capabilities: list[str] = Field(default_factory=list, max_length=100)
    default: PublicSecurityDecision = PublicSecurityDecision.DENY


class PolicyCreate(BaseModel):
    organization_id: str
    version: str = Field(min_length=1, max_length=40)
    mode: PolicyMode = PolicyMode.ENFORCE
    rules: GenericPolicyRules
    priority: int = Field(default=100, ge=0, le=10000)


class SecurityEvaluationRequest(BaseModel):
    agent_id: str
    action: str = Field(min_length=1, max_length=160)
    capability: str = Field(min_length=3, max_length=160)
    destination: str = Field(min_length=1, max_length=2048)
    environment: str = Field(default="production", max_length=80)
    data_classifications: list[DataClassification] = Field(default_factory=list, max_length=20)
    resource_scope: dict = Field(default_factory=dict, max_length=100)
    context: dict = Field(default_factory=dict, max_length=100)
    requested_decision: str = Field(default="ALLOW", pattern=r"^ALLOW$")
    request_id: str = Field(min_length=8, max_length=128)
    idempotency_key: str = Field(min_length=16, max_length=255)
    nonce: str = Field(min_length=16, max_length=255)
    timestamp: datetime
    approval_reference: str = Field(default="", max_length=36)

    @field_validator("resource_scope", "context")
    @classmethod
    def safe_request_metadata(cls, value: dict, info) -> dict:
        return _safe_metadata(value, info.field_name)


class DecisionValidationRequest(BaseModel):
    action: str = Field(min_length=1, max_length=160)
    capability: str = Field(min_length=3, max_length=160)
    destination: str = Field(min_length=1, max_length=2048)
    environment: str = Field(default="production", max_length=80)
    resource_scope: dict = Field(default_factory=dict, max_length=100)
    connected_address: str = Field(min_length=2, max_length=45)
    consume: bool = False

    @field_validator("resource_scope")
    @classmethod
    def safe_validation_scope(cls, value: dict) -> dict:
        return _safe_metadata(value, "resource_scope")


class ProxyReceiptStart(BaseModel):
    capability: str = Field(min_length=3, max_length=160)
    method: str = Field(min_length=3, max_length=12, pattern=r"^[A-Z]+$")
    pinned_address: str = Field(min_length=2, max_length=45)
    correlation_id: str = Field(min_length=8, max_length=128)
    request_body_hash: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")
    request_classifications: list[str] = Field(default_factory=list, max_length=20)
    proxy_replica_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class ProxyReceiptFinish(BaseModel):
    outcome: str = Field(min_length=2, max_length=80, pattern=r"^[A-Z_]+$")
    security_reason: str = Field(default="", max_length=500)
    response_status: int | None = Field(default=None, ge=100, le=599)
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    redirect_count: int = Field(default=0, ge=0, le=10)
    latency_ms: int = Field(default=0, ge=0)
    request_classifications: list[str] | None = Field(default=None, max_length=20)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _admin(db: Session, user: User, organization_id: str) -> None:
    require_organization_admin(db, user.id, organization_id)


def _client_for_principal(
    principal: WorkloadPrincipal = Depends(get_workload_principal),
    db: Session = Depends(get_db),
) -> SecurityClient:
    client = db.scalar(
        select(SecurityClient).where(SecurityClient.external_client_id == principal.client_id)
    )
    if client is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown workload client")
    if client.status.upper() != ClientStatus.ACTIVE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Workload client is not active")
    return client


def _operation_fingerprint(
    *,
    agent_id: str,
    action: str,
    capability: str,
    canonical_destination: str,
    environment: str,
    resource_scope: dict,
    classifications: list[str],
) -> str:
    return digest(
        {
            "agent_id": agent_id,
            "action": action,
            "capability": capability,
            "destination": canonical_destination,
            "environment": environment,
            "resource_scope": resource_scope,
            "data_classifications": classifications,
        }
    )


def _authorization(db: Session, decision_id: str) -> DecisionAuthorization | None:
    return db.get(DecisionAuthorization, decision_id)


def _receipt(
    event: EgressEvent, authorization: DecisionAuthorization | None = None
) -> dict:
    destination_binding = {
        "canonical_identifier": event.destination,
        "resolved_addresses": event.normalized_request.get("resolved_addresses", []),
        "redirects_require_reevaluation": True,
    }
    if authorization:
        destination_binding.update(
            {
                "scheme": authorization.scheme,
                "hostname": authorization.hostname,
                "port": authorization.port,
                "resolution_time": authorization.resolution_time.isoformat(),
                "resolution_expires_at": authorization.resolution_expires_at.isoformat(),
                "connection_contract": "pin_connected_address_and_validate_before_execution",
            }
        )
    return {
        "decision_id": event.id,
        "decision": public_decision(event.effective_decision),
        "requested_decision": event.normalized_request.get("requested_decision", "ALLOW"),
        "evaluated_decision": public_decision(event.evaluated_decision),
        "effective_decision": public_decision(event.effective_decision),
        "enforced_decision": public_decision(event.enforced_decision),
        "human_readable_reason": event.human_reason,
        "reason_codes": event.reason_codes,
        "policy_references": event.policy_trace,
        "policy_mode": event.policy_mode.upper(),
        "risk_score": event.risk_score,
        "required_approval": public_decision(event.evaluated_decision) == "REQUIRE_APPROVAL",
        "correlation_id": event.correlation_id,
        "request_id": event.request_id,
        "destination_binding": destination_binding,
        "authorization": (
            {
                "issued_at": authorization.issued_at.isoformat(),
                "expires_at": authorization.expires_at.isoformat(),
                "maximum_uses": authorization.maximum_uses,
                "use_count": authorization.use_count,
                "single_use": authorization.maximum_uses == 1,
                "operation_fingerprint": authorization.operation_fingerprint,
            }
            if authorization
            else None
        ),
        "expires_at": authorization.expires_at.isoformat() if authorization else None,
        "integrity": {"valid": verify_event(event), "event_hash": event.event_hash},
        "created_at": event.created_at.isoformat(),
    }


@router.post("/clients", status_code=201)
def create_security_client(
    payload: SecurityClientCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _admin(db, user, payload.organization_id)
    client = SecurityClient(
        organization_id=payload.organization_id,
        external_client_id=payload.external_client_id,
        name=payload.name,
        environment=payload.environment,
        status=ClientStatus.ACTIVE.value.lower(),
        credential_reference=payload.credential_reference,
        created_by_id=user.id,
    )
    db.add(client)
    ensure_default_capabilities(db)
    default_policy(db, payload.organization_id, user.id)
    record_audit(
        db,
        organization_id=payload.organization_id,
        actor_id=user.id,
        action="security.client.create",
        object_type="security_client",
        object_id=client.id,
    )
    db.commit()
    return {"id": client.id, "name": client.name, "status": client.status}


@router.get("/clients")
def list_security_clients(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    membership_for(db, user.id, organization_id)
    clients = db.scalars(
        select(SecurityClient).where(SecurityClient.organization_id == organization_id)
    )
    return [
        {
            "id": item.id,
            "name": item.name,
            "external_client_id": item.external_client_id,
            "environment": item.environment,
            "status": item.status,
            "credential_version": item.credential_version,
            "last_authenticated_at": item.last_authenticated_at,
        }
        for item in clients
    ]


@router.patch("/clients/{client_id}/status")
def update_client_status(
    client_id: str,
    payload: StatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    client = db.get(SecurityClient, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security client not found")
    _admin(db, user, client.organization_id)
    try:
        new_status = ClientStatus(payload.status.upper())
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid client status") from exc
    if client.status != new_status.value.lower():
        client.authorization_generation += 1
    client.status = new_status.value.lower()
    client.revoked_at = datetime.now(UTC) if new_status == ClientStatus.REVOKED else None
    record_audit(
        db,
        organization_id=client.organization_id,
        actor_id=user.id,
        action=f"security.client.{new_status.value.lower()}",
        object_type="security_client",
        object_id=client.id,
    )
    db.commit()
    return {"id": client.id, "status": client.status}


@router.post("/clients/{client_id}/rotate-credential")
def rotate_client_credential(
    client_id: str,
    payload: ClientCredentialRotation,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    client = db.get(SecurityClient, client_id)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security client not found")
    _admin(db, user, client.organization_id)
    client.credential_reference = payload.credential_reference
    client.credential_version += 1
    client.authorization_generation += 1
    client.updated_at = datetime.now(UTC)
    record_audit(
        db,
        organization_id=client.organization_id,
        actor_id=user.id,
        action="security.client.credential_rotated",
        object_type="security_client",
        object_id=client.id,
    )
    db.commit()
    return {"id": client.id, "credential_version": client.credential_version}


@router.post("/agents", status_code=201)
def create_agent(
    payload: AgentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _admin(db, user, payload.organization_id)
    client = db.get(SecurityClient, payload.security_client_id)
    if client is None or client.organization_id != payload.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security client not found")
    agent = ProtectedAgent(
        organization_id=payload.organization_id,
        security_client_id=client.id,
        name=payload.name,
        agent_type=payload.agent_type,
        owner_id=user.id,
        environment=payload.environment,
        owner_metadata=payload.owner_metadata,
        status=AgentStatus.ACTIVE.value.lower(),
    )
    db.add(agent)
    db.flush()
    record_audit(
        db,
        organization_id=payload.organization_id,
        actor_id=user.id,
        action="security.agent.create",
        object_type="protected_agent",
        object_id=agent.id,
    )
    db.commit()
    return {"id": agent.id, "name": agent.name, "status": agent.status}


@router.get("/agents")
def list_agents(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _admin(db, user, organization_id)
    agents = db.scalars(
        select(ProtectedAgent).where(ProtectedAgent.organization_id == organization_id)
    )
    return [
        {
            "id": item.id,
            "name": item.name,
            "status": item.status,
            "environment": item.environment,
            "risk_level": item.risk_level,
            "security_client_id": item.security_client_id,
        }
        for item in agents
    ]


@router.patch("/agents/{agent_id}/status")
def update_agent_status(
    agent_id: str,
    payload: StatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    agent = db.get(ProtectedAgent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Protected agent not found")
    _admin(db, user, agent.organization_id)
    try:
        new_status = AgentStatus(payload.status.upper()).value.lower()
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid agent status") from exc
    if agent.status != new_status:
        agent.authorization_generation += 1
    agent.status = new_status
    agent.updated_at = datetime.now(UTC)
    record_audit(
        db,
        organization_id=agent.organization_id,
        actor_id=user.id,
        action=f"security.agent.{agent.status}",
        object_type="protected_agent",
        object_id=agent.id,
    )
    db.commit()
    return {"id": agent.id, "status": agent.status}


@router.post("/capabilities", status_code=201)
def create_capability(
    payload: CapabilityCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _admin(db, user, payload.organization_id)
    capability = db.scalar(select(AgentCapability).where(AgentCapability.name == payload.name))
    if capability is None:
        capability = AgentCapability(
            name=payload.name,
            description=payload.description,
            risk_level=payload.risk_level,
        )
        db.add(capability)
        db.flush()
    db.commit()
    return {"id": capability.id, "name": capability.name, "status": capability.status}


@router.get("/capabilities")
def list_capabilities(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _admin(db, user, organization_id)
    items = db.scalars(select(AgentCapability).order_by(AgentCapability.name))
    return [
        {
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "risk_level": item.risk_level,
            "status": item.status,
        }
        for item in items
    ]


@router.post("/agents/{agent_id}/capability-grants", status_code=201)
def create_capability_grant(
    agent_id: str,
    payload: GrantCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _admin(db, user, payload.organization_id)
    agent = db.get(ProtectedAgent, agent_id)
    capability = db.scalar(
        select(AgentCapability).where(AgentCapability.name == payload.capability)
    )
    if agent is None or agent.organization_id != payload.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Protected agent not found")
    if capability is None or capability.status != "active":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability not found")
    grant = AgentCapabilityGrant(
        organization_id=payload.organization_id,
        agent_id=agent.id,
        capability_id=capability.id,
        environment=payload.environment,
        resource_scope=payload.resource_scope,
        resource_scope_hash=digest(payload.resource_scope),
        status=GrantStatus.ACTIVE.value.lower(),
        created_by_id=user.id,
        expires_at=payload.expires_at,
    )
    db.add(grant)
    db.flush()
    record_audit(
        db,
        organization_id=payload.organization_id,
        actor_id=user.id,
        action="security.capability.grant",
        object_type="agent_capability_grant",
        object_id=grant.id,
    )
    db.commit()
    return {"id": grant.id, "status": grant.status, "capability": capability.name}


@router.post("/capability-grants/{grant_id}/revoke")
def revoke_capability_grant(
    grant_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    grant = db.get(AgentCapabilityGrant, grant_id)
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability grant not found")
    _admin(db, user, grant.organization_id)
    if grant.status != GrantStatus.REVOKED.value.lower():
        grant.authorization_generation += 1
    grant.status = GrantStatus.REVOKED.value.lower()
    grant.revoked_at = datetime.now(UTC)
    record_audit(
        db,
        organization_id=grant.organization_id,
        actor_id=user.id,
        action="security.capability.revoke",
        object_type="agent_capability_grant",
        object_id=grant.id,
    )
    db.commit()
    return {"id": grant.id, "status": grant.status}


@router.get("/agents/{agent_id}/capability-grants")
def list_capability_grants(
    agent_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    agent = db.get(ProtectedAgent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Protected agent not found")
    _admin(db, user, agent.organization_id)
    rows = db.execute(
        select(AgentCapabilityGrant, AgentCapability)
        .join(AgentCapability, AgentCapability.id == AgentCapabilityGrant.capability_id)
        .where(AgentCapabilityGrant.agent_id == agent.id)
    )
    return [
        {
            "id": grant.id,
            "capability": capability.name,
            "environment": grant.environment,
            "resource_scope": grant.resource_scope,
            "status": grant.status,
            "expires_at": grant.expires_at,
        }
        for grant, capability in rows
    ]


@router.post("/destinations", status_code=201)
def create_destination(
    payload: DestinationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _admin(db, user, payload.organization_id)
    try:
        canonical = canonicalize_destination(payload.destination)
    except UnsafeDestination as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    destination = SecurityDestination(
        organization_id=payload.organization_id,
        canonical_identifier=canonical.canonical_identifier,
        destination_type=payload.destination_type,
        hostname=canonical.hostname,
        service_identity=payload.service_identity,
        environment=payload.environment,
        trust_state=payload.trust_state.value.lower(),
        reputation_metadata={
            **payload.reputation_metadata,
            "last_resolved_addresses": list(canonical.resolved_addresses),
            "last_resolved_at": datetime.now(UTC).isoformat(),
        },
        created_by_id=user.id,
    )
    db.add(destination)
    db.flush()
    record_audit(
        db,
        organization_id=payload.organization_id,
        actor_id=user.id,
        action="security.destination.create",
        object_type="security_destination",
        object_id=destination.id,
    )
    db.commit()
    return {
        "id": destination.id,
        "canonical_identifier": destination.canonical_identifier,
        "trust_state": destination.trust_state,
    }


@router.get("/destinations")
def list_destinations(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _admin(db, user, organization_id)
    items = db.scalars(
        select(SecurityDestination).where(SecurityDestination.organization_id == organization_id)
    )
    return [
        {
            "id": item.id,
            "canonical_identifier": item.canonical_identifier,
            "hostname": item.hostname,
            "environment": item.environment,
            "trust_state": item.trust_state,
        }
        for item in items
    ]


@router.patch("/destinations/{destination_id}/trust")
def update_destination_trust(
    destination_id: str,
    payload: DestinationTrustUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    destination = db.get(SecurityDestination, destination_id)
    if destination is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security destination not found")
    _admin(db, user, destination.organization_id)
    if destination.trust_state != payload.trust_state.value.lower():
        destination.authorization_generation += 1
    destination.trust_state = payload.trust_state.value.lower()
    destination.updated_at = datetime.now(UTC)
    record_audit(
        db,
        organization_id=destination.organization_id,
        actor_id=user.id,
        action=f"security.destination.{destination.trust_state}",
        object_type="security_destination",
        object_id=destination.id,
    )
    db.commit()
    return {"id": destination.id, "trust_state": destination.trust_state}


@router.post("/policies", status_code=201)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _admin(db, user, payload.organization_id)
    policy = default_policy(db, payload.organization_id, user.id, mode=payload.mode.value)
    rules = payload.rules.model_dump(mode="json")
    if policy.version == payload.version and policy.rules != rules:
        raise HTTPException(status.HTTP_409_CONFLICT, "Activated policy versions are immutable")
    if policy.version == payload.version and policy.enforcement_mode != payload.mode.value.lower():
        raise HTTPException(status.HTTP_409_CONFLICT, "Activated policy versions are immutable")
    if policy.version != payload.version:
        prior_policies = list(
            db.scalars(
                select(EgressPolicy).where(
                    EgressPolicy.organization_id == payload.organization_id,
                    EgressPolicy.name == "agent-security-default",
                )
            )
        )
        next_generation = max(
            (item.authorization_generation for item in prior_policies), default=0
        ) + 1
        for existing_policy in prior_policies:
            if existing_policy.state == "active":
                existing_policy.state = "retired"
                existing_policy.authorization_generation += 1
        policy = EgressPolicy(
            organization_id=payload.organization_id,
            name="agent-security-default",
            version=payload.version,
            scope={"agents": "all", "clients": "all", "environments": "all"},
            rules=rules,
            enforcement_mode=payload.mode.value.lower(),
            policy_type="agent_security",
            priority=payload.priority,
            authorization_generation=next_generation,
            state="active",
            integrity_hash="",
            created_by_id=user.id,
            approved_by_id=user.id,
            activated_at=datetime.now(UTC),
        )
        from .security_control import policy_integrity

        policy.integrity_hash = policy_integrity(policy)
        db.add(policy)
    db.commit()
    return {"id": policy.id, "version": policy.version, "mode": policy.enforcement_mode}


@router.get("/policies")
def list_security_policies(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _admin(db, user, organization_id)
    policies = db.scalars(
        select(EgressPolicy)
        .where(
            EgressPolicy.organization_id == organization_id,
            EgressPolicy.policy_type == "agent_security",
        )
        .order_by(EgressPolicy.created_at.desc())
    )
    return [
        {
            "id": item.id,
            "name": item.name,
            "version": item.version,
            "mode": item.enforcement_mode.upper(),
            "state": item.state,
            "priority": item.priority,
            "integrity_hash": item.integrity_hash,
        }
        for item in policies
    ]


@router.post("/evaluate", status_code=201)
def evaluate_security_request(
    payload: SecurityEvaluationRequest,
    request: Request,
    db: Session = Depends(get_db),
    client: SecurityClient = Depends(_client_for_principal),
    settings: Settings = Depends(get_settings),
) -> dict:
    now = datetime.now(UTC)
    timestamp = payload.timestamp
    if timestamp.tzinfo is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Timestamp must include timezone"
        )
    clock_delta = abs((now - timestamp.astimezone(UTC)).total_seconds())
    if clock_delta > settings.security_request_clock_skew_seconds:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Request timestamp is outside allowed clock skew"
        )
    idempotency_hash = _hash(payload.idempotency_key)
    nonce_hash = _hash(payload.nonce)
    _serialize_idempotent_evaluation(
        db,
        security_client_id=client.id,
        idempotency_hash=idempotency_hash,
    )
    request_metadata = {
        "agent_id": payload.agent_id,
        "action": payload.action,
        "capability": payload.capability,
        "destination": payload.destination,
        "environment": payload.environment,
        "data_classifications": [item.value for item in payload.data_classifications],
        "resource_scope": payload.resource_scope,
        "context_hash": digest(payload.context),
        "requested_decision": payload.requested_decision,
        "request_id": payload.request_id,
        "timestamp": timestamp.astimezone(UTC).isoformat(),
    }
    input_hash = digest(request_metadata)
    request_metadata["input_hash"] = input_hash
    agent = db.get(ProtectedAgent, payload.agent_id)
    if (
        agent is None
        or agent.organization_id != client.organization_id
        or agent.security_client_id != client.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Protected agent not found")
    existing = db.scalar(
        select(EgressEvent).where(
            EgressEvent.security_client_id == client.id,
            EgressEvent.idempotency_key_hash == idempotency_hash,
        )
    )
    if existing:
        if existing.normalized_request.get("input_hash") != input_hash:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Idempotency key was reused for a different request",
            )
        return _receipt(existing, _authorization(db, existing.id))
    replay = db.scalar(
        select(EgressEvent.id).where(
            EgressEvent.security_client_id == client.id,
            EgressEvent.nonce_hash == nonce_hash,
        )
    )
    if replay:
        raise HTTPException(status.HTTP_409_CONFLICT, "Request nonce has already been used")
    try:
        canonical = canonicalize_destination(payload.destination)
        classifications = normalize_classifications(
            [item.value for item in payload.data_classifications]
        )
    except (UnsafeDestination, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    destination = db.scalar(
        select(SecurityDestination).where(
            SecurityDestination.organization_id == client.organization_id,
            SecurityDestination.environment == payload.environment,
            SecurityDestination.canonical_identifier == canonical.canonical_identifier,
        )
    )
    request_metadata["canonical_destination"] = canonical.canonical_identifier
    request_metadata["resolved_addresses"] = list(canonical.resolved_addresses)
    request_hash = digest(request_metadata)
    grant = active_grant(
        db,
        organization_id=client.organization_id,
        agent=agent,
        capability_name=payload.capability,
        environment=payload.environment,
        resource_scope=payload.resource_scope,
    )
    policies = list(
        db.scalars(
            select(EgressPolicy)
            .where(
                EgressPolicy.organization_id == client.organization_id,
                EgressPolicy.policy_type == "agent_security",
                EgressPolicy.state == "active",
            )
            .order_by(EgressPolicy.priority.asc(), EgressPolicy.created_at.desc())
        )
    )
    if not policies:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "No active security policy")
    # Phase 1 supports one active deterministic policy version. Multiple active
    # versions fail closed rather than introducing ambiguous precedence.
    if len(policies) != 1:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Ambiguous active security policies"
        )
    policy = policies[0]
    result = evaluate_generic_policy(
        client=client,
        agent=agent,
        grant=grant,
        destination=destination,
        classifications=classifications,
        capability=payload.capability,
        environment=payload.environment,
        policy=policy,
    )
    internal_effective = internal_decision(result.effective_decision)
    event = EgressEvent(
        organization_id=client.organization_id,
        agent_id=agent.id,
        actor_id=None,
        security_client_id=client.id,
        correlation_id=request.headers.get("X-Correlation-ID", "")[:128] or payload.request_id,
        action_type=payload.action,
        destination=canonical.canonical_identifier,
        capability=payload.capability,
        environment=payload.environment,
        resource_scope=payload.resource_scope,
        data_classifications=classifications,
        normalized_request=request_metadata,
        request_hash=request_hash,
        decision=EgressDecision(internal_effective),
        reason_codes=result.reason_codes,
        human_reason=result.reason,
        policy_id=policy.id,
        policy_version=policy.version,
        policy_trace=result.policy_trace,
        policy_mode=result.policy_mode.lower(),
        evaluated_decision=internal_decision(result.evaluated_decision),
        effective_decision=internal_effective,
        enforced_decision=internal_decision(result.enforced_decision),
        risk_score=0,
        request_id=payload.request_id,
        idempotency_key_hash=idempotency_hash,
        nonce_hash=nonce_hash,
        request_timestamp=timestamp.astimezone(UTC),
        approval_id=payload.approval_reference or None,
        status=status_for(internal_effective),
    )
    db.add(event)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        concurrent = db.scalar(
            select(EgressEvent).where(
                EgressEvent.security_client_id == client.id,
                EgressEvent.idempotency_key_hash == idempotency_hash,
            )
        )
        if concurrent and concurrent.normalized_request.get("input_hash") == input_hash:
            return _receipt(concurrent, _authorization(db, concurrent.id))
        raise HTTPException(status.HTTP_409_CONFLICT, "Duplicate security request") from exc
    authorization = None
    if (
        result.evaluated_decision == PublicSecurityDecision.ALLOW.value
        and result.effective_decision == PublicSecurityDecision.ALLOW.value
        and grant is not None
        and destination is not None
    ):
        issued_at = datetime.now(UTC)
        high_consequence = payload.capability in {
            "commerce.purchase",
            "email.send",
            "database.write",
            "code.execute",
        }
        authorization = DecisionAuthorization(
            decision_id=event.id,
            organization_id=client.organization_id,
            security_client_id=client.id,
            agent_id=agent.id,
            grant_id=grant.id,
            destination_id=destination.id,
            policy_id=policy.id,
            client_generation=client.authorization_generation,
            agent_generation=agent.authorization_generation,
            grant_generation=grant.authorization_generation,
            destination_generation=destination.authorization_generation,
            policy_generation=policy.authorization_generation,
            operation_fingerprint=_operation_fingerprint(
                agent_id=agent.id,
                action=payload.action,
                capability=payload.capability,
                canonical_destination=canonical.canonical_identifier,
                environment=payload.environment,
                resource_scope=payload.resource_scope,
                classifications=classifications,
            ),
            canonical_destination=canonical.canonical_identifier,
            scheme=canonical.scheme,
            hostname=canonical.hostname,
            port=canonical.port,
            resolved_addresses=list(canonical.resolved_addresses),
            resolution_time=issued_at,
            resolution_expires_at=issued_at
            + timedelta(seconds=settings.security_resolution_ttl_seconds),
            issued_at=issued_at,
            expires_at=issued_at
            + timedelta(seconds=settings.security_authorization_ttl_seconds),
            maximum_uses=1 if high_consequence else None,
        )
        db.add(authorization)
        db.flush()
    seal_event(db, event)
    client.last_authenticated_at = now
    agent.last_seen_at = now
    record_audit(
        db,
        organization_id=client.organization_id,
        actor_id=None,
        security_client_id=client.id,
        action=f"security.evaluate.{result.evaluated_decision.lower()}",
        object_type="egress_event",
        object_id=event.id,
        decision=result.enforced_decision,
        reason_code=",".join(result.reason_codes),
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        concurrent = db.scalar(
            select(EgressEvent).where(
                EgressEvent.security_client_id == client.id,
                EgressEvent.idempotency_key_hash == idempotency_hash,
            )
        )
        if concurrent and concurrent.normalized_request.get("input_hash") == input_hash:
            return _receipt(concurrent, _authorization(db, concurrent.id))
        raise HTTPException(status.HTTP_409_CONFLICT, "Duplicate security request") from exc
    return _receipt(event, authorization)


@router.post("/decisions/{decision_id}/validate")
def validate_decision_authorization(
    decision_id: str,
    payload: DecisionValidationRequest,
    db: Session = Depends(get_db),
    client: SecurityClient = Depends(_client_for_principal),
) -> dict:
    event = db.get(EgressEvent, decision_id)
    if (
        event is None
        or event.organization_id != client.organization_id
        or event.security_client_id != client.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security decision not found")
    authorization = db.scalar(
        select(DecisionAuthorization)
        .where(DecisionAuthorization.decision_id == decision_id)
        .with_for_update()
    )
    if authorization is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Decision does not carry execution authority"
        )

    now = datetime.now(UTC)
    reasons: list[str] = []
    agent = db.get(ProtectedAgent, authorization.agent_id)
    grant = db.get(AgentCapabilityGrant, authorization.grant_id)
    destination = db.get(SecurityDestination, authorization.destination_id)
    policy = db.get(EgressPolicy, authorization.policy_id)
    if event.evaluated_decision != "ALLOW" or event.enforced_decision != "ALLOW":
        reasons.append("DECISION_NOT_ALLOW")
    if authorization.revoked_at is not None:
        reasons.append("AUTHORIZATION_REVOKED")
    expires_at = authorization.expires_at.replace(
        tzinfo=authorization.expires_at.tzinfo or UTC
    )
    if expires_at <= now:
        reasons.append("AUTHORIZATION_EXPIRED")
    resolution_expires_at = authorization.resolution_expires_at.replace(
        tzinfo=authorization.resolution_expires_at.tzinfo or UTC
    )
    if resolution_expires_at <= now:
        reasons.append("RESOLUTION_EXPIRED")
    if client.authorization_generation != authorization.client_generation:
        reasons.append("CLIENT_AUTHORITY_CHANGED")
    if agent is None or agent.organization_id != client.organization_id:
        reasons.append("AGENT_NOT_FOUND")
    elif (
        agent.status != "active"
        or agent.authorization_generation != authorization.agent_generation
    ):
        reasons.append("AGENT_AUTHORITY_CHANGED")
    if grant is None or grant.organization_id != client.organization_id:
        reasons.append("CAPABILITY_GRANT_NOT_FOUND")
    else:
        grant_expires_at = grant.expires_at
        if grant_expires_at is not None and grant_expires_at.tzinfo is None:
            grant_expires_at = grant_expires_at.replace(tzinfo=UTC)
        if (
            grant.status != "active"
            or grant.authorization_generation != authorization.grant_generation
            or (grant_expires_at is not None and grant_expires_at <= now)
        ):
            reasons.append("CAPABILITY_AUTHORITY_CHANGED")
    if destination is None or destination.organization_id != client.organization_id:
        reasons.append("DESTINATION_NOT_FOUND")
    elif (
        destination.trust_state not in {"trusted", "approved"}
        or destination.authorization_generation != authorization.destination_generation
    ):
        reasons.append("DESTINATION_AUTHORITY_CHANGED")
    if policy is None or policy.organization_id != client.organization_id:
        reasons.append("POLICY_NOT_FOUND")
    elif (
        policy.state != "active"
        or policy.authorization_generation != authorization.policy_generation
        or policy.integrity_hash != policy_integrity(policy)
    ):
        reasons.append("POLICY_AUTHORITY_CHANGED")

    try:
        canonical = canonicalize_destination(payload.destination)
        connected_address = ipaddress.ip_address(payload.connected_address).compressed
        if not ipaddress.ip_address(connected_address).is_global:
            raise UnsafeDestination("Connected address is not public")
    except (UnsafeDestination, ValueError):
        canonical = None
        connected_address = ""
        reasons.append("DESTINATION_BINDING_INVALID")
    if canonical is not None:
        if (
            canonical.canonical_identifier != authorization.canonical_destination
            or canonical.scheme != authorization.scheme
            or canonical.port != authorization.port
        ):
            reasons.append("DESTINATION_BINDING_MISMATCH")
        bound_addresses = set(authorization.resolved_addresses)
        current_addresses = set(canonical.resolved_addresses)
        if current_addresses != bound_addresses:
            reasons.append("RESOLUTION_BINDING_CHANGED")
        if connected_address not in bound_addresses:
            reasons.append("CONNECTED_ADDRESS_NOT_AUTHORIZED")
    fingerprint = _operation_fingerprint(
        agent_id=event.agent_id,
        action=payload.action,
        capability=payload.capability,
        canonical_destination=(
            canonical.canonical_identifier if canonical else payload.destination
        ),
        environment=payload.environment,
        resource_scope=payload.resource_scope,
        classifications=event.data_classifications,
    )
    if fingerprint != authorization.operation_fingerprint:
        reasons.append("OPERATION_BINDING_MISMATCH")
    if (
        authorization.maximum_uses is not None
        and authorization.use_count >= authorization.maximum_uses
    ):
        reasons.append("AUTHORIZATION_EXHAUSTED")

    valid = not reasons
    consumed = False
    if valid and payload.consume:
        authorization.use_count += 1
        consumed = True
    record_audit(
        db,
        organization_id=client.organization_id,
        actor_id=None,
        security_client_id=client.id,
        action="security.authorization.validated" if valid else "security.authorization.denied",
        object_type="decision_authorization",
        object_id=decision_id,
        decision="allowed" if valid else "denied",
        reason_code="VALID" if valid else ",".join(sorted(set(reasons))),
    )
    db.commit()
    return {
        "decision_id": decision_id,
        "valid": valid,
        "decision": "ALLOW" if valid else "DENY",
        "reason_codes": sorted(set(reasons)),
        "consumed": consumed,
        "use_count": authorization.use_count,
        "maximum_uses": authorization.maximum_uses,
        "expires_at": authorization.expires_at.isoformat(),
        "resolution_expires_at": authorization.resolution_expires_at.isoformat(),
        "connection": {
            "canonical_destination": authorization.canonical_destination,
            "scheme": authorization.scheme,
            "hostname": authorization.hostname,
            "port": authorization.port,
            "approved_addresses": authorization.resolved_addresses,
            "connected_address": connected_address,
            "redirects_require_new_evaluation": True,
        },
    }


@router.get("/decisions/{decision_id}")
def get_decision(
    decision_id: str,
    db: Session = Depends(get_db),
    client: SecurityClient = Depends(_client_for_principal),
) -> dict:
    event = db.get(EgressEvent, decision_id)
    if (
        event is None
        or event.organization_id != client.organization_id
        or event.security_client_id != client.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security decision not found")
    return _receipt(event, _authorization(db, event.id))


@router.post("/decisions/{decision_id}/proxy-receipts", status_code=201)
def start_proxy_receipt(
    decision_id: str,
    payload: ProxyReceiptStart,
    db: Session = Depends(get_db),
    client: SecurityClient = Depends(_client_for_principal),
) -> dict:
    """Create a safe durable receipt before the proxy attempts final validation."""
    event = db.get(EgressEvent, decision_id)
    authorization = db.get(DecisionAuthorization, decision_id)
    if (
        event is None
        or authorization is None
        or event.organization_id != client.organization_id
        or event.security_client_id != client.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Security decision not found")
    try:
        pinned_address = ipaddress.ip_address(payload.pinned_address).compressed
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid pinned address"
        ) from exc
    if pinned_address not in set(authorization.resolved_addresses):
        raise HTTPException(status.HTTP_409_CONFLICT, "Pinned address is not authorized")
    if payload.capability != event.capability:
        raise HTTPException(status.HTTP_409_CONFLICT, "Capability does not match decision")
    expected_capability = "web.read" if payload.method in {"GET", "HEAD"} else "web.write"
    if payload.capability != expected_capability:
        raise HTTPException(status.HTTP_409_CONFLICT, "HTTP method is not authorized by capability")
    receipt = ProxyExecutionReceipt(
        decision_id=decision_id,
        organization_id=client.organization_id,
        security_client_id=client.id,
        agent_id=authorization.agent_id,
        capability=event.capability,
        canonical_destination=authorization.canonical_destination,
        pinned_address=pinned_address,
        method=payload.method,
        proxy_replica_id=payload.proxy_replica_id,
        outcome="PENDING_VALIDATION",
        security_reason="",
        correlation_id=payload.correlation_id,
        request_body_hash=payload.request_body_hash,
        request_classifications=sorted(set(payload.request_classifications)),
        started_at=datetime.now(UTC),
    )
    db.add(receipt)
    db.commit()
    return {"proxy_request_id": receipt.id, "outcome": receipt.outcome}


@router.patch("/proxy-receipts/{receipt_id}")
def finish_proxy_receipt(
    receipt_id: str,
    payload: ProxyReceiptFinish,
    db: Session = Depends(get_db),
    client: SecurityClient = Depends(_client_for_principal),
) -> dict:
    receipt = db.get(ProxyExecutionReceipt, receipt_id)
    if (
        receipt is None
        or receipt.organization_id != client.organization_id
        or receipt.security_client_id != client.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Proxy receipt not found")
    receipt.outcome = payload.outcome
    receipt.security_reason = payload.security_reason
    receipt.response_status = payload.response_status
    receipt.bytes_sent = payload.bytes_sent
    receipt.bytes_received = payload.bytes_received
    receipt.redirect_count = payload.redirect_count
    receipt.latency_ms = payload.latency_ms
    if payload.request_classifications is not None:
        receipt.request_classifications = sorted(set(payload.request_classifications))
    receipt.completed_at = datetime.now(UTC)
    db.commit()
    return {"proxy_request_id": receipt.id, "outcome": receipt.outcome}


@router.get("/proxy-receipts")
def list_proxy_receipts(
    organization_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _admin(db, user, organization_id)
    bounded_limit = max(1, min(limit, 500))
    receipts = db.scalars(
        select(ProxyExecutionReceipt)
        .where(ProxyExecutionReceipt.organization_id == organization_id)
        .order_by(ProxyExecutionReceipt.started_at.desc())
        .limit(bounded_limit)
    ).all()
    return [
        {
            "proxy_request_id": item.id,
            "decision_id": item.decision_id,
            "agent_id": item.agent_id,
            "capability": item.capability,
            "destination": item.canonical_destination,
            "method": item.method,
            "proxy_replica_id": item.proxy_replica_id,
            "outcome": item.outcome,
            "security_reason": item.security_reason,
            "response_status": item.response_status,
            "bytes_sent": item.bytes_sent,
            "bytes_received": item.bytes_received,
            "redirect_count": item.redirect_count,
            "latency_ms": item.latency_ms,
            "correlation_id": item.correlation_id,
            "started_at": item.started_at.isoformat(),
            "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        }
        for item in receipts
    ]


@router.get("/decisions")
def list_decisions(
    organization_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _admin(db, user, organization_id)
    events = db.scalars(
        select(EgressEvent)
        .where(
            EgressEvent.organization_id == organization_id,
            EgressEvent.security_client_id.is_not(None),
        )
        .order_by(EgressEvent.created_at.desc())
        .limit(min(max(limit, 1), 500))
    )
    return [_receipt(event, _authorization(db, event.id)) for event in events]
