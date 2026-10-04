from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import record_audit
from .auth import (
    WorkloadPrincipal,
    get_current_user,
    get_workload_principal,
    require_organization_admin,
)
from .config import Settings, get_settings
from .database import get_db
from .destination_security import UnsafeDestination, canonicalize_destination
from .egress import digest, seal_event, status_for, verify_event
from .models import (
    AgentCapability,
    AgentCapabilityGrant,
    EgressDecision,
    EgressEvent,
    EgressPolicy,
    ProtectedAgent,
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
)

router = APIRouter(prefix="/api/v1/security", tags=["agent-security-control-plane"])
CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$")
SENSITIVE_METADATA_KEYS = {"authorization", "credential", "password", "secret", "token"}


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


def _receipt(event: EgressEvent) -> dict:
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
        "destination_binding": {
            "canonical_identifier": event.destination,
            "resolved_addresses": event.normalized_request.get("resolved_addresses", []),
            "redirects_require_reevaluation": True,
        },
        "expires_at": None,
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
    _admin(db, user, organization_id)
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
        agent.status = AgentStatus(payload.status.upper()).value.lower()
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid agent status") from exc
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
        for active in db.scalars(
            select(EgressPolicy).where(
                EgressPolicy.organization_id == payload.organization_id,
                EgressPolicy.name == "agent-security-default",
                EgressPolicy.state == "active",
            )
        ):
            active.state = "retired"
        policy = EgressPolicy(
            organization_id=payload.organization_id,
            name="agent-security-default",
            version=payload.version,
            scope={"agents": "all", "clients": "all", "environments": "all"},
            rules=rules,
            enforcement_mode=payload.mode.value.lower(),
            policy_type="agent_security",
            priority=payload.priority,
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
        return _receipt(existing)
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
        raise HTTPException(status.HTTP_409_CONFLICT, "Duplicate security request") from exc
    return _receipt(event)


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
    return _receipt(event)


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
    return [_receipt(event) for event in events]
