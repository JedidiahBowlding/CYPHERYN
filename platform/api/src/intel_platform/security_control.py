from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .egress import digest
from .models import (
    AgentCapability,
    AgentCapabilityGrant,
    EgressPolicy,
    ProtectedAgent,
    SecurityClient,
    SecurityDestination,
)
from .security_contracts import (
    DEFAULT_CAPABILITIES,
    AgentStatus,
    ClientStatus,
    DestinationTrust,
    GrantStatus,
    PolicyMode,
    PublicSecurityDecision,
)

GENERIC_POLICY_NAME = "agent-security-default"
GENERIC_POLICY_VERSION = "1.0.0"


def ensure_default_capabilities(db: Session) -> None:
    existing = set(db.scalars(select(AgentCapability.name)))
    for name in DEFAULT_CAPABILITIES:
        if name not in existing:
            db.add(
                AgentCapability(
                    name=name,
                    description=f"CYPHERYN standard agent capability: {name}",
                )
            )


@dataclass(frozen=True)
class PolicyResult:
    evaluated_decision: str
    effective_decision: str
    enforced_decision: str
    reason: str
    reason_codes: list[str]
    policy_trace: list[dict]
    policy_mode: str


def policy_integrity(policy: EgressPolicy) -> str:
    return digest(
        {
            "name": policy.name,
            "version": policy.version,
            "scope": policy.scope,
            "rules": policy.rules,
            "mode": policy.enforcement_mode,
            "type": policy.policy_type,
            "priority": policy.priority,
        }
    )


def default_policy(
    db: Session, organization_id: str, created_by_id: str, *, mode: str = "enforce"
) -> EgressPolicy:
    existing = db.scalar(
        select(EgressPolicy).where(
            EgressPolicy.organization_id == organization_id,
            EgressPolicy.name == GENERIC_POLICY_NAME,
            EgressPolicy.version == GENERIC_POLICY_VERSION,
        )
    )
    if existing:
        return existing
    rules = {
        "deny_destination_states": ["BLOCKED", "RESTRICTED"],
        "deny_sensitive_to_states": ["UNKNOWN", "RESTRICTED", "BLOCKED"],
        "sensitive_classifications": [
            "CONFIDENTIAL",
            "PERSONAL",
            "FINANCIAL",
            "AUTHENTICATION_SECRET",
            "SYSTEM_SECRET",
            "HIGHLY_RESTRICTED",
        ],
        "require_approval_destination_states": ["UNKNOWN"],
        "require_approval_capabilities": [
            "commerce.purchase",
            "email.send",
            "database.write",
            "code.execute",
        ],
        "default": "ALLOW",
    }
    policy = EgressPolicy(
        organization_id=organization_id,
        name=GENERIC_POLICY_NAME,
        version=GENERIC_POLICY_VERSION,
        scope={"agents": "all", "clients": "all", "environments": "all"},
        rules=rules,
        enforcement_mode=mode.lower(),
        policy_type="agent_security",
        priority=100,
        state="active",
        integrity_hash="",
        created_by_id=created_by_id,
        approved_by_id=created_by_id,
        activated_at=datetime.now(UTC),
    )
    policy.integrity_hash = policy_integrity(policy)
    db.add(policy)
    db.flush()
    return policy


def active_grant(
    db: Session,
    *,
    organization_id: str,
    agent: ProtectedAgent,
    capability_name: str,
    environment: str,
    resource_scope: dict,
) -> AgentCapabilityGrant | None:
    now = datetime.now(UTC)
    grants = db.scalars(
        select(AgentCapabilityGrant)
        .join(AgentCapability, AgentCapability.id == AgentCapabilityGrant.capability_id)
        .where(
            AgentCapabilityGrant.organization_id == organization_id,
            AgentCapabilityGrant.agent_id == agent.id,
            AgentCapabilityGrant.environment == environment,
            AgentCapabilityGrant.status == GrantStatus.ACTIVE.value.lower(),
            AgentCapability.name == capability_name,
            AgentCapability.status == "active",
        )
    )
    for grant in grants:
        unexpired = grant.expires_at is None or grant.expires_at.replace(
            tzinfo=grant.expires_at.tzinfo or UTC
        ) > now
        if unexpired and _scope_allows(grant.resource_scope, resource_scope):
            return grant
    return None


def _scope_allows(granted: dict, requested: dict) -> bool:
    if not granted:
        return True
    for key, allowed in granted.items():
        if key not in requested:
            return False
        actual = requested[key]
        if isinstance(allowed, list):
            actual_values = actual if isinstance(actual, list) else [actual]
            if not set(actual_values).issubset(set(allowed)):
                return False
        elif actual != allowed:
            return False
    return True


def _result(
    decision: str,
    reason: str,
    code: str,
    policy: EgressPolicy,
    trace: list[dict],
) -> PolicyResult:
    mode = PolicyMode(policy.enforcement_mode.upper())
    effective = decision if mode == PolicyMode.ENFORCE else PublicSecurityDecision.ALLOW.value
    return PolicyResult(
        evaluated_decision=decision,
        effective_decision=effective,
        enforced_decision=effective,
        reason=reason,
        reason_codes=[code],
        policy_trace=[*trace, {"policy_id": policy.id, "rule": code, "decision": decision}],
        policy_mode=mode.value,
    )


def evaluate_generic_policy(
    *,
    client: SecurityClient,
    agent: ProtectedAgent,
    grant: AgentCapabilityGrant | None,
    destination: SecurityDestination | None,
    classifications: list[str],
    capability: str,
    environment: str,
    policy: EgressPolicy,
) -> PolicyResult:
    trace: list[dict] = []
    if policy.state != "active" or policy.integrity_hash != policy_integrity(policy):
        return _result(
            PublicSecurityDecision.DENY,
            "Policy integrity or activation could not be verified.",
            "POLICY_INTEGRITY_FAILURE",
            policy,
            trace,
        )
    if client.status.upper() != ClientStatus.ACTIVE:
        return _result(
            PublicSecurityDecision.DENY,
            "The workload client is not active.",
            "CLIENT_NOT_ACTIVE",
            policy,
            trace,
        )
    if agent.status.upper() != AgentStatus.ACTIVE:
        return _result(
            PublicSecurityDecision.DENY,
            "The protected agent is not active.",
            "AGENT_NOT_ACTIVE",
            policy,
            trace,
        )
    if client.environment != environment or agent.environment != environment:
        return _result(
            PublicSecurityDecision.DENY,
            "The request environment does not match the client and agent scope.",
            "ENVIRONMENT_SCOPE_MISMATCH",
            policy,
            trace,
        )
    if grant is None:
        return _result(
            PublicSecurityDecision.DENY,
            f"The agent has no active grant for {capability}.",
            "CAPABILITY_NOT_GRANTED",
            policy,
            trace,
        )
    trust = destination.trust_state.upper() if destination else DestinationTrust.UNKNOWN.value
    if trust in set(policy.rules.get("deny_destination_states", [])):
        return _result(
            PublicSecurityDecision.DENY,
            f"The destination is {trust.lower()}.",
            "DESTINATION_PROHIBITED",
            policy,
            trace,
        )
    sensitive = set(classifications).intersection(
        policy.rules.get("sensitive_classifications", [])
    )
    if sensitive and trust in set(policy.rules.get("deny_sensitive_to_states", [])):
        return _result(
            PublicSecurityDecision.DENY,
            "Sensitive information cannot be transmitted to this destination.",
            "SENSITIVE_EGRESS_PROHIBITED",
            policy,
            trace,
        )
    if trust in set(policy.rules.get("require_approval_destination_states", [])):
        return _result(
            PublicSecurityDecision.REQUIRE_APPROVAL,
            "The destination is unknown and requires explicit approval.",
            "UNKNOWN_DESTINATION_APPROVAL",
            policy,
            trace,
        )
    if capability in set(policy.rules.get("require_approval_capabilities", [])):
        return _result(
            PublicSecurityDecision.REQUIRE_APPROVAL,
            "This capability requires explicit approval.",
            "CAPABILITY_APPROVAL_REQUIRED",
            policy,
            trace,
        )
    decision = str(policy.rules.get("default", "DENY")).upper()
    if decision not in {item.value for item in PublicSecurityDecision}:
        decision = PublicSecurityDecision.DENY.value
    return _result(
        decision,
        "The request satisfied the active deterministic policy.",
        "DEFAULT",
        policy,
        trace,
    )
