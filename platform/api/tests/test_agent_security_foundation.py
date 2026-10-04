from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from intel_platform.auth import WorkloadPrincipal, get_workload_principal
from intel_platform.config import Settings
from intel_platform.destination_security import UnsafeDestination, canonicalize_destination
from intel_platform.main import app
from intel_platform.models import EgressEvent, EgressPolicy, ProtectedAgent
from intel_platform.security_control import policy_integrity


def _foundation(client, *, destination_state="TRUSTED", destination="https://8.8.8.8"):
    organization = client.post("/api/v1/organizations", json={"name": "Agent Security"}).json()
    organization_id = organization["id"]
    security_client = client.post(
        "/api/v1/security/clients",
        json={
            "organization_id": organization_id,
            "external_client_id": "workload-client-test",
            "name": "Test workload",
            "credential_reference": "oidc://auth0/workload-client-test",
        },
    )
    assert security_client.status_code == 201, security_client.text
    client_id = security_client.json()["id"]
    agent = client.post(
        "/api/v1/security/agents",
        json={
            "organization_id": organization_id,
            "security_client_id": client_id,
            "name": "test-agent",
        },
    )
    assert agent.status_code == 201, agent.text
    agent_id = agent.json()["id"]
    capability = client.post(
        "/api/v1/security/capabilities",
        json={"organization_id": organization_id, "name": "web.read"},
    )
    assert capability.status_code == 201, capability.text
    grant = client.post(
        f"/api/v1/security/agents/{agent_id}/capability-grants",
        json={"organization_id": organization_id, "capability": "web.read"},
    )
    assert grant.status_code == 201, grant.text
    destination_response = client.post(
        "/api/v1/security/destinations",
        json={
            "organization_id": organization_id,
            "destination": destination,
            "trust_state": destination_state,
        },
    )
    assert destination_response.status_code == 201, destination_response.text
    return organization_id, client_id, agent_id, grant.json()["id"]


def _workload(client):
    app.dependency_overrides[get_workload_principal] = lambda: WorkloadPrincipal(
        subject="workload-client-test@clients", client_id="workload-client-test"
    )


def _evaluation(agent_id: str, **changes):
    payload = {
        "agent_id": agent_id,
        "action": "fetch",
        "capability": "web.read",
        "destination": "https://8.8.8.8/path-is-not-policy-identity",
        "environment": "production",
        "data_classifications": ["PUBLIC"],
        "resource_scope": {"method": "GET"},
        "context": {"purpose": "synthetic-test"},
        "request_id": "request-00000001",
        "idempotency_key": "idempotency-key-00000001",
        "nonce": "nonce-value-0000000001",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    payload.update(changes)
    return payload


def test_authenticated_workload_with_grant_and_trusted_destination_is_allowed(client):
    _, _, agent_id, _ = _foundation(client)
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.status_code == 201, response.text
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["policy_mode"] == "ENFORCE"
    assert response.json()["integrity"]["valid"] is True


def test_workload_authentication_is_required(client):
    _, _, agent_id, _ = _foundation(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.status_code == 401


def test_invalid_workload_token_is_rejected(monkeypatch):
    class InvalidJwks:
        def __init__(self, _url):
            pass

        def get_signing_key_from_jwt(self, _token):
            raise jwt.InvalidTokenError("synthetic invalid token")

    monkeypatch.setattr("intel_platform.auth.PyJWKClient", InvalidJwks)
    request = Request(
        {
            "type": "http",
            "headers": [(b"authorization", b"Bearer invalid-synthetic-token")],
        }
    )
    settings = Settings(
        oidc_issuer="https://issuer.example/",
        oidc_audience="cypheryn",
        oidc_jwks_url="https://issuer.example/.well-known/jwks.json",
    )
    with pytest.raises(HTTPException) as exc:
        get_workload_principal(request, settings)
    assert exc.value.status_code == 401


def test_interactive_oidc_token_cannot_authenticate_as_workload(monkeypatch):
    monkeypatch.setattr(
        "intel_platform.auth._bearer_claims",
        lambda _request, _settings: {"sub": "human-user", "azp": "browser-client"},
    )
    request = Request({"type": "http", "headers": []})
    with pytest.raises(HTTPException) as exc:
        get_workload_principal(request, Settings())
    assert exc.value.status_code == 401


def test_revoked_client_is_rejected_before_policy(client):
    _, client_id, agent_id, _ = _foundation(client)
    response = client.patch(
        f"/api/v1/security/clients/{client_id}/status", json={"status": "REVOKED"}
    )
    assert response.status_code == 200
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.status_code == 403


@pytest.mark.parametrize("agent_status", ["SUSPENDED", "REVOKED", "QUARANTINED"])
def test_inactive_agent_cannot_receive_allow(client, agent_status):
    _, _, agent_id, _ = _foundation(client)
    assert client.patch(
        f"/api/v1/security/agents/{agent_id}/status", json={"status": agent_status}
    ).status_code == 200
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.status_code == 201
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason_codes"] == ["AGENT_NOT_ACTIVE"]


def test_missing_and_revoked_capability_are_denied(client):
    _, _, agent_id, grant_id = _foundation(client)
    _workload(client)
    missing = client.post(
        "/api/v1/security/evaluate",
        json=_evaluation(
            agent_id,
            capability="email.send",
            request_id="request-missing-capability",
            idempotency_key="idempotency-missing-capability",
            nonce="nonce-missing-capability-0001",
        ),
    )
    assert missing.json()["reason_codes"] == ["CAPABILITY_NOT_GRANTED"]
    app.dependency_overrides.pop(get_workload_principal)
    assert client.post(f"/api/v1/security/capability-grants/{grant_id}/revoke").status_code == 200
    _workload(client)
    revoked = client.post(
        "/api/v1/security/evaluate",
        json=_evaluation(
            agent_id,
            request_id="request-revoked-capability",
            idempotency_key="idempotency-revoked-capability",
            nonce="nonce-revoked-capability-0001",
        ),
    )
    assert revoked.json()["decision"] == "DENY"


def test_blocked_destination_and_sensitive_unknown_destination_are_denied(client):
    _, _, agent_id, _ = _foundation(client, destination_state="BLOCKED")
    _workload(client)
    blocked = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert blocked.json()["reason_codes"] == ["DESTINATION_PROHIBITED"]

    unknown = client.post(
        "/api/v1/security/evaluate",
        json=_evaluation(
            agent_id,
            destination="https://1.1.1.1",
            data_classifications=["CONFIDENTIAL"],
            request_id="request-sensitive-unknown",
            idempotency_key="idempotency-sensitive-unknown",
            nonce="nonce-sensitive-unknown-001",
        ),
    )
    assert unknown.json()["reason_codes"] == ["SENSITIVE_EGRESS_PROHIBITED"]


@pytest.mark.parametrize(
    "destination",
    [
        "http://example.com",
        "https://127.0.0.1",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1",
        "https://user:password@example.com",
        "https://example.com:8443",
    ],
)
def test_destination_canonicalization_rejects_ssrf_bypasses(destination):
    with pytest.raises(UnsafeDestination):
        canonicalize_destination(destination, resolve=False)


def test_dns_rebinding_answer_fails_closed():
    def private_answer(*_args, **_kwargs):
        return [(2, 1, 6, "", ("192.168.1.10", 443))]

    with pytest.raises(UnsafeDestination):
        canonicalize_destination("https://public.example", resolver=private_answer)


def test_idna_and_redirect_paths_are_canonicalized_to_a_bound_origin():
    canonical = canonicalize_destination(
        "https://xn--bcher-kva.example/a?next=https://127.0.0.1", resolve=False
    )
    assert canonical.hostname == "xn--bcher-kva.example"
    assert canonical.canonical_identifier == "https://xn--bcher-kva.example"


def test_block_maps_to_public_deny_without_mutating_internal_record(client):
    _, _, agent_id, _ = _foundation(client, destination_state="BLOCKED")
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.json()["evaluated_decision"] == "DENY"
    with client.app.state.testing_session() as db:
        event = db.get(EgressEvent, response.json()["decision_id"])
        assert event.evaluated_decision == "BLOCK"


def test_shadow_records_denial_but_does_not_enforce_it(client):
    organization_id, _, agent_id, _ = _foundation(client, destination_state="BLOCKED")
    with client.app.state.testing_session() as db:
        policy = db.scalar(
            select(EgressPolicy).where(
                EgressPolicy.organization_id == organization_id,
                EgressPolicy.policy_type == "agent_security",
            )
        )
        policy.enforcement_mode = "shadow"
        policy.integrity_hash = policy_integrity(policy)
        db.commit()
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    body = response.json()
    assert body["evaluated_decision"] == "DENY"
    assert body["effective_decision"] == "ALLOW"
    assert body["enforced_decision"] == "ALLOW"
    assert body["policy_mode"] == "SHADOW"


def test_idempotency_and_nonce_replay_protection(client):
    _, _, agent_id, _ = _foundation(client)
    _workload(client)
    payload = _evaluation(agent_id)
    first = client.post("/api/v1/security/evaluate", json=payload)
    second = client.post("/api/v1/security/evaluate", json=payload)
    assert first.json()["decision_id"] == second.json()["decision_id"]
    changed = client.post(
        "/api/v1/security/evaluate", json={**payload, "action": "changed-action"}
    )
    assert changed.status_code == 409
    replay = client.post(
        "/api/v1/security/evaluate",
        json={
            **payload,
            "request_id": "request-replay-nonce",
            "idempotency_key": "different-idempotency-key-0001",
        },
    )
    assert replay.status_code == 409


def test_sensitive_context_is_rejected_instead_of_stored(client):
    _, _, agent_id, _ = _foundation(client)
    _workload(client)
    response = client.post(
        "/api/v1/security/evaluate",
        json=_evaluation(agent_id, context={"authorization_token": "synthetic-secret-value"}),
    )
    assert response.status_code == 422
    assert "must not contain credentials or secrets" in response.text


def test_policy_integrity_failure_denies(client):
    organization_id, _, agent_id, _ = _foundation(client)
    with client.app.state.testing_session() as db:
        policy = db.scalar(
            select(EgressPolicy).where(
                EgressPolicy.organization_id == organization_id,
                EgressPolicy.policy_type == "agent_security",
            )
        )
        policy.integrity_hash = "0" * 64
        db.commit()
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.json()["reason_codes"] == ["POLICY_INTEGRITY_FAILURE"]


def test_environment_scope_mismatch_is_denied(client):
    _, _, agent_id, _ = _foundation(client)
    _workload(client)
    response = client.post(
        "/api/v1/security/evaluate",
        json=_evaluation(
            agent_id,
            environment="development",
            request_id="request-environment-mismatch",
            idempotency_key="idempotency-environment-mismatch",
            nonce="nonce-environment-mismatch-01",
        ),
    )
    assert response.json()["reason_codes"] == ["ENVIRONMENT_SCOPE_MISMATCH"]


def test_expired_grant_is_denied(client):
    organization_id, _, agent_id, _ = _foundation(client)
    with client.app.state.testing_session() as db:
        agent = db.get(ProtectedAgent, agent_id)
        grant = next(iter(agent_grants(db, organization_id, agent.id)))
        grant.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    _workload(client)
    response = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id))
    assert response.json()["reason_codes"] == ["CAPABILITY_NOT_GRANTED"]


def agent_grants(db, organization_id, agent_id):
    from intel_platform.models import AgentCapabilityGrant

    return db.scalars(
        select(AgentCapabilityGrant).where(
            AgentCapabilityGrant.organization_id == organization_id,
            AgentCapabilityGrant.agent_id == agent_id,
        )
    )


def test_cross_tenant_administration_and_decision_access_are_hidden(client):
    _, _, agent_id, _ = _foundation(client)
    other = client.post("/api/v1/organizations", json={"name": "Other tenant"}).json()
    _workload(client)
    decision = client.post("/api/v1/security/evaluate", json=_evaluation(agent_id)).json()
    app.dependency_overrides.pop(get_workload_principal)
    assert client.get(f"/api/v1/security/agents?organization_id={other['id']}").status_code == 200
    # The current user created both organizations; a genuinely unrelated principal
    # is introduced to verify that membership lookup hides the tenant.
    from intel_platform.auth import Principal, get_principal

    app.dependency_overrides[get_principal] = lambda: Principal(subject="other-user")
    assert client.get(f"/api/v1/security/agents?organization_id={other['id']}").status_code == 403
    _workload(client)
    # A client can retrieve only its own organization's decisions.
    assert client.get(f"/api/v1/security/decisions/{decision['decision_id']}").status_code == 200


def test_workload_cannot_evaluate_another_clients_agent(client):
    _, _, first_agent, _ = _foundation(client)
    second_org = client.post("/api/v1/organizations", json={"name": "Second tenant"}).json()
    second_client = client.post(
        "/api/v1/security/clients",
        json={
            "organization_id": second_org["id"],
            "external_client_id": "second-workload-client",
            "name": "Second workload",
        },
    ).json()
    second_agent = client.post(
        "/api/v1/security/agents",
        json={
            "organization_id": second_org["id"],
            "security_client_id": second_client["id"],
            "name": "second-agent",
        },
    ).json()
    assert first_agent != second_agent["id"]
    _workload(client)
    response = client.post(
        "/api/v1/security/evaluate",
        json=_evaluation(second_agent["id"]),
    )
    assert response.status_code == 404
