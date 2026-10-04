from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from intel_platform.auth import WorkloadPrincipal, get_workload_principal
from intel_platform.destination_security import CanonicalDestination, UnsafeDestination
from intel_platform.main import app
from intel_platform.models import DecisionAuthorization, EgressPolicy
from intel_platform.security_control import policy_integrity


def _setup(client, *, destination="https://8.8.8.8", capability="web.read"):
    organization_id = client.post(
        "/api/v1/organizations", json={"name": "Authorization lease test"}
    ).json()["id"]
    security_client = client.post(
        "/api/v1/security/clients",
        json={
            "organization_id": organization_id,
            "external_client_id": "lease-workload",
            "name": "Lease workload",
        },
    ).json()
    agent = client.post(
        "/api/v1/security/agents",
        json={
            "organization_id": organization_id,
            "security_client_id": security_client["id"],
            "name": "lease-agent",
        },
    ).json()
    grant = client.post(
        f"/api/v1/security/agents/{agent['id']}/capability-grants",
        json={"organization_id": organization_id, "capability": capability},
    ).json()
    configured_destination = client.post(
        "/api/v1/security/destinations",
        json={
            "organization_id": organization_id,
            "destination": destination,
            "trust_state": "TRUSTED",
        },
    ).json()
    return {
        "organization_id": organization_id,
        "client_id": security_client["id"],
        "agent_id": agent["id"],
        "grant_id": grant["id"],
        "destination_id": configured_destination["id"],
        "destination": destination,
        "capability": capability,
    }


def _workload():
    app.dependency_overrides[get_workload_principal] = lambda: WorkloadPrincipal(
        subject="lease-workload@clients", client_id="lease-workload"
    )


def _evaluate(client, state: dict, *, number=1):
    _workload()
    return client.post(
        "/api/v1/security/evaluate",
        json={
            "agent_id": state["agent_id"],
            "action": "fetch",
            "capability": state["capability"],
            "destination": state["destination"],
            "environment": "production",
            "data_classifications": ["PUBLIC"],
            "resource_scope": {"method": "GET"},
            "context": {"purpose": "authorization-lease-test"},
            "request_id": f"lease-request-{number:08d}",
            "idempotency_key": f"lease-idempotency-{number:08d}",
            "nonce": f"lease-nonce-value-{number:08d}",
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )


def _validate(client, state: dict, decision_id: str, *, set_workload=True, **changes):
    destination = state["destination"]
    address = destination.removeprefix("https://").strip("[]")
    payload = {
        "action": "fetch",
        "capability": state["capability"],
        "destination": destination,
        "environment": "production",
        "resource_scope": {"method": "GET"},
        "connected_address": address,
        "consume": False,
    }
    payload.update(changes)
    if set_workload:
        _workload()
    return client.post(f"/api/v1/security/decisions/{decision_id}/validate", json=payload)


def test_allow_receipt_contains_bounded_resolution_and_validates(client):
    state = _setup(client)
    receipt = _evaluate(client, state).json()
    assert receipt["decision"] == "ALLOW"
    assert receipt["authorization"]["expires_at"]
    assert receipt["destination_binding"]["resolution_expires_at"]
    assert receipt["destination_binding"]["resolved_addresses"] == ["8.8.8.8"]
    validation = _validate(client, state, receipt["decision_id"])
    assert validation.status_code == 200
    assert validation.json()["valid"] is True


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("agent", "AGENT_AUTHORITY_CHANGED"),
        ("grant", "CAPABILITY_AUTHORITY_CHANGED"),
        ("destination", "DESTINATION_AUTHORITY_CHANGED"),
    ],
)
def test_revocation_after_allow_invalidates_execution_authority(client, target, reason):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    app.dependency_overrides.pop(get_workload_principal)
    if target == "agent":
        response = client.patch(
            f"/api/v1/security/agents/{state['agent_id']}/status",
            json={"status": "REVOKED"},
        )
    elif target == "grant":
        response = client.post(
            f"/api/v1/security/capability-grants/{state['grant_id']}/revoke"
        )
    else:
        response = client.patch(
            f"/api/v1/security/destinations/{state['destination_id']}/trust",
            json={"trust_state": "BLOCKED"},
        )
    assert response.status_code == 200
    validation = _validate(client, state, decision_id)
    assert validation.json()["valid"] is False
    assert reason in validation.json()["reason_codes"]


def test_client_revocation_after_allow_rejects_final_validation(client):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    app.dependency_overrides.pop(get_workload_principal)
    assert client.patch(
        f"/api/v1/security/clients/{state['client_id']}/status",
        json={"status": "REVOKED"},
    ).status_code == 200
    assert _validate(client, state, decision_id).status_code == 403


def test_policy_generation_change_invalidates_prior_allow(client):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    with client.app.state.testing_session() as db:
        policy = db.scalar(
            select(EgressPolicy).where(
                EgressPolicy.organization_id == state["organization_id"],
                EgressPolicy.state == "active",
            )
        )
        policy.authorization_generation += 1
        policy.integrity_hash = policy_integrity(policy)
        db.commit()
    validation = _validate(client, state, decision_id)
    assert validation.json()["valid"] is False
    assert "POLICY_AUTHORITY_CHANGED" in validation.json()["reason_codes"]


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("expires_at", "AUTHORIZATION_EXPIRED"),
        ("resolution_expires_at", "RESOLUTION_EXPIRED"),
    ],
)
def test_expired_authority_and_resolution_are_denied(client, field, reason):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    with client.app.state.testing_session() as db:
        authorization = db.get(DecisionAuthorization, decision_id)
        setattr(authorization, field, datetime.now(UTC) - timedelta(seconds=1))
        db.commit()
    validation = _validate(client, state, decision_id)
    assert validation.json()["valid"] is False
    assert reason in validation.json()["reason_codes"]


def test_single_use_high_consequence_authority_cannot_be_replayed(client):
    state = _setup(client, capability="email.send")
    with client.app.state.testing_session() as db:
        policy = db.scalar(
            select(EgressPolicy).where(
                EgressPolicy.organization_id == state["organization_id"],
                EgressPolicy.state == "active",
            )
        )
        policy.rules = {**policy.rules, "require_approval_capabilities": []}
        policy.integrity_hash = policy_integrity(policy)
        db.commit()
    receipt = _evaluate(client, state).json()
    assert receipt["authorization"]["single_use"] is True
    first = _validate(client, state, receipt["decision_id"], consume=True)
    assert first.json()["valid"] is True and first.json()["consumed"] is True
    second = _validate(client, state, receipt["decision_id"], consume=True)
    assert second.json()["valid"] is False
    assert "AUTHORIZATION_EXHAUSTED" in second.json()["reason_codes"]


@pytest.mark.parametrize(
    "changes",
    [
        {"destination": "http://8.8.8.8"},
        {"destination": "https://8.8.8.8:8443"},
        {"destination": "https://1.1.1.1", "connected_address": "1.1.1.1"},
        {"connected_address": "1.1.1.1"},
        {"capability": "email.send"},
        {"resource_scope": {"method": "POST"}},
    ],
)
def test_operation_and_network_binding_cannot_be_reused(changes, client):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    validation = _validate(client, state, decision_id, **changes)
    assert validation.json()["valid"] is False


def test_same_origin_redirect_path_is_valid_but_cross_origin_requires_new_evaluation(client):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    same_origin = _validate(
        client, state, decision_id, destination="https://8.8.8.8/redirect-target"
    )
    assert same_origin.json()["valid"] is True
    cross_origin = _validate(
        client,
        state,
        decision_id,
        destination="https://1.1.1.1/redirect-target",
        connected_address="1.1.1.1",
    )
    assert cross_origin.json()["valid"] is False
    assert cross_origin.json()["connection"]["redirects_require_new_evaluation"] is True


def test_dns_resolution_change_invalidates_the_bound_decision(client, monkeypatch):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    monkeypatch.setattr(
        "intel_platform.security_api.canonicalize_destination",
        lambda _value: CanonicalDestination(
            "https://8.8.8.8", "8.8.8.8", 443, "https", ("1.1.1.1",)
        ),
    )
    validation = _validate(client, state, decision_id)
    assert validation.json()["valid"] is False
    assert "RESOLUTION_BINDING_CHANGED" in validation.json()["reason_codes"]


@pytest.mark.parametrize(
    "answers",
    [
        [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("10.0.0.1", 443))],
        [(2, 1, 6, "", ("127.0.0.1", 443))],
        [(2, 1, 6, "", ("169.254.169.254", 443))],
        [(10, 1, 6, "", ("::1", 443, 0, 0))],
        [(10, 1, 6, "", ("fd00::1", 443, 0, 0))],
    ],
)
def test_any_unsafe_dns_answer_fails_the_entire_resolution(answers):
    from intel_platform.destination_security import canonicalize_destination

    with pytest.raises(UnsafeDestination):
        canonicalize_destination("https://public.example", resolver=lambda *_args, **_kw: answers)


def test_ipv6_address_binding_validates(client):
    state = _setup(client, destination="https://[2606:4700:4700::1111]")
    decision_id = _evaluate(client, state).json()["decision_id"]
    assert _validate(client, state, decision_id).json()["valid"] is True


def test_cross_tenant_workload_cannot_validate_a_decision(client):
    state = _setup(client)
    decision_id = _evaluate(client, state).json()["decision_id"]
    app.dependency_overrides[get_workload_principal] = lambda: WorkloadPrincipal(
        subject="other@clients", client_id="other-client"
    )
    assert _validate(client, state, decision_id, set_workload=False).status_code in {401, 404}
