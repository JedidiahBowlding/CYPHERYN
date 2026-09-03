from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from intel_platform.models import Authorization, CollectionJob, EvidenceSource
from intel_platform.provider_contract import registry
from intel_platform.security_controls import redact_payload, redact_text
from intel_platform.worker import process_one


def _organization(client: TestClient) -> dict:
    response = client.post("/api/v1/organizations", json={"name": "Control validation"})
    assert response.status_code == 201
    return response.json()


def test_every_registered_provider_meets_contract_and_is_described(
    client: TestClient,
) -> None:
    descriptors = {item["name"]: item for item in client.get("/api/v1/providers").json()}
    registered = {provider.name: provider for provider in registry.list()}
    assert descriptors.keys() == registered.keys()
    for name, provider in registered.items():
        descriptor = descriptors[name]
        assert provider.capabilities.target_types
        assert all(isinstance(item, str) and item for item in provider.capabilities.target_types)
        assert descriptor["version"]
        assert descriptor["passive_only"] is provider.capabilities.passive_only
        assert descriptor["requires_credentials"] is provider.capabilities.requires_credentials
        assert isinstance(descriptor["available"], bool)


def test_every_provider_is_covered_by_end_to_end_readiness_gate(
    client: TestClient,
) -> None:
    organization = _organization(client)
    response = client.get(f"/api/v1/organizations/{organization['id']}/platform-assurance")
    assert response.status_code == 200
    statuses = {item["provider"]: item for item in response.json()["providers"]}
    assert statuses.keys() == {provider.name for provider in registry.list()}
    for provider in registry.list():
        status = statuses[provider.name]
        assert status["mode"] in {"passive", "active"}
        assert status["version"]
        assert status["health"] in {"healthy", "degraded", "circuit_open"}
        if provider.capabilities.requires_credentials:
            assert status["ready"] is False
            assert status["configuration"] == "credentials_required"


def test_recursive_redaction_removes_secrets_from_evidence_and_errors() -> None:
    payload = redact_payload(
        {
            "api_key": "top-secret",
            "nested": {"Authorization": "Bearer abc.def", "safe": "retained"},
            "lines": ["token=abc123", "ordinary evidence"],
        }
    )
    assert payload["api_key"] == "[REDACTED]"
    assert payload["nested"]["Authorization"] == "[REDACTED]"
    assert payload["nested"]["safe"] == "retained"
    assert payload["lines"][0] == "token=[REDACTED]"
    assert redact_text("Bearer abc123") == "Bearer [REDACTED]"
    assert "top-secret" not in str(payload)


def test_active_authorization_is_revalidated_immediately_before_execution(
    client: TestClient,
) -> None:
    organization = _organization(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Execution authorization"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Temporary active test scope",
            "passive_allowed": True,
            "active_allowed": True,
            "active_scope_confirmed": True,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=1)).isoformat(),
        },
    ).json()
    target = client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "ip_address",
            "value": "127.0.0.1",
        },
    ).json()
    queued = client.post(
        f"/api/v1/investigations/{investigation['id']}/collect",
        json={"provider": "local_observer", "target_id": target["id"]},
    )
    assert queued.status_code == 202
    with client.app.state.testing_session() as db:
        stored = db.get(Authorization, authorization["id"])
        stored.revoked_at = datetime.now(UTC)
        db.commit()
    processed = process_one("authorization-recheck", client.app.state.testing_session)
    assert processed is not None
    with client.app.state.testing_session() as db:
        job = db.get(CollectionJob, queued.json()["id"])
        assert "authorization" in (job.error_summary or "").lower()
        assert db.scalar(select(EvidenceSource).where(EvidenceSource.job_id == job.id)) is None
