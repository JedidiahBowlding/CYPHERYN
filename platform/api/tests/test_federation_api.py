from datetime import UTC, datetime
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intel_platform.federation import create_assertion, identity_document


def enable_federation(monkeypatch, key_path):
    settings = SimpleNamespace(
        federation_enabled=True,
        federation_display_name="Node B",
        federation_key_path=str(key_path),
        federation_max_assertion_bytes=65536,
        federation_rate_limit_per_minute=60,
    )
    monkeypatch.setattr("intel_platform.federation_api.get_settings", lambda: settings)


def test_federation_is_disabled_by_default(client) -> None:
    response = client.get("/api/federation/v1/identity")
    assert response.status_code == 404


def test_two_node_enrollment_delivery_replay_and_revocation(client, tmp_path, monkeypatch) -> None:
    node_b_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "node-b.pem"
    from cryptography.hazmat.primitives import serialization

    key_path.write_bytes(
        node_b_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    enable_federation(monkeypatch, key_path)
    identity_response = client.get("/api/federation/v1/identity")
    assert identity_response.status_code == 200
    assert identity_response.json()["display_name"] == "Node B"

    organization = client.post("/api/v1/organizations", json={"name": "Node B Org"}).json()
    organization_id = organization["id"]
    node_a_key = Ed25519PrivateKey.generate()
    node_a = identity_document(node_a_key, "Node A")
    enrollment = client.post(
        f"/api/federation/v1/organizations/{organization_id}/peers",
        json=node_a,
    )
    assert enrollment.status_code == 201
    peer_id = enrollment.json()["id"]
    trusted = client.patch(
        f"/api/federation/v1/organizations/{organization_id}/peers/{peer_id}",
        json={"status": "trusted"},
    )
    assert trusted.status_code == 200

    assertion = create_assertion(
        node_a_key,
        assertion_type="indicator_assessment",
        subject_type="domain",
        subject_fingerprint="a" * 64,
        evidence_fingerprint="b" * 64,
        source_category="node-a-local-observation",
        confidence=75,
        severity="high",
        observation_time=datetime.now(UTC),
    )
    endpoint = f"/api/federation/v1/organizations/{organization_id}/assertions/inbound"
    accepted = client.post(endpoint, json=assertion)
    assert accepted.status_code == 202
    assert accepted.json()["verification_status"] == "verified"
    assert accepted.json()["issuer_node_id"] == node_a["node_id"]
    assert client.post(endpoint, json=assertion).status_code == 422

    revoked = client.patch(
        f"/api/federation/v1/organizations/{organization_id}/peers/{peer_id}",
        json={"status": "revoked"},
    )
    assert revoked.status_code == 200
    second = {**assertion, "assertion_id": "urn:uuid:tampered"}
    assert client.post(endpoint, json=second).status_code == 422

    stored = client.get(
        f"/api/federation/v1/organizations/{organization_id}/assertions"
    ).json()
    assert len(stored) == 1
    assert stored[0]["trust_state"] == "trusted"
