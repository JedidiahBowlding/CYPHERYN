from sqlalchemy import select

from intel_platform.auth import Principal, get_principal
from intel_platform.main import app
from intel_platform.models import LegalAcceptance, User


def test_unaccepted_identity_is_rejected_then_accepted(client) -> None:
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="new-unaccepted-user", email="new@example.test"
    )

    rejected = client.get("/api/v1/organizations")
    assert rejected.status_code == 403
    assert rejected.json()["detail"]["code"] == "legal_acceptance_required"
    with client.app.state.testing_session() as db:
        assert db.scalar(select(User).where(User.external_subject == "new-unaccepted-user")) is None

    missing_affirmation = client.post(
        "/api/v1/legal/acceptance",
        json={"accepted": False, "terms_version": "1.0", "responsible_use_version": "1.0"},
    )
    assert missing_affirmation.status_code == 422

    stale_version = client.post(
        "/api/v1/legal/acceptance",
        json={"accepted": True, "terms_version": "0.9", "responsible_use_version": "1.0"},
    )
    assert stale_version.status_code == 409

    accepted = client.post(
        "/api/v1/legal/acceptance",
        json={"accepted": True, "terms_version": "1.0", "responsible_use_version": "1.0"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["accepted"] is True
    assert accepted.json()["accepted_at"]
    with client.app.state.testing_session() as db:
        user = db.scalar(select(User).where(User.external_subject == "new-unaccepted-user"))
        assert user is not None
        record = db.scalar(select(LegalAcceptance).where(LegalAcceptance.user_id == user.id))
        assert record is not None
        assert record.terms_version == "1.0"
        assert record.responsible_use_version == "1.0"

    allowed = client.get("/api/v1/organizations")
    assert allowed.status_code == 200


def test_active_authorization_requires_scope_confirmation(client) -> None:
    organization = client.post("/api/v1/organizations", json={"name": "Legal test"}).json()
    payload = {
        "basis": "Written permission",
        "passive_allowed": True,
        "active_allowed": True,
        "active_scope_confirmed": False,
        "valid_from": "2026-09-03T00:00:00Z",
        "valid_until": "2026-10-03T00:00:00Z",
    }
    rejected = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations", json=payload
    )
    assert rejected.status_code == 422
    payload["active_scope_confirmed"] = True
    accepted = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations", json=payload
    )
    assert accepted.status_code == 201
