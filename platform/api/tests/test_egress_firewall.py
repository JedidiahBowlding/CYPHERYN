import base64
import io
import shutil
from datetime import UTC, datetime, timedelta

import pytest
from PIL import Image, ImageDraw

from intel_platform.auth import Principal, get_principal
from intel_platform.config import Settings
from intel_platform.egress import (
    evaluate_policy,
    normalize_action,
    scan_artifact,
    verify_event,
)
from intel_platform.main import app
from intel_platform.models import EgressApproval, EgressFinding, Membership, MembershipRole, User


def _encoded(value: bytes) -> str:
    return base64.b64encode(value).decode()


def _organization_and_agent(client):
    organization = client.post("/api/v1/organizations", json={"name": "Egress Test"}).json()
    response = client.post(
        "/api/v1/egress/agents",
        json={
            "organization_id": organization["id"],
            "name": "test-agent",
            "runtime": "pytest",
            "workspace": "/workspace/test",
        },
    )
    assert response.status_code == 201
    return organization["id"], response.json()["id"]


def _evaluate(client, organization_id, agent_id, **overrides):
    payload = {
        "organization_id": organization_id,
        "agent_id": agent_id,
        "action_type": "github.repository.create",
        "destination": "api.github.com",
        "repository": "example/private-test",
        "requested_visibility": "private",
        "correlation_id": "test-run",
        "artifacts": [],
    }
    payload.update(overrides)
    return client.post("/api/v1/egress/evaluate", json=payload)


def test_public_repository_creation_is_blocked(client):
    organization_id, agent_id = _organization_and_agent(client)
    response = _evaluate(
        client,
        organization_id,
        agent_id,
        requested_visibility="public",
    )
    assert response.status_code == 201
    assert response.json()["decision"] == "BLOCK"
    assert "PUBLIC_REPOSITORY_PROHIBITED" in response.json()["reason_codes"]
    assert response.json()["integrity_valid"] is True


def test_private_to_public_visibility_change_is_blocked():
    action = normalize_action(
        {
            "action_type": "github.repository.visibility_change",
            "requested_visibility": "public",
            "destination": "api.github.com",
        }
    )
    decision, codes, _ = evaluate_policy(
        action,
        artifact_classifications=[],
        approved_private_repositories=[],
        mandatory_scanners_healthy=True,
    )
    assert decision == "BLOCK"
    assert codes == ["PUBLIC_REPOSITORY_PROHIBITED"]


def test_approved_private_repository_is_allowed():
    action = normalize_action(
        {
            "action_type": "git.push",
            "repository": "example/private",
            "requested_visibility": "private",
            "destination": "github.com",
        }
    )
    decision, _, _ = evaluate_policy(
        action,
        artifact_classifications=[],
        approved_private_repositories=["example/private"],
        mandatory_scanners_healthy=True,
    )
    assert decision == "ALLOW"


def test_unknown_image_host_is_blocked():
    action = normalize_action(
        {
            "action_type": "upload",
            "destination": "images.example",
            "requested_visibility": "private",
        }
    )
    decision, codes, _ = evaluate_policy(
        action,
        artifact_classifications=[],
        approved_private_repositories=[],
        mandatory_scanners_healthy=True,
    )
    assert decision == "BLOCK"
    assert codes == ["UNKNOWN_OUTBOUND_DESTINATION"]


def test_secret_file_is_classified_without_exposing_value():
    secret = "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"  # noqa: S105 - synthetic fixture
    result = scan_artifact(
        filename="config.env",
        content_base64=_encoded(f"TOKEN={secret}".encode()),
        settings=Settings(egress_max_artifact_bytes=1024),
    )
    assert "secret" in result.classification
    assert secret not in repr(result.findings)


@pytest.mark.skipif(shutil.which("tesseract") is None, reason="Tesseract is not installed")
def test_screenshot_ocr_detects_synthetic_sensitive_text():
    image = Image.new("RGB", (1400, 260), "white")
    draw = ImageDraw.Draw(image)
    draw.text(
        (30, 40),
        "SYNTHETIC TEST ONLY\nAPI_KEY=synthetic_demo_secret_1234567890\ndemo@example.test",
        fill="black",
        spacing=20,
    )
    output = io.BytesIO()
    image.save(output, format="PNG")
    result = scan_artifact(
        filename="synthetic.png",
        content_base64=_encoded(output.getvalue()),
        settings=Settings(egress_max_artifact_bytes=1024 * 1024),
    )
    assert result.ocr_status == "completed"
    assert {"secret", "personal_information"}.intersection(result.classification)


def test_unhealthy_mandatory_scanner_fails_closed():
    decision, codes, _ = evaluate_policy(
        normalize_action({"action_type": "git.push", "destination": "github.com"}),
        artifact_classifications=[],
        approved_private_repositories=[],
        mandatory_scanners_healthy=False,
    )
    assert decision == "BLOCK"
    assert codes == ["MANDATORY_SCANNER_UNHEALTHY"]


def test_unsupported_file_is_quarantined(tmp_path):
    result = scan_artifact(
        filename="archive.bin",
        content_base64=_encoded(b"\x00\x01\x02\x03"),
        settings=Settings(
            egress_max_artifact_bytes=1024,
            egress_quarantine_dir=str(tmp_path / "quarantine"),
        ),
    )
    assert result.classification == ["uninspectable"]
    assert result.quarantine_reference
    assert (tmp_path / "quarantine" / result.sha256[:2] / result.sha256).exists()


def test_oversized_and_path_traversal_artifacts_are_rejected():
    settings = Settings(egress_max_artifact_bytes=3)
    for filename, content in (("large.txt", b"four"), ("../secret.txt", b"ok")):
        try:
            scan_artifact(filename=filename, content_base64=_encoded(content), settings=settings)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe artifact should be rejected")


def test_agent_cannot_approve_own_action(client):
    organization_id, agent_id = _organization_and_agent(client)
    event = _evaluate(client, organization_id, agent_id).json()
    response = client.post(
        f"/api/v1/egress/events/{event['event_id']}/approvals",
        json={"approve": True},
    )
    assert response.status_code == 403


def test_approval_is_exact_single_use_and_mismatch_creates_finding(client):
    organization_id, agent_id = _organization_and_agent(client)
    event = _evaluate(client, organization_id, agent_id).json()
    session_factory = client.app.state.testing_session
    with session_factory() as db:
        requester = db.scalar(db.query(User).filter(User.external_subject == "test-user").statement)
        approver = User(external_subject="approver", email="approver@example.test")
        db.add(approver)
        db.flush()
        db.add(
            Membership(
                organization_id=organization_id,
                user_id=approver.id,
                role=MembershipRole.ORGANIZATION_ADMIN,
            )
        )
        db.commit()
        assert requester.id != approver.id
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="approver", email="approver@example.test"
    )
    legal_response = client.post(
        "/api/v1/legal/acceptance",
        json={
            "accepted": True,
            "terms_version": "1.0",
            "responsible_use_version": "1.0",
        },
    )
    assert legal_response.status_code == 200
    approval_response = client.post(
        f"/api/v1/egress/events/{event['event_id']}/approvals",
        json={"approve": True, "expires_in_minutes": 30},
    )
    assert approval_response.status_code == 201, approval_response.text
    token = approval_response.json()["approval_token"]
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="test-user", email="analyst@example.test"
    )
    verify_response = client.post(
        f"/api/v1/egress/executions/{event['event_id']}/verify",
        json={
            "approval_token": token,
            "observed_repository": "unexpected/public-host",
            "observed_visibility": "public",
        },
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["status"] == "MISMATCHED"
    replay = client.post(
        f"/api/v1/egress/executions/{event['event_id']}/verify",
        json={"approval_token": token},
    )
    assert replay.status_code == 403
    with session_factory() as db:
        assert db.scalar(db.query(EgressFinding).statement) is not None


def test_expired_approval_is_rejected(client):
    organization_id, agent_id = _organization_and_agent(client)
    event = _evaluate(client, organization_id, agent_id).json()
    session_factory = client.app.state.testing_session
    with session_factory() as db:
        record = db.get(
            __import__("intel_platform.models", fromlist=["EgressEvent"]).EgressEvent,
            event["event_id"],
        )
        approval = EgressApproval(
            event_id=record.id,
            requested_by_id=record.actor_id,
            decided_by_id=record.actor_id,
            action_hash=record.request_hash,
            token_hash="0" * 64,
            state="approved",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        db.add(approval)
        db.flush()
        record.approval_id = approval.id
        db.commit()
    response = client.post(
        f"/api/v1/egress/executions/{event['event_id']}/verify",
        json={"approval_token": "invalid"},
    )
    assert response.status_code == 403


def test_event_evidence_export_verifies(client):
    organization_id, agent_id = _organization_and_agent(client)
    event = _evaluate(
        client,
        organization_id,
        agent_id,
        requested_visibility="public",
    ).json()
    response = client.get(f"/api/v1/egress/events/{event['event_id']}/evidence")
    assert response.status_code == 200
    assert response.json()["integrity"]["valid"] is True
    with client.app.state.testing_session() as db:
        from intel_platform.models import EgressEvent

        assert verify_event(db.get(EgressEvent, event["event_id"])) is True
