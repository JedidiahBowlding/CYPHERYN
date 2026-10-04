from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from intel_platform.auth import Principal, WorkloadPrincipal, get_principal, get_workload_principal
from intel_platform.config import Settings
from intel_platform.database import Base, get_db
from intel_platform.egress import verify_event
from intel_platform.egress_proxy import (
    ProxyRequest,
    ProxySecurityError,
    TransportResult,
    execute_proxy_request,
)
from intel_platform.main import app
from intel_platform.models import DecisionAuthorization, EgressEvent

DATABASE_URL = os.getenv("AGENT_SECURITY_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="PostgreSQL agent-security certification DB not configured"
)


def _payload(agent_id: str, number: int, *, shared: bool = False) -> dict:
    suffix = "shared-000000000" if shared else f"unique-{number:09d}"
    return {
        "agent_id": agent_id,
        "action": "fetch",
        "capability": "web.read",
        "destination": "https://8.8.8.8",
        "environment": "production",
        "data_classifications": ["PUBLIC"],
        "resource_scope": {"method": "GET"},
        "context": {"purpose": "postgres-concurrency-certification"},
        "request_id": f"request-{suffix}",
        "idempotency_key": f"idempotency-{suffix}",
        "nonce": f"nonce-value-{suffix}",
        "timestamp": datetime.now(UTC).isoformat(),
    }


def _foundation(client: TestClient, number: int) -> tuple[str, str, str]:
    organization_id = client.post(
        "/api/v1/organizations", json={"name": f"Concurrent tenant {number}"}
    ).json()["id"]
    external_client_id = f"concurrent-client-{number}"
    security_client_id = client.post(
        "/api/v1/security/clients",
        json={
            "organization_id": organization_id,
            "external_client_id": external_client_id,
            "name": f"Concurrent workload {number}",
        },
    ).json()["id"]
    agent_id = client.post(
        "/api/v1/security/agents",
        json={
            "organization_id": organization_id,
            "security_client_id": security_client_id,
            "name": f"concurrent-agent-{number}",
        },
    ).json()["id"]
    assert client.post(
        "/api/v1/security/agents/" + agent_id + "/capability-grants",
        json={"organization_id": organization_id, "capability": "web.read"},
    ).status_code == 201
    assert client.post(
        "/api/v1/security/destinations",
        json={
            "organization_id": organization_id,
            "destination": "https://8.8.8.8",
            "trust_state": "TRUSTED",
        },
    ).status_code == 201
    return organization_id, external_client_id, agent_id


def test_postgresql_serializes_security_receipts_and_idempotent_races() -> None:
    engine = create_engine(DATABASE_URL, pool_size=16, max_overflow=8)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        with testing_session() as db:
            yield db

    def workload(request: Request) -> WorkloadPrincipal:
        client_id = request.headers["x-test-workload"]
        return WorkloadPrincipal(subject=f"{client_id}@clients", client_id=client_id)

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="postgres-certification-admin", email="certification@example.test"
    )
    try:
        with TestClient(app) as client:
            assert client.post(
                "/api/v1/legal/acceptance",
                json={
                    "accepted": True,
                    "terms_version": "1.0",
                    "responsible_use_version": "1.0",
                },
            ).status_code == 200
            first_org, first_client, first_agent = _foundation(client, 1)
            second_org, second_client, second_agent = _foundation(client, 2)
            app.dependency_overrides[get_workload_principal] = workload

            def post(external_client_id: str, payload: dict):
                return client.post(
                    "/api/v1/security/evaluate",
                    json=payload,
                    headers={"X-Test-Workload": external_client_id},
                )

            shared_payload = _payload(first_agent, 0, shared=True)
            with ThreadPoolExecutor(max_workers=8) as pool:
                identical = list(
                    pool.map(
                        lambda _: post(first_client, shared_payload),
                        range(8),
                    )
                )
            assert {response.status_code for response in identical} == {201}
            shared_decision_id = identical[0].json()["decision_id"]
            assert {response.json()["decision_id"] for response in identical} == {
                shared_decision_id
            }

            with testing_session() as db:
                authority = db.get(DecisionAuthorization, shared_decision_id)
                authority.maximum_uses = 1
                db.commit()
            validation_payload = {
                "action": "fetch",
                "capability": "web.read",
                "destination": "https://8.8.8.8",
                "environment": "production",
                "resource_scope": {"method": "GET"},
                "connected_address": "8.8.8.8",
                "consume": True,
            }
            with ThreadPoolExecutor(max_workers=8) as pool:
                consumption = list(
                    pool.map(
                        lambda _: client.post(
                            f"/api/v1/security/decisions/{shared_decision_id}/validate",
                            json=validation_payload,
                            headers={"X-Test-Workload": first_client},
                        ),
                        range(8),
                    )
                )
            assert {response.status_code for response in consumption} == {200}
            assert sum(response.json()["valid"] for response in consumption) == 1
            assert sum(response.json()["consumed"] for response in consumption) == 1

            proxy_decision_id = post(first_client, _payload(first_agent, 100)).json()[
                "decision_id"
            ]
            with testing_session() as db:
                authority = db.get(DecisionAuthorization, proxy_decision_id)
                authority.maximum_uses = 1
                db.commit()
            socket_count = 0
            socket_lock = threading.Lock()

            class IntegratedControlPlane:
                def start_receipt(self, decision_id, payload):
                    response = client.post(
                        f"/api/v1/security/decisions/{decision_id}/proxy-receipts",
                        json=payload,
                        headers={"X-Test-Workload": first_client},
                    )
                    response.raise_for_status()
                    return response.json()["proxy_request_id"]

                def validate(self, decision_id, payload):
                    response = client.post(
                        f"/api/v1/security/decisions/{decision_id}/validate",
                        json=payload,
                        headers={"X-Test-Workload": first_client},
                    )
                    response.raise_for_status()
                    return response.json()

                def finish_receipt(self, receipt_id, payload):
                    response = client.patch(
                        f"/api/v1/security/proxy-receipts/{receipt_id}",
                        json=payload,
                        headers={"X-Test-Workload": first_client},
                    )
                    response.raise_for_status()

            class CountingTransport:
                def request(self, *args):
                    nonlocal socket_count
                    with socket_lock:
                        socket_count += 1
                    return TransportResult(204, {}, b"", 0)

            proxy_payload = ProxyRequest(
                decision_id=proxy_decision_id,
                action="fetch",
                capability="web.read",
                url="https://8.8.8.8",
                method="GET",
                resource_scope={"method": "GET"},
                correlation_id="postgres-multi-proxy-0001",
            )

            def proxy_call():
                try:
                    execute_proxy_request(
                        proxy_payload,
                        "Bearer test-token",
                        Settings(trusted_egress_proxy_enabled=True),
                        control_plane=IntegratedControlPlane(),
                        transport=CountingTransport(),
                    )
                    return "executed"
                except ProxySecurityError as exc:
                    return exc.outcome

            with ThreadPoolExecutor(max_workers=2) as pool:
                proxy_outcomes = list(pool.map(lambda _: proxy_call(), range(2)))
            assert sorted(proxy_outcomes) == ["AUTHORITY_CONSUMED", "executed"]
            assert socket_count == 1

            work = [
                (first_client, _payload(first_agent, number))
                if number % 2 == 0
                else (second_client, _payload(second_agent, number))
                for number in range(12)
            ]
            with ThreadPoolExecutor(max_workers=8) as pool:
                independent = list(pool.map(lambda item: post(*item), work))
            assert {response.status_code for response in independent} == {201}
            assert {response.json()["decision"] for response in independent} == {"ALLOW"}

        with Session(engine) as db:
            assert db.scalar(select(func.count(EgressEvent.id))) == 14
            first_events = list(
                db.scalars(
                    select(EgressEvent)
                    .where(EgressEvent.organization_id == first_org)
                    .order_by(EgressEvent.created_at, EgressEvent.id)
                )
            )
            second_events = list(
                db.scalars(
                    select(EgressEvent)
                    .where(EgressEvent.organization_id == second_org)
                    .order_by(EgressEvent.created_at, EgressEvent.id)
                )
            )
            assert all(verify_event(event) for event in [*first_events, *second_events])
            for events in (first_events, second_events):
                roots = [event for event in events if event.previous_event_hash is None]
                links = [event.previous_event_hash for event in events if event.previous_event_hash]
                hashes = {event.event_hash for event in events}
                assert len(roots) == 1
                assert len(links) == len(events) - 1
                assert len(set(links)) == len(links)
                assert set(links) <= hashes
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)
        engine.dispose()
