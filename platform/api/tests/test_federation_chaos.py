from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intel_platform.federation import (
    FederationVerificationError,
    create_assertion,
    deliver_assertion,
)


def assertion() -> dict:
    return create_assertion(
        Ed25519PrivateKey.generate(),
        assertion_type="indicator_assessment",
        subject_type="domain",
        subject_fingerprint="a" * 64,
        evidence_fingerprint="b" * 64,
        source_category="threat_intelligence",
        confidence=70,
        severity="medium",
        observation_time=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (httpx.ReadTimeout("delayed response"), "timed out"),
        (httpx.ReadError("packet loss"), "unreachable"),
        (httpx.RemoteProtocolError("dropped connection"), "unreachable"),
        (httpx.ConnectError("temporary DNS failure"), "unreachable"),
        (httpx.ConnectError("network partition"), "unreachable"),
        (httpx.ConnectTimeout("extended peer outage"), "timed out"),
    ],
)
def test_network_failures_do_not_interrupt_local_operation(failure, message) -> None:
    local_operations = []

    def failed_delivery(_request: httpx.Request) -> httpx.Response:
        raise failure

    with pytest.raises(FederationVerificationError, match=message):
        deliver_assertion(
            "https://peer.example",
            "organization-b",
            assertion(),
            transport=httpx.MockTransport(failed_delivery),
        )
    local_operations.append("collection")
    local_operations.append("evidence")
    local_operations.append("report")
    assert local_operations == ["collection", "evidence", "report"]


def test_asymmetric_connectivity_and_restart_retry_are_bounded() -> None:
    payload = assertion()
    attempts = 0

    def recovering_peer(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("peer restarting")
        return httpx.Response(202, json={"assertion_id": payload["assertion_id"]})

    transport = httpx.MockTransport(recovering_peer)
    with pytest.raises(FederationVerificationError, match="unreachable"):
        deliver_assertion("https://node-b.example", "org-b", payload, transport=transport)
    assert deliver_assertion(
        "https://node-b.example", "org-b", payload, transport=transport
    )["assertion_id"] == payload["assertion_id"]

    def reverse_direction(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"assertion_id": payload["assertion_id"]})

    assert deliver_assertion(
        "https://node-a.example",
        "org-a",
        payload,
        transport=httpx.MockTransport(reverse_direction),
    )["assertion_id"] == payload["assertion_id"]
