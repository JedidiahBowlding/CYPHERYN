from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from intel_platform.federation import (
    FederationVerificationError,
    corroborate,
    create_assertion,
    deliver_assertion,
    identity_document,
    receive_assertion,
    verify_assertion,
)
from intel_platform.models import Base, FederationPeer
from intel_platform.observability import federation_telemetry_snapshot

NOW = datetime(2026, 8, 30, 20, 0, tzinfo=UTC)
SUBJECT = "a" * 64
EVIDENCE = "b" * 64


def assertion_for(key: Ed25519PrivateKey, **overrides):
    values = {
        "assertion_type": "indicator_assessment",
        "subject_type": "domain",
        "subject_fingerprint": SUBJECT,
        "evidence_fingerprint": EVIDENCE,
        "source_category": "threat_intelligence",
        "confidence": 80,
        "severity": "high",
        "observation_time": NOW - timedelta(minutes=1),
        "now": NOW,
    }
    values.update(overrides)
    return create_assertion(key, **values)


def verify(assertion, key, **overrides):
    identity = identity_document(key, "Node A")
    values = {
        "trusted_public_key": identity["public_key"],
        "expected_node_id": identity["node_id"],
        "expected_key_id": identity["key_id"],
        "now": NOW,
    }
    values.update(overrides)
    return verify_assertion(assertion, **values)


def test_node_identity_is_cryptographic_and_assertion_round_trips() -> None:
    key = Ed25519PrivateKey.generate()
    identity = identity_document(key, "Independent Node A")
    assert identity["node_id"].startswith("cypheryn-node:")
    assert identity["key_id"].startswith("ed25519:")
    assertion = assertion_for(key)
    result = verify(assertion, key)
    assert len(result["payload_fingerprint"]) == 64
    assert result["expires_at"] > NOW


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("protocol_version", "cypheryn-federation-v99", "protocol"),
        ("signature_algorithm", "custom-crypto", "algorithm"),
        ("assertion_type", "arbitrary", "assertion type"),
        ("subject_type", "customer_database", "subject type"),
        ("source_category", "customer-records", "source category"),
        ("subject_fingerprint", "raw-customer-value", "SHA-256"),
        ("confidence", 101, "Confidence"),
    ],
)
def test_strict_schema_rejects_invalid_values(field, value, message) -> None:
    key = Ed25519PrivateKey.generate()
    assertion = assertion_for(key)
    assertion[field] = value
    with pytest.raises(FederationVerificationError, match=message):
        verify(assertion, key)


def test_tampering_and_key_substitution_fail_closed() -> None:
    key = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    assertion = assertion_for(key)
    tampered = copy.deepcopy(assertion)
    tampered["severity"] = "low"
    with pytest.raises(FederationVerificationError, match="signature"):
        verify(tampered, key)
    with pytest.raises(FederationVerificationError, match="identity mismatch"):
        verify(assertion, attacker)


def test_expired_future_oversized_and_unknown_fields_are_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    expired = assertion_for(key, now=NOW - timedelta(days=8), lifetime=timedelta(days=1))
    with pytest.raises(FederationVerificationError, match="expired"):
        verify(expired, key)
    future = assertion_for(key, now=NOW + timedelta(hours=1))
    with pytest.raises(FederationVerificationError, match="future"):
        verify(future, key)
    oversized = assertion_for(key)
    with pytest.raises(FederationVerificationError, match="size limit"):
        verify(oversized, key, max_bytes=10)
    extra = assertion_for(key)
    extra["customer_name"] = "must-not-be-accepted"
    with pytest.raises(FederationVerificationError, match="unsupported fields"):
        verify(extra, key)


@pytest.mark.parametrize(
    "field",
    [
        "credentials",
        "api_token",
        "private_key",
        "pii",
        "customer_records",
        "raw_topology",
        "evidence_checkpoint",
        "analyst_notes",
        "authorization_document",
        "raw_malware",
        "source_code",
        "vulnerability_report",
    ],
)
def test_privacy_boundary_rejects_prohibited_transport_fields(field) -> None:
    key = Ed25519PrivateKey.generate()
    assertion = assertion_for(key)
    assertion[field] = {"nested": {"secret": "must-not-cross-federation"}}
    with pytest.raises(FederationVerificationError, match="unsupported fields"):
        verify(assertion, key)


def test_corroboration_preserves_agreement_and_disagreement() -> None:
    first_key = Ed25519PrivateKey.generate()
    second_key = Ed25519PrivateKey.generate()
    first = assertion_for(first_key, severity="high")
    second = assertion_for(
        second_key,
        severity="unknown",
        source_category="attack_surface",
        evidence_fingerprint="c" * 64,
    )
    result = corroborate([first, second], now=NOW)
    assert result["independent_issuer_count"] == 2
    assert result["source_diversity"] == 2
    assert result["agreement"] is False
    assert result["severities"] == ["high", "unknown"]


def test_persistence_keeps_federated_provenance_and_rejects_replay(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'federation.db'}")
    Base.metadata.create_all(engine)
    key = Ed25519PrivateKey.generate()
    identity = identity_document(key, "Node A")
    with Session(engine) as db:
        peer = FederationPeer(
            organization_id="org-b",
            node_id=identity["node_id"],
            display_name="Node A",
            public_key=identity["public_key"],
            key_id=identity["key_id"],
            status="trusted",
            capabilities=identity["capabilities"],
            enrolled_by_id="admin-b",
        )
        db.add(peer)
        db.flush()
        assertion = assertion_for(key)
        record = receive_assertion(
            db, organization_id="org-b", peer=peer, assertion=assertion, now=NOW
        )
        assert record.verification_status == "verified"
        assert record.trust_state == "trusted"
        assert record.assertion["issuer_node_id"] == identity["node_id"]
        with pytest.raises(FederationVerificationError, match="replay"):
            receive_assertion(
                db, organization_id="org-b", peer=peer, assertion=assertion, now=NOW
            )
    engine.dispose()


def test_suspended_or_revoked_peer_is_rejected(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'revoked.db'}")
    Base.metadata.create_all(engine)
    key = Ed25519PrivateKey.generate()
    identity = identity_document(key, "Node A")
    with Session(engine) as db:
        peer = FederationPeer(
            organization_id="org-b",
            node_id=identity["node_id"],
            display_name="Node A",
            public_key=identity["public_key"],
            key_id=identity["key_id"],
            status="suspended",
            capabilities=[],
            enrolled_by_id="admin-b",
        )
        db.add(peer)
        db.flush()
        with pytest.raises(FederationVerificationError, match="not trusted"):
            receive_assertion(
                db,
                organization_id="org-b",
                peer=peer,
                assertion=assertion_for(key),
                now=NOW,
            )
    engine.dispose()


def test_delivery_handles_success_timeout_unreachable_and_peer_failure() -> None:
    key = Ed25519PrivateKey.generate()
    assertion = assertion_for(key)

    def success(request: httpx.Request) -> httpx.Response:
        assert request.url.scheme == "https"
        return httpx.Response(202, json={"assertion_id": assertion["assertion_id"]})

    delivered = deliver_assertion(
        "https://node-b.example",
        "org-b",
        assertion,
        transport=httpx.MockTransport(success),
    )
    assert delivered["assertion_id"] == assertion["assertion_id"]

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("deadline exceeded")

    with pytest.raises(FederationVerificationError, match="timed out"):
        deliver_assertion(
            "https://node-b.example",
            "org-b",
            assertion,
            transport=httpx.MockTransport(timeout),
        )

    def unreachable(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    with pytest.raises(FederationVerificationError, match="unreachable"):
        deliver_assertion(
            "https://node-b.example",
            "org-b",
            assertion,
            transport=httpx.MockTransport(unreachable),
        )
    counters, latencies = federation_telemetry_snapshot()
    assert counters["accepted"] >= 1
    assert counters["timeout"] >= 1
    assert counters["unreachable_peer"] >= 1
    assert len(latencies) >= 3

    with pytest.raises(FederationVerificationError, match="HTTP 503"):
        deliver_assertion(
            "https://node-b.example",
            "org-b",
            assertion,
            transport=httpx.MockTransport(lambda _: httpx.Response(503)),
        )


def test_delivery_rejects_insecure_remote_transport_and_bad_acknowledgement() -> None:
    assertion = assertion_for(Ed25519PrivateKey.generate())
    with pytest.raises(FederationVerificationError, match="HTTPS"):
        deliver_assertion("http://node-b.example", "org-b", assertion)
    with pytest.raises(FederationVerificationError, match="acknowledgement"):
        deliver_assertion(
            "https://node-b.example",
            "org-b",
            assertion,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(202, json={"assertion_id": "wrong"})
            ),
        )
