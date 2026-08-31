from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from intel_platform.federation import (
    FederationVerificationError,
    create_assertion,
    identity_document,
    receive_assertion,
)
from intel_platform.models import (
    Base,
    FederatedAssertion,
    FederationPeer,
    FederationReplayNonce,
    Organization,
    User,
)

DATABASE_URL = os.getenv("FEDERATION_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="PostgreSQL federation DB not configured")


def _deliver_in_process(database_url: str, peer_id: str, assertion: dict) -> str:
    engine = create_engine(database_url)
    try:
        with Session(engine) as db:
            peer = db.get(FederationPeer, peer_id)
            try:
                receive_assertion(
                    db,
                    organization_id=peer.organization_id,
                    peer=peer,
                    assertion=assertion,
                )
                db.commit()
                return "accepted"
            except FederationVerificationError:
                db.rollback()
                return "replay"
    finally:
        engine.dispose()


def test_postgresql_serializes_duplicate_assertion_and_nonce_races() -> None:
    engine = create_engine(DATABASE_URL)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    key = Ed25519PrivateKey.generate()
    identity = identity_document(key, "Concurrent Node")
    with Session(engine) as db:
        user = User(external_subject="postgres-federation-admin")
        organization = Organization(name="PostgreSQL Federation Test")
        db.add_all([user, organization])
        db.flush()
        peer = FederationPeer(
            organization_id=organization.id,
            node_id=identity["node_id"],
            display_name="Concurrent Node",
            public_key=identity["public_key"],
            key_id=identity["key_id"],
            status="trusted",
            capabilities=identity["capabilities"],
            enrolled_by_id=user.id,
        )
        db.add(peer)
        db.commit()
        peer_id = peer.id
        organization_id = organization.id

    assertion = create_assertion(
        key,
        assertion_type="indicator_assessment",
        subject_type="domain",
        subject_fingerprint="a" * 64,
        evidence_fingerprint="b" * 64,
        source_category="threat_intelligence",
        confidence=80,
        severity="high",
        observation_time=datetime.now(UTC),
    )
    with ProcessPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                _deliver_in_process,
                [DATABASE_URL] * 4,
                [peer_id] * 4,
                [assertion] * 4,
            )
        )
    assert results.count("accepted") == 1
    assert results.count("replay") == 3

    with Session(engine) as db:
        assert db.scalar(select(func.count(FederatedAssertion.id))) == 1
        assert db.scalar(select(func.count(FederationReplayNonce.id))) == 1
        peer = db.get(FederationPeer, peer_id)
        peer.status = "revoked"
        peer.revoked_at = datetime.now(UTC)
        db.commit()
        with pytest.raises(FederationVerificationError, match="not trusted"):
            receive_assertion(
                db,
                organization_id=organization_id,
                peer=peer,
                assertion=create_assertion(
                    key,
                    assertion_type="indicator_assessment",
                    subject_type="domain",
                    subject_fingerprint="c" * 64,
                    evidence_fingerprint="d" * 64,
                    source_category="attack_surface",
                    confidence=60,
                    severity="medium",
                    observation_time=datetime.now(UTC),
                ),
            )
        db.rollback()
        assert db.scalar(select(func.count(FederatedAssertion.id))) == 1
    Base.metadata.drop_all(engine)
    engine.dispose()
