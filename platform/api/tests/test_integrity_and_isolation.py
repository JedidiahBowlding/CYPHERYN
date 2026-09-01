import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from intel_platform.integrity import seal_audit_event, seal_evidence_source
from intel_platform.models import AuditEvent, Base, EvidenceSource
from intel_platform.process_isolation import MAX_CAPTURE_BYTES, run_isolated_process
from intel_platform.schema_upgrade import upgrade_existing_schema


def test_anchor_key_initializer_drops_privileges_before_key_operations() -> None:
    root = Path(__file__).resolve().parents[3]
    compose = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    initializer = compose["services"]["anchor-key-init"]

    assert initializer["user"] == "0:0"
    assert initializer["cap_drop"] == ["ALL"]
    assert set(initializer["cap_add"]) == {
        "CHOWN",
        "DAC_OVERRIDE",
        "SETGID",
        "SETUID",
    }
    assert initializer["read_only"] is True
    command = " ".join(initializer["command"])
    assert command.index("chown -R 10001:10001") < command.index("runuser -u appuser")
    assert command.index("runuser -u appuser") < command.index("integrity_anchor")


def test_evidence_integrity_detects_mutation(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'integrity.db'}")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as db:
        source = EvidenceSource(
            investigation_id="investigation",
            job_id="job",
            target_id="target",
            authorization_id="authorization",
            provider="virustotal",
            provider_version="v3",
            ruleset_version="provider-native",
            query="example.test",
            raw_response_hash="a" * 64,
            redacted_payload={"verdict": "clean"},
            redaction_policy="central-default-v2",
            retrieved_at=now,
            retain_until=now + timedelta(days=30),
        )
        db.add(source)
        db.flush()
        seal_evidence_source(db, source)
        original = source.integrity_hash
        assert original and len(original) == 64
        source.query = "mutated.example"
        seal_evidence_source(db, source)
        assert source.integrity_hash != original


def test_audit_events_form_an_integrity_chain(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = AuditEvent(
            organization_id="org",
            actor_id="user",
            action="first",
            object_type="test",
            object_id="one",
            decision="allowed",
            reason_code="authorized",
            occurred_at=datetime.now(UTC),
        )
        db.add(first)
        db.flush()
        seal_audit_event(db, first)
        db.flush()
        second = AuditEvent(
            organization_id="org",
            actor_id="user",
            action="second",
            object_type="test",
            object_id="two",
            decision="allowed",
            reason_code="authorized",
            occurred_at=datetime.now(UTC) + timedelta(microseconds=1),
        )
        db.add(second)
        db.flush()
        seal_audit_event(db, second)
        assert second.previous_integrity_hash == first.integrity_hash
        assert second.integrity_hash != first.integrity_hash


def test_isolated_process_has_bounded_output() -> None:
    result = run_isolated_process([sys.executable, "-c", "print('x' * 2100000)"], timeout=5)
    assert result.returncode == 0
    assert len(result.stdout) == MAX_CAPTURE_BYTES


def test_isolated_process_is_hard_terminated() -> None:
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        run_isolated_process([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2)
    assert time.monotonic() - started < 3


def test_additive_schema_upgrade_adds_integrity_columns(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE collection_jobs (id VARCHAR(36))")
        connection.exec_driver_sql("CREATE TABLE findings (id VARCHAR(36))")
        connection.exec_driver_sql("CREATE TABLE organizations (id VARCHAR(36))")
        connection.exec_driver_sql("CREATE TABLE evidence_sources (id VARCHAR(36))")
        connection.exec_driver_sql("CREATE TABLE audit_events (id VARCHAR(36))")
        connection.exec_driver_sql(
            "CREATE TABLE relationships ("
            "id VARCHAR(36), investigation_id VARCHAR(36), subject_entity_id VARCHAR(36), "
            "predicate VARCHAR(80), object_entity_id VARCHAR(36), provider VARCHAR(100))"
        )
    upgrade_existing_schema(engine)
    evidence_columns = {item["name"] for item in inspect(engine).get_columns("evidence_sources")}
    audit_columns = {item["name"] for item in inspect(engine).get_columns("audit_events")}
    assert {"previous_integrity_hash", "integrity_hash"} <= evidence_columns
    assert {"previous_integrity_hash", "integrity_hash"} <= audit_columns
