from __future__ import annotations

import json
import os
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from intel_platform.detection_engine import ingest_network_events, parse_json_lines, parse_sigma
from intel_platform.malware_analysis import (
    correlate_hashes,
    quarantine_file,
    scan_clamav,
    scan_yara,
)
from intel_platform.models import (
    AlertNotification,
    Base,
    CollectionJob,
    CollectionJobEvent,
    Entity,
    EvidenceChange,
    EvidenceSource,
    Finding,
    Investigation,
    InvestigationStatus,
    JobStatus,
    NetworkDetection,
    NotificationPreference,
    Relationship,
    Target,
    TargetType,
    ThreatIntelObject,
)
from intel_platform.normalization import canonicalize_target
from intel_platform.notifications import (
    _deliver_email,
    _deliver_webhook,
    _suppression_reason,
    deliver_pending_notifications,
    emit_notification,
    validate_webhook_url,
)
from intel_platform.report_exports import (
    findings_csv,
    json_export,
    stix_export,
    timeline_csv,
    timeline_records,
)
from intel_platform.worker import (
    apply_direct_verification,
    claim_next_job,
    compare_redacted_payloads,
    execute_safe_mock,
    reconcile_findings,
    record_evidence_change,
    recover_expired_jobs,
)


@pytest.fixture
def session_factory(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'critical.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    engine.dispose()


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        (TargetType.DOMAIN, " Exämple.COM. ", "xn--exmple-cua.com"),
        (TargetType.IP_ADDRESS, "2001:0db8::1", "2001:db8::1"),
        (TargetType.NETWORK, "8.8.8.0/30", "8.8.8.0/30"),
        (TargetType.ASN, "as00123", "AS123"),
        (TargetType.URL, "HTTPS://Exämple.com/path?q=1", "https://xn--exmple-cua.com/path?q=1"),
        (TargetType.EMAIL_ADDRESS, "Analyst@EXAMPLE.COM.", "Analyst@example.com"),
        (TargetType.USERNAME, "  signal   analyst ", "signal analyst"),
        (TargetType.CONTAINER_IMAGE, "GHCR.IO/ORG/APP:1.2.3", "ghcr.io/org/app:1.2.3"),
        (
            TargetType.REPOSITORY,
            "https://github.com/Example/CYPHERYN",
            "https://github.com/Example/CYPHERYN.git",
        ),
    ],
)
def test_target_canonicalization_valid_cases(kind: TargetType, raw: str, expected: str) -> None:
    assert canonicalize_target(kind, raw) == expected


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        (TargetType.DOMAIN, "invalid"),
        (TargetType.NETWORK, "10.0.0.0/24"),
        (TargetType.NETWORK, "8.8.0.0/16"),
        (TargetType.ASN, "AS0"),
        (TargetType.URL, "file:///etc/passwd"),
        (TargetType.EMAIL_ADDRESS, "@example.test"),
        (TargetType.REPOSITORY, "http://github.com/owner/repo"),
        (TargetType.CONTAINER_IMAGE, "ubuntu"),
    ],
)
def test_target_canonicalization_rejects_unsafe_cases(kind: TargetType, raw: str) -> None:
    with pytest.raises(HTTPException) as error:
        canonicalize_target(kind, raw)
    assert error.value.status_code == 422


def test_local_repository_and_sbom_paths_are_constrained(tmp_path: Path) -> None:
    repository = tmp_path / "owner" / "project"
    repository.mkdir(parents=True)
    sbom = tmp_path / "inventory.json"
    sbom.write_text("{}", encoding="utf-8")
    assert canonicalize_target(TargetType.REPOSITORY, str(repository)) == str(repository.resolve())
    assert canonicalize_target(TargetType.SBOM, str(sbom)) == str(sbom.resolve())
    with pytest.raises(HTTPException):
        canonicalize_target(TargetType.SBOM, str(repository))


def test_detection_parsers_handle_valid_invalid_and_partial_input() -> None:
    rule = parse_sigma(
        """
title: Suspicious connection
id: rule-1
level: unexpected
logsource: {category: network_connection}
detection: {selection: {DestinationPort: 4444}, condition: selection}
tags: [attack.command-and-control]
"""
    )
    assert rule["rule_id"] == "rule-1"
    assert rule["level"] == "medium"
    for invalid in ("[]", "title: Missing", "title: x\nlogsource: {}"):
        with pytest.raises(ValueError):
            parse_sigma(invalid)
    events, skipped = parse_json_lines(b'# comment\n{"ok": 1}\ninvalid\n[1]\n')
    assert events == [{"ok": 1}]
    assert skipped == 2


def test_network_ingest_normalizes_and_correlates_suricata_and_zeek(session_factory) -> None:
    with session_factory() as db:
        investigation = Investigation(
            id="inv", organization_id="org", owner_id="user", name="Network evidence"
        )
        db.add_all(
            [
                investigation,
                Entity(
                    investigation_id="inv",
                    entity_type="ip_address",
                    canonical_value="203.0.113.4",
                    provider="test",
                ),
            ]
        )
        db.commit()
        suricata = (
            b'{"event_type":"alert","timestamp":"2026-08-29T00:00:00Z",'
            b'"src_ip":"203.0.113.4","dest_ip":"198.51.100.8","src_port":22,'
            b'"dest_port":443,"proto":"TCP","alert":{"severity":1,"signature":"Test"}}\n'
            b'{"event_type":"flow"}\n'
        )
        result = ingest_network_events(db, investigation, "suricata", suricata)
        assert result == {"source": "suricata", "imported": 1, "correlated": 1, "skipped": 1}
        zeek = b'{"_path":"notice","ts":1760000000,"id.orig_h":"192.0.2.1","note":"Scan"}\n'
        assert ingest_network_events(db, investigation, "zeek", zeek)["imported"] == 1
        detections = list(db.scalars(select(NetworkDetection)))
        assert detections[0].severity == "high"
        assert detections[0].correlated_entity_ids
        assert detections[1].severity == "medium"


def test_malware_quarantine_hashes_permissions_and_scanner_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample, hashes = quarantine_file(b"cypheryn", str(tmp_path / "quarantine"))
    assert hashes["sha256"] == "bf85914b9dcf2e710edc322fb97cd7fe2a6afb059bd00c40c5a6b3d867ce65e9"
    assert sample.read_bytes() == b"cypheryn"
    if os.name == "posix":
        assert os.stat(sample).st_mode & 0o777 == 0o600
    monkeypatch.setattr("intel_platform.malware_analysis.shutil.which", lambda name: None)
    assert scan_clamav(sample)["status"] == "not_installed"
    assert scan_yara(sample, tmp_path / "missing.yar") == []

    monkeypatch.setattr("intel_platform.malware_analysis.shutil.which", lambda name: f"/{name}")
    infected = SimpleNamespace(returncode=1, stdout=f"{sample}: Test.Signature FOUND\n", stderr="")
    monkeypatch.setattr("intel_platform.malware_analysis.subprocess.run", lambda *a, **k: infected)
    assert scan_clamav(sample)["signature"] == "Test.Signature"
    rules = tmp_path / "rules.yar"
    rules.write_text("rule test { condition: true }", encoding="utf-8")
    yara_result = SimpleNamespace(
        returncode=0, stdout="rule_one sample\nrule_two sample\n", stderr=""
    )
    monkeypatch.setattr(
        "intel_platform.malware_analysis.subprocess.run", lambda *a, **k: yara_result
    )
    assert [item["rule"] for item in scan_yara(sample, rules)] == ["rule_one", "rule_two"]
    monkeypatch.setattr(
        "intel_platform.malware_analysis.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("scan", 1)),
    )
    assert scan_clamav(sample)["status"] == "timeout"
    assert scan_yara(sample, rules)[0]["rule"] == "scanner_timeout"


def test_malware_hash_correlation_ignores_revoked_and_unmatched(session_factory) -> None:
    digest = "a" * 64
    with session_factory() as db:
        db.add_all(
            [
                ThreatIntelObject(
                    organization_id="org",
                    stix_id="indicator--one",
                    object_type="indicator",
                    name="Known sample",
                    pattern=f"[file:hashes.'SHA-256' = '{digest}']",
                    source="trusted",
                    confidence=90,
                ),
                ThreatIntelObject(
                    organization_id="org",
                    stix_id="indicator--revoked",
                    object_type="indicator",
                    pattern=f"[file:hashes.'SHA-256' = '{digest}']",
                    revoked=True,
                ),
            ]
        )
        db.commit()
        matches = correlate_hashes(db, "org", [digest.upper(), ""])
        assert len(matches) == 1
        assert matches[0]["matched_hashes"] == [digest]


def test_notification_url_validation_suppression_and_deduplication(
    session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    assert validate_webhook_url("https://alerts.example.test/hook").startswith("https://")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="public"):
        validate_webhook_url("https://localhost/hook")
    with pytest.raises(ValueError, match="HTTPS"):
        validate_webhook_url("http://example.test/hook")

    now = datetime(2026, 8, 29, 23, tzinfo=UTC)
    preference = NotificationPreference(
        organization_id="org", quiet_start_hour=22, quiet_end_hour=6, dedupe_minutes=60
    )
    assert _suppression_reason(preference, now) == "quiet_period"
    preference.maintenance_starts_at = now - timedelta(minutes=1)
    preference.maintenance_ends_at = now + timedelta(minutes=1)
    assert _suppression_reason(preference, now) == "maintenance_window"

    with session_factory() as db:
        db.add(preference)
        db.commit()
        first = emit_notification(
            db,
            organization_id="org",
            event_type="finding.opened",
            title="Opened",
            message="first",
            dedupe_key="same",
        )
        second = emit_notification(
            db,
            organization_id="org",
            event_type="finding.opened",
            title="Opened",
            message="updated",
            dedupe_key="same",
        )
        assert first.id == second.id
        assert second.occurrence_count == 2
        assert second.message == "updated"


def test_notification_delivery_records_success_and_bounded_failure(
    session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory() as db:
        db.add(
            NotificationPreference(
                organization_id="org",
                email_enabled=True,
                email_to="analyst@example.test",
                webhook_enabled=True,
                webhook_url="https://alerts.example.test/hook",
            )
        )
        db.add(
            AlertNotification(
                organization_id="org",
                event_type="test",
                title="Delivery",
                message="message",
                dedupe_key="delivery",
                email_status="pending",
                webhook_status="pending",
            )
        )
        db.commit()
    monkeypatch.setattr("intel_platform.notifications._deliver_email", lambda *a: None)
    monkeypatch.setattr(
        "intel_platform.notifications._deliver_webhook",
        lambda *a: (_ for _ in ()).throw(RuntimeError("provider secret must not appear")),
    )
    assert deliver_pending_notifications(session_factory) == 1
    with session_factory() as db:
        notification = db.scalar(select(AlertNotification))
        assert notification.email_status == "delivered"
        assert notification.webhook_status == "failed"
        assert notification.delivery_error == "provider secret must not appear"


def test_email_and_webhook_delivery_apply_transport_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeSmtp:
        def __init__(self, host, port, timeout):
            calls.append(f"connect:{host}:{port}:{timeout}")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def starttls(self, context):
            calls.append("tls")

        def login(self, username, password):
            calls.append(f"login:{username}:{password}")

        def send_message(self, message):
            calls.append(f"send:{message['To']}")

    transport_password = "-".join(("transport", "password"))
    settings = SimpleNamespace(
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_from="cypheryn@example.test",
        smtp_use_tls=True,
        smtp_username="mailer",
        smtp_password=transport_password,
        provider_encryption_key="unused",
    )
    notification = SimpleNamespace(
        id="notice",
        title="Security change",
        message="A finding changed",
        event_type="finding.changed",
        severity="high",
        investigation_id="inv",
        finding_id="finding",
        created_at=datetime.now(UTC),
    )
    preference = SimpleNamespace(
        email_to="analyst@example.test",
        webhook_url="https://alerts.example.test/hook",
        encrypted_webhook_secret=None,
    )
    monkeypatch.setattr("intel_platform.notifications.get_settings", lambda: settings)
    monkeypatch.setattr("intel_platform.notifications.smtplib.SMTP", FakeSmtp)
    _deliver_email(notification, preference)
    assert calls == [
        "connect:smtp.example.test:587:20",
        "tls",
        "login:mailer:transport-password",
        "send:analyst@example.test",
    ]
    monkeypatch.setattr(
        "intel_platform.notifications.validate_webhook_url", lambda value: value
    )
    sent = {}

    def post(url, **kwargs):
        sent.update(url=url, **kwargs)
        return SimpleNamespace(status_code=204)

    monkeypatch.setattr("intel_platform.notifications.httpx.post", post)
    _deliver_webhook(notification, preference)
    assert sent["url"].startswith("https://")
    assert sent["follow_redirects"] is False
    assert b"A finding changed" in sent["content"]
    monkeypatch.setattr(
        "intel_platform.notifications.httpx.post",
        lambda *a, **k: SimpleNamespace(status_code=500),
    )
    with pytest.raises(RuntimeError, match="HTTP 500"):
        _deliver_webhook(notification, preference)


def test_reports_preserve_evidence_integrity_and_escape_csv() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    investigation = Investigation(
        id="inv",
        organization_id="org",
        owner_id="user",
        name="Report",
        description="Evidence report",
        status=InvestigationStatus.ACTIVE,
    )
    target = Target(
        id="target",
        investigation_id="inv",
        authorization_id="auth",
        target_type=TargetType.DOMAIN,
        raw_value="example.test",
        canonical_value="example.test",
    )
    source = EvidenceSource(
        id="source",
        investigation_id="inv",
        job_id="job",
        target_id="target",
        authorization_id="auth",
        provider="virustotal",
        provider_version="v3",
        ruleset_version="native",
        query="example.test",
        raw_response_hash="a" * 64,
        previous_integrity_hash="b" * 64,
        integrity_hash="c" * 64,
        redacted_payload={"verdict": "clean"},
        retrieved_at=now,
        retain_until=now + timedelta(days=1),
    )
    finding = Finding(
        id="finding",
        investigation_id="inv",
        source_id="source",
        rule_id="rule",
        title='Formula, "quoted"',
        description="Description",
        severity="medium",
        status="open",
        asset_value="example.test",
        provider="virustotal",
        created_at=now,
        updated_at=now,
        verification_history=[{"observed_at": now.isoformat(), "classification": "confirmed"}],
    )
    entity = Entity(
        id="entity",
        investigation_id="inv",
        entity_type="domain",
        canonical_value="example.test",
        provider="virustotal",
    )
    related = Entity(
        id="ip",
        investigation_id="inv",
        entity_type="ip_address",
        canonical_value="203.0.113.8",
        provider="virustotal",
    )
    relationship = Relationship(
        id="relation",
        investigation_id="inv",
        subject_entity_id="entity",
        predicate="RESOLVES_TO",
        object_entity_id="ip",
        provider="virustotal",
    )
    change = EvidenceChange(
        id="change",
        investigation_id="inv",
        target_id="target",
        provider="virustotal",
        previous_source_id="old",
        current_source_id="source",
        summary="Evidence changed",
        created_at=now + timedelta(minutes=1),
    )
    event = CollectionJobEvent(
        id="event",
        job_id="job",
        event_type="completed",
        to_status="completed",
        message="Done",
        occurred_at=now + timedelta(minutes=2),
    )
    exported = json.loads(
        json_export(
            investigation,
            [target],
            [finding],
            [source],
            [change],
            [event],
            [entity, related],
            [relationship],
            integrity_anchor={
                "signing_key_id": "ed25519:test",
                "checkpoint": {"record_count": 1},
            },
        )
    )
    assert exported["data"]["evidence_sources"][0]["integrity_hash"] == "c" * 64
    assert exported["data"]["integrity_anchor"]["signing_key_id"] == "ed25519:test"
    assert len(exported["manifest"]["content_sha256"]) == 64
    timeline = timeline_records([source], [change], [finding], [event])
    assert timeline == sorted(timeline, key=lambda item: item["timestamp"])
    assert b'"Formula, ""quoted"""' in findings_csv([finding])
    assert b"event_type" in timeline_csv(timeline)
    bundle = json.loads(stix_export(investigation, [finding], [entity, related], [relationship]))
    assert {item["type"] for item in bundle["objects"]} >= {
        "identity",
        "domain-name",
        "ipv4-addr",
        "relationship",
        "note",
    }


def test_worker_recovers_cancelled_failed_and_retryable_leases(session_factory) -> None:
    expired = datetime.now(UTC) - timedelta(minutes=1)
    with session_factory() as db:
        jobs = [
            CollectionJob(
                id="cancel",
                investigation_id="inv",
                target_id="target",
                status=JobStatus.RUNNING,
                lease_expires_at=expired,
                cancellation_requested_at=expired,
            ),
            CollectionJob(
                id="failed",
                investigation_id="inv",
                target_id="target",
                status=JobStatus.RUNNING,
                lease_expires_at=expired,
                attempt=3,
                max_attempts=3,
            ),
            CollectionJob(
                id="retry",
                investigation_id="inv",
                target_id="target",
                status=JobStatus.RUNNING,
                lease_expires_at=expired,
                attempt=1,
                max_attempts=3,
            ),
        ]
        db.add_all(jobs)
        db.commit()
        assert recover_expired_jobs(db) == 3
        assert db.get(CollectionJob, "cancel").status == JobStatus.CANCELLED
        assert db.get(CollectionJob, "failed").status == JobStatus.FAILED
        assert db.get(CollectionJob, "retry").status == JobStatus.QUEUED
        assert {event.event_type for event in db.scalars(select(CollectionJobEvent))} == {
            "cancelled",
            "failed",
            "lease_recovered",
        }


def test_worker_claim_is_atomic_and_safe_mock_is_idempotent(session_factory) -> None:
    with session_factory() as db:
        db.add(
            Target(
                id="target",
                investigation_id="inv",
                authorization_id="auth",
                target_type=TargetType.DOMAIN,
                raw_value="example.test",
                canonical_value="example.test",
            )
        )
        db.add(
            CollectionJob(
                id="queued",
                investigation_id="inv",
                target_id="target",
                status=JobStatus.QUEUED,
            )
        )
        db.commit()
        claimed = claim_next_job(db, "worker-1")
        assert claimed.status == JobStatus.RUNNING
        assert claimed.attempt == 1
        assert claimed.lease_owner == "worker-1"
        assert claim_next_job(db, "worker-2") is None
        assert execute_safe_mock(db, claimed) == 4
        db.commit()
        assert execute_safe_mock(db, claimed) == 4
        db.commit()
        assert len(list(db.scalars(select(Entity)))) == 4
        assert len(list(db.scalars(select(Relationship)))) == 3


def test_evidence_comparison_ignores_volatile_fields_and_records_real_change(
    session_factory,
) -> None:
    comparison = compare_redacted_payloads(
        {"scan_time": "old", "services": [{"port": 80}], "value": 1},
        {"scan_time": "new", "services": [{"port": 443}], "value": 2},
    )
    assert comparison["changed_field_count"] == 2
    now = datetime.now(UTC)
    with session_factory() as db:
        old = EvidenceSource(
            id="old",
            investigation_id="inv",
            job_id="job-old",
            target_id="target",
            authorization_id="auth",
            provider="censys",
            query="example.test",
            raw_response_hash="a" * 64,
            redacted_payload={"services": [80]},
            retrieved_at=now - timedelta(minutes=1),
            retain_until=now + timedelta(days=1),
        )
        current = EvidenceSource(
            id="current",
            investigation_id="inv",
            job_id="job-current",
            target_id="target",
            authorization_id="auth",
            provider="censys",
            query="example.test",
            raw_response_hash="b" * 64,
            redacted_payload={"services": [443], "risk": "changed"},
            retrieved_at=now,
            retain_until=now + timedelta(days=1),
        )
        db.add_all([old, current])
        db.commit()
        change = record_evidence_change(db, current)
        assert change is not None
        assert change.details["changed_field_count"] == 2
        db.flush()
        assert record_evidence_change(db, old) is not None


def test_finding_reconciliation_opens_confirms_and_resolves_after_two_clean_runs(
    session_factory,
) -> None:
    now = datetime.now(UTC)
    with session_factory() as db:
        source = EvidenceSource(
            id="finding-source",
            investigation_id="inv",
            job_id="job",
            target_id="target",
            authorization_id="auth",
            provider="nuclei",
            query="example.test",
            raw_response_hash="d" * 64,
            redacted_payload={},
            retrieved_at=now,
            retain_until=now + timedelta(days=1),
        )
        db.add(source)
        db.commit()
        candidate = {
            "rule_id": "web.cwe.79",
            "asset_value": "https://example.test/",
            "entity_value": "example.test",
            "title": "Reflected input",
            "description": "Input appeared in output",
            "severity": "high",
            "confidence": 90,
        }
        reconcile_findings(db, source, [candidate])
        db.commit()
        finding = db.scalar(select(Finding))
        assert finding.status == "open"
        assert finding.confidence == 90
        reconcile_findings(db, source, [])
        db.commit()
        assert finding.status == "verifying"
        assert finding.clean_observations == 1
        reconcile_findings(db, source, [])
        db.commit()
        assert finding.status == "resolved"
        assert finding.resolved_at is not None
        changed = {**candidate, "title": "Reflected input confirmed", "severity": "critical"}
        reconcile_findings(db, source, [changed])
        db.commit()
        assert finding.status == "open"
        assert finding.title == "Reflected input confirmed"
        assert finding.severity == "critical"


def test_direct_verification_distinguishes_confirmed_fixed_and_stale(session_factory) -> None:
    now = datetime.now(UTC)
    with session_factory() as db:
        source = EvidenceSource(
            id="direct-source",
            investigation_id="inv",
            job_id="origin-job",
            target_id="target",
            authorization_id="auth",
            provider="censys",
            query="203.0.113.8",
            retrieved_at=now - timedelta(days=2),
            retain_until=now + timedelta(days=1),
        )
        job = CollectionJob(
            id="verify-job",
            investigation_id="inv",
            target_id="target",
            status=JobStatus.RUNNING,
        )
        finding = Finding(
            id="direct-finding",
            investigation_id="inv",
            source_id="direct-source",
            verification_job_id="verify-job",
            rule_id="censys.service",
            title="Public SSH",
            description="SSH observed",
            severity="medium",
            asset_value="203.0.113.8:22/tcp",
            provider="censys",
            evidence_observed_at=now - timedelta(days=2),
        )
        db.add_all([source, job, finding])
        db.commit()
        apply_direct_verification(
            db,
            job,
            {
                "observed_at": now.isoformat(),
                "services": [
                    {"address": "203.0.113.8", "port": 22, "protocol": "tcp", "state": "responded"}
                ],
            },
        )
        assert finding.verification_state == "confirmed"
        assert finding.status == "open"
        for expected in ("fixed_pending_confirmation", "fixed"):
            apply_direct_verification(
                db,
                job,
                {
                    "observed_at": now.isoformat(),
                    "services": [
                        {
                            "address": "203.0.113.8",
                            "port": 22,
                            "protocol": "tcp",
                            "state": "refused",
                        }
                    ],
                },
            )
            assert finding.verification_state == expected
        assert finding.status == "resolved"
        finding.asset_value = "not-a-service"
        finding.provider_observed_at = now - timedelta(days=2)
        apply_direct_verification(db, job, {"observed_at": now.isoformat(), "services": []})
        assert finding.verification_state == "stale"
        assert finding.status == "verifying"
        assert len(finding.verification_history) == 4
