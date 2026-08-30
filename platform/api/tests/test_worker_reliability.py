from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from intel_platform.models import (
    AlertNotification,
    AnalysisSnapshot,
    Authorization,
    Base,
    CollectionJob,
    EvidenceSource,
    Finding,
    Investigation,
    InvestigationStatus,
    JobStatus,
    MonitorSchedule,
    Organization,
    ReportArtifact,
    ReportSchedule,
    Target,
    TargetType,
    User,
)
from intel_platform.provider_contract import registry
from intel_platform.providers import register_builtin_providers
from intel_platform.worker import (
    enqueue_due_finding_monitors,
    enqueue_due_schedules,
    generate_due_reports,
    monitor_job_health,
    regenerate_monitoring_summary,
)


@pytest.fixture
def session_factory(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-reliability.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    register_builtin_providers(registry)
    yield factory
    engine.dispose()


def seed_scope(factory, *, active_allowed: bool = True):
    now = datetime.now(UTC)
    with factory() as db:
        user = User(external_subject="worker-test-user", email="worker@example.test")
        organization = Organization(name="Worker Reliability")
        db.add_all([user, organization])
        db.flush()
        authorization = Authorization(
            organization_id=organization.id,
            authorizer_id=user.id,
            basis="Explicit authorization for worker reliability tests",
            passive_allowed=True,
            active_allowed=active_allowed,
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        )
        investigation = Investigation(
            organization_id=organization.id,
            owner_id=user.id,
            name="Worker lifecycle",
            status=InvestigationStatus.ACTIVE,
        )
        db.add_all([authorization, investigation])
        db.flush()
        target = Target(
            investigation_id=investigation.id,
            authorization_id=authorization.id,
            target_type=TargetType.DOMAIN,
            raw_value="example.test",
            canonical_value="example.test",
        )
        db.add(target)
        db.commit()
        return user.id, organization.id, authorization.id, investigation.id, target.id


def test_due_schedule_queues_once_and_advances_deadline(session_factory) -> None:
    user_id, _org_id, _auth_id, investigation_id, target_id = seed_scope(session_factory)
    due = datetime.now(UTC) - timedelta(minutes=1)
    with session_factory() as db:
        schedule = MonitorSchedule(
            investigation_id=investigation_id,
            target_id=target_id,
            provider="safe_mock",
            interval_minutes=30,
            next_run_at=due,
        )
        db.add(schedule)
        db.commit()
        schedule_id = schedule.id

    assert enqueue_due_schedules(session_factory) == 1
    assert enqueue_due_schedules(session_factory) == 0
    with session_factory() as db:
        schedule = db.get(MonitorSchedule, schedule_id)
        jobs = list(db.scalars(select(CollectionJob)))
        assert schedule is not None and schedule.last_job_id == jobs[0].id
        assert schedule.next_run_at > datetime.now(UTC).replace(tzinfo=None)
        assert jobs[0].requested_by_id == user_id
        assert jobs[0].status == JobStatus.QUEUED


def test_finding_monitor_creates_direct_verification_and_deduplicates(session_factory) -> None:
    user_id, _org_id, auth_id, investigation_id, target_id = seed_scope(session_factory)
    now = datetime.now(UTC)
    with session_factory() as db:
        source_job = CollectionJob(
            investigation_id=investigation_id,
            target_id=target_id,
            requested_by_id=user_id,
            provider="safe_mock",
            status=JobStatus.COMPLETED,
        )
        db.add(source_job)
        db.flush()
        source = EvidenceSource(
            investigation_id=investigation_id,
            job_id=source_job.id,
            target_id=target_id,
            authorization_id=auth_id,
            provider="safe_mock",
            query="example.test",
            retain_until=now + timedelta(days=30),
        )
        db.add(source)
        db.flush()
        finding = Finding(
            investigation_id=investigation_id,
            source_id=source.id,
            rule_id="unexpected-ssh",
            title="Unexpected SSH",
            description="A public service requires verification.",
            severity="medium",
            asset_value="203.0.113.10:22/tcp",
            provider="safe_mock",
            monitoring_enabled=True,
            monitoring_interval_minutes=15,
            next_monitor_at=now - timedelta(minutes=1),
        )
        db.add(finding)
        db.commit()
        finding_id = finding.id

    assert enqueue_due_finding_monitors(session_factory) == 1
    assert enqueue_due_finding_monitors(session_factory) == 0
    with session_factory() as db:
        finding = db.get(Finding, finding_id)
        job = db.get(CollectionJob, finding.verification_job_id)
        target = db.get(Target, job.target_id)
        assert job.provider == "direct_verifier"
        assert finding.verification_state == "queued"
        assert target.target_type == TargetType.IP_ADDRESS
        assert target.canonical_value == "203.0.113.10"


def test_expired_authorization_blocks_finding_monitor_and_notifies(session_factory) -> None:
    user_id, org_id, auth_id, investigation_id, target_id = seed_scope(
        session_factory, active_allowed=False
    )
    now = datetime.now(UTC)
    with session_factory() as db:
        source_job = CollectionJob(
            investigation_id=investigation_id,
            target_id=target_id,
            requested_by_id=user_id,
            provider="safe_mock",
            status=JobStatus.COMPLETED,
        )
        db.add(source_job)
        db.flush()
        source = EvidenceSource(
            investigation_id=investigation_id,
            job_id=source_job.id,
            target_id=target_id,
            authorization_id=auth_id,
            provider="safe_mock",
            query="example.test",
            retain_until=now + timedelta(days=1),
        )
        db.add(source)
        db.flush()
        db.add(
            Finding(
                investigation_id=investigation_id,
                source_id=source.id,
                rule_id="unexpected-rdp",
                title="Unexpected RDP",
                description="Authorization must be current.",
                severity="medium",
                asset_value="203.0.113.11:3389/tcp",
                provider="safe_mock",
                monitoring_enabled=True,
                next_monitor_at=now - timedelta(minutes=1),
            )
        )
        db.commit()

    assert enqueue_due_finding_monitors(session_factory) == 0
    with session_factory() as db:
        alert = db.scalar(select(AlertNotification))
        assert alert is not None
        assert alert.organization_id == org_id
        assert alert.event_type == "monitor.authorization_expired"


def test_health_monitor_emits_once_for_each_stalled_job(session_factory) -> None:
    user_id, _org_id, _auth_id, investigation_id, target_id = seed_scope(session_factory)
    now = datetime.now(UTC)
    with session_factory() as db:
        db.add_all(
            [
                CollectionJob(
                    investigation_id=investigation_id,
                    target_id=target_id,
                    requested_by_id=user_id,
                    provider="safe_mock",
                    status=JobStatus.QUEUED,
                    created_at=now - timedelta(minutes=20),
                ),
                CollectionJob(
                    investigation_id=investigation_id,
                    target_id=target_id,
                    requested_by_id=user_id,
                    provider="safe_mock",
                    status=JobStatus.RUNNING,
                    lease_expires_at=now - timedelta(minutes=1),
                ),
            ]
        )
        db.commit()

    assert monitor_job_health(session_factory) == 2
    assert monitor_job_health(session_factory) == 0
    with session_factory() as db:
        assert db.scalar(select(func.count(AlertNotification.id))) == 2


def test_monitoring_summary_and_due_report_are_persisted(session_factory, monkeypatch) -> None:
    user_id, _org_id, _auth_id, investigation_id, target_id = seed_scope(session_factory)
    now = datetime.now(UTC)
    with session_factory() as db:
        job = CollectionJob(
            investigation_id=investigation_id,
            target_id=target_id,
            requested_by_id=user_id,
            provider="safe_mock",
            status=JobStatus.COMPLETED,
        )
        db.add(job)
        db.flush()
        db.add(
            MonitorSchedule(
                investigation_id=investigation_id,
                target_id=target_id,
                provider="safe_mock",
                interval_minutes=60,
                next_run_at=now + timedelta(hours=1),
                last_job_id=job.id,
            )
        )
        db.flush()
        regenerate_monitoring_summary(db, job, generate_ai=False)
        db.add(
            ReportSchedule(
                investigation_id=investigation_id,
                created_by_id=user_id,
                style="technical",
                interval_minutes=60,
                next_run_at=now - timedelta(minutes=1),
            )
        )
        db.commit()
        assert db.scalar(select(func.count(AnalysisSnapshot.id))) == 1

    monkeypatch.setattr("intel_platform.worker.latest_anchor_metadata", lambda *_args: None)
    assert generate_due_reports(session_factory) == 1
    assert generate_due_reports(session_factory) == 0
    with session_factory() as db:
        artifact = db.scalar(select(ReportArtifact))
        assert artifact is not None
        assert artifact.filename.startswith("cypheryn-")
        assert artifact.content.startswith(b"%PDF")
        assert len(artifact.sha256) == 64
