import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class MembershipRole(enum.StrEnum):
    ORGANIZATION_ADMIN = "organization_admin"
    INVESTIGATION_LEAD = "investigation_lead"
    ANALYST = "analyst"
    VIEWER = "viewer"
    COMPLIANCE_AUDITOR = "compliance_auditor"


class InvestigationStatus(enum.StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class TargetType(enum.StrEnum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    NETWORK = "network"
    ASN = "asn"
    URL = "url"
    EMAIL_ADDRESS = "email_address"
    USERNAME = "username"
    ORGANIZATION = "organization"
    PERSON = "person"
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"
    SBOM = "sbom"


class JobStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    external_subject: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LegalAcceptance(Base):
    __tablename__ = "legal_acceptances"
    __table_args__ = (
        UniqueConstraint("user_id", "terms_version", "responsible_use_version"),
        Index("ix_legal_acceptance_user_time", "user_id", "accepted_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    terms_version: Mapped[str] = mapped_column(String(30), nullable=False)
    responsible_use_version: Mapped[str] = mapped_column(String(30), nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    report_title: Mapped[str] = mapped_column(String(200), default="CYPHERYN", nullable=False)
    report_accent: Mapped[str] = mapped_column(String(7), default="#147d72", nullable=False)
    report_logo: Mapped[bytes | None] = mapped_column(LargeBinary)
    report_logo_mime: Mapped[str] = mapped_column(String(30), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    role: Mapped[MembershipRole] = mapped_column(Enum(MembershipRole), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigation_org_status", "organization_id", "status"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus), default=InvestigationStatus.DRAFT
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    targets: Mapped[list["Target"]] = relationship(back_populates="investigation")


class Authorization(Base):
    __tablename__ = "authorizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    authorizer_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    basis: Mapped[str] = mapped_column(Text, nullable=False)
    passive_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    active_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("investigation_id", "target_type", "canonical_value"),
        Index("ix_target_investigation", "investigation_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("authorizations.id"), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType), nullable=False)
    raw_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    include_descendants: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="targets")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_org_time", "organization_id", "occurred_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    object_type: Mapped[str] = mapped_column(String(100), nullable=False)
    object_id: Mapped[str] = mapped_column(String(36), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    previous_integrity_hash: Mapped[str | None] = mapped_column(String(64))
    integrity_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectionJob(Base):
    __tablename__ = "collection_jobs"
    __table_args__ = (Index("ix_job_investigation_created", "investigation_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    requested_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    provider: Mapped[str] = mapped_column(String(100), nullable=False, default="safe_mock")
    profile: Mapped[str] = mapped_column(String(50), nullable=False, default="passive")
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.QUEUED)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_owner: Mapped[str | None] = mapped_column(String(120))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CollectionJobEvent(Base):
    __tablename__ = "collection_job_events"
    __table_args__ = (Index("ix_job_event_job_time", "job_id", "occurred_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("collection_jobs.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(String(500), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkerState(Base):
    __tablename__ = "worker_states"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    version: Mapped[str] = mapped_column(String(100), nullable=False, default="unknown")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_successful_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure: Mapped[str | None] = mapped_column(String(500))
    active_jobs: Mapped[int] = mapped_column(Integer, default=0)
    version_metadata: Mapped[dict] = mapped_column(JSON, default=dict)


class ProviderConfiguration(Base):
    __tablename__ = "provider_configurations"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", name="uq_provider_configuration"),
        Index("ix_provider_configuration_org", "organization_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_credentials: Mapped[str | None] = mapped_column(Text)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProviderRuntimeState(Base):
    __tablename__ = "provider_runtime_states"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", name="uq_provider_runtime_state"),
        Index("ix_provider_runtime_state_org", "organization_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    circuit_open_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MalwareSample(Base):
    __tablename__ = "malware_samples"
    __table_args__ = (
        Index("ix_malware_sample_investigation_time", "investigation_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    uploaded_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    quarantine_name: Mapped[str | None] = mapped_column(String(100))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    md5: Mapped[str | None] = mapped_column(String(32))
    sha1: Mapped[str | None] = mapped_column(String(40))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    analysis_type: Mapped[str] = mapped_column(String(20), nullable=False)
    verdict: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown")
    clamav_result: Mapped[dict] = mapped_column(JSON, default=dict)
    yara_matches: Mapped[list] = mapped_column(JSON, default=list)
    intelligence_matches: Mapped[list] = mapped_column(JSON, default=list)
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id", name="uq_detection_rule_org_id"),
        Index("ix_detection_rule_org", "organization_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    source_format: Mapped[str] = mapped_column(String(30), nullable=False, default="sigma")
    level: Mapped[str] = mapped_column(String(20), default="medium")
    logsource: Mapped[dict] = mapped_column(JSON, default=dict)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NetworkDetection(Base):
    __tablename__ = "network_detections"
    __table_args__ = (
        Index("ix_network_detection_investigation_time", "investigation_id", "observed_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    signature: Mapped[str] = mapped_column(String(500), default="")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    src_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dest_ip: Mapped[str | None] = mapped_column(String(45))
    dest_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20), default="")
    correlated_entity_ids: Mapped[list] = mapped_column(JSON, default=list)
    raw_event: Mapped[dict] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceSource(Base):
    __tablename__ = "evidence_sources"
    __table_args__ = (
        Index("ix_evidence_source_investigation_time", "investigation_id", "retrieved_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    job_id: Mapped[str] = mapped_column(ForeignKey("collection_jobs.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("authorizations.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_version: Mapped[str] = mapped_column(String(100), default="unknown", nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(100), default="unknown", nullable=False)
    query: Mapped[str] = mapped_column(String(2048), nullable=False)
    raw_response_hash: Mapped[str | None] = mapped_column(String(64))
    redacted_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    redaction_policy: Mapped[str] = mapped_column(String(80), default="default-v1")
    previous_integrity_hash: Mapped[str | None] = mapped_column(String(64))
    integrity_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    retain_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ClaimObservation(Base):
    __tablename__ = "claim_observations"
    __table_args__ = (
        UniqueConstraint("source_id", "entity_id", "relationship_id", name="uq_claim_observation"),
        Index("ix_claim_observation_source", "source_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    source_id: Mapped[str] = mapped_column(ForeignKey("evidence_sources.id"), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id"))
    relationship_id: Mapped[str | None] = mapped_column(ForeignKey("relationships.id"))
    claim_class: Mapped[str] = mapped_column(String(40), default="OBSERVED_FACT")
    confidence: Mapped[int] = mapped_column(Integer, default=100)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("investigation_id", "entity_type", "canonical_value"),
        Index("ix_entity_investigation", "investigation_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    canonical_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=100)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Relationship(Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "subject_entity_id",
            "predicate",
            "object_entity_id",
            "provider",
            name="uq_relationship_claim",
        ),
        Index("ix_relationship_investigation", "investigation_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    subject_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), nullable=False)
    predicate: Mapped[str] = mapped_column(String(80), nullable=False)
    object_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), nullable=False)
    claim_class: Mapped[str] = mapped_column(String(40), default="OBSERVED_FACT")
    confidence: Mapped[int] = mapped_column(Integer, default=100)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ThreatIntelObject(Base):
    __tablename__ = "threat_intel_objects"
    __table_args__ = (
        UniqueConstraint("organization_id", "stix_id", name="uq_threat_intel_org_stix"),
        Index("ix_threat_intel_org_type", "organization_id", "object_type"),
        Index("ix_threat_intel_expiration", "revoked", "valid_until"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    stix_id: Mapped[str] = mapped_column(String(200), nullable=False)
    object_type: Mapped[str] = mapped_column(String(60), nullable=False)
    name: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    pattern: Mapped[str] = mapped_column(Text, default="", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source: Mapped[str] = mapped_column(String(100), default="stix_bundle", nullable=False)
    external_references: Mapped[list] = mapped_column(JSON, default=list)
    labels: Mapped[list] = mapped_column(JSON, default=list)
    raw_object: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "source_id",
            "rule_id",
            "asset_value",
            name="uq_finding_evidence_rule_asset",
        ),
        Index("ix_finding_investigation_status", "investigation_id", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    source_id: Mapped[str] = mapped_column(ForeignKey("evidence_sources.id"), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id"))
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    asset_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_job_id: Mapped[str | None] = mapped_column(String(36))
    verification_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    clean_observations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    remediation_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_state: Mapped[str] = mapped_column(String(30), default="not_verified")
    direct_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_history: Mapped[list] = mapped_column(JSON, default=list)
    corroborating_providers: Mapped[list] = mapped_column(JSON, default=list)
    exception_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    exception_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_accepted_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    risk_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    monitoring_interval_minutes: Mapped[int | None] = mapped_column(Integer)
    next_monitor_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MonitorSchedule(Base):
    __tablename__ = "monitor_schedules"
    __table_args__ = (
        UniqueConstraint("target_id", "provider", name="uq_monitor_target_provider"),
        Index("ix_monitor_due", "enabled", "next_run_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_job_id: Mapped[str | None] = mapped_column(ForeignKey("collection_jobs.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationPreference(Base):
    __tablename__ = "notification_preferences"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_notification_preference_org"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    email_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_to: Mapped[str] = mapped_column(String(320), default="", nullable=False)
    webhook_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    webhook_url: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    encrypted_webhook_secret: Mapped[str | None] = mapped_column(Text)
    quiet_start_hour: Mapped[int | None] = mapped_column(Integer)
    quiet_end_hour: Mapped[int | None] = mapped_column(Integer)
    maintenance_starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    maintenance_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dedupe_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertNotification(Base):
    __tablename__ = "alert_notifications"
    __table_args__ = (
        Index("ix_alert_notification_org_time", "organization_id", "created_at"),
        Index("ix_alert_notification_dedupe", "organization_id", "dedupe_key"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id"))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"))
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(500), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    external_suppressed_reason: Mapped[str] = mapped_column(String(100), default="")
    email_status: Mapped[str] = mapped_column(String(30), default="pending")
    webhook_status: Mapped[str] = mapped_column(String(30), default="pending")
    delivery_error: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceChange(Base):
    __tablename__ = "evidence_changes"
    __table_args__ = (
        Index("ix_evidence_change_investigation_time", "investigation_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    previous_source_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_sources.id"), nullable=False
    )
    current_source_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_sources.id"), nullable=False
    )
    change_type: Mapped[str] = mapped_column(String(50), default="evidence_changed")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisSnapshot(Base):
    __tablename__ = "analysis_snapshots"
    __table_args__ = (Index("ix_analysis_investigation_time", "investigation_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    generated_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False)
    claims: Mapped[list] = mapped_column(JSON, default=list)
    correlations: Mapped[list] = mapped_column(JSON, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    engine_version: Mapped[str] = mapped_column(String(50), default="deterministic-v1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NarrativeSnapshot(Base):
    __tablename__ = "narrative_snapshots"
    __table_args__ = (Index("ix_narrative_analysis_time", "analysis_snapshot_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    analysis_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_snapshots.id"), nullable=False
    )
    generated_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False)
    technical_summary: Mapped[str] = mapped_column(Text, nullable=False)
    key_points: Mapped[list] = mapped_column(JSON, default=list)
    classification: Mapped[str] = mapped_column(String(50), default="AI_GENERATED_SUMMARY")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    __table_args__ = (Index("ix_report_schedule_due", "enabled", "next_run_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    style: Mapped[str] = mapped_column(String(20), default="technical", nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=10080, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    __table_args__ = (Index("ix_report_artifact_investigation", "investigation_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    schedule_id: Mapped[str | None] = mapped_column(ForeignKey("report_schedules.id"))
    generated_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    style: Mapped[str] = mapped_column(String(20), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FederationPeer(Base):
    __tablename__ = "federation_peers"
    __table_args__ = (
        UniqueConstraint("organization_id", "node_id", name="uq_federation_peer_org_node"),
        Index("ix_federation_peer_org_status", "organization_id", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    node_id: Mapped[str] = mapped_column(String(96), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(96), nullable=False)
    protocol_version: Mapped[str] = mapped_column(String(30), default="cypheryn-federation-v1")
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    enrolled_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FederatedAssertion(Base):
    __tablename__ = "federated_assertions"
    __table_args__ = (
        UniqueConstraint("organization_id", "assertion_id", name="uq_federated_assertion"),
        Index("ix_federated_assertion_subject", "organization_id", "subject_fingerprint"),
        Index("ix_federated_assertion_issuer", "organization_id", "issuer_node_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(96), nullable=False)
    issuer_node_id: Mapped[str] = mapped_column(String(96), nullable=False)
    issuer_key_id: Mapped[str] = mapped_column(String(96), nullable=False)
    assertion_type: Mapped[str] = mapped_column(String(60), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(60), nullable=False)
    subject_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    assertion: Mapped[dict] = mapped_column(JSON, nullable=False)
    verification_status: Mapped[str] = mapped_column(String(30), nullable=False)
    trust_state: Mapped[str] = mapped_column(String(20), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FederationReplayNonce(Base):
    __tablename__ = "federation_replay_nonces"
    __table_args__ = (
        UniqueConstraint("issuer_node_id", "nonce", name="uq_federation_issuer_nonce"),
        Index("ix_federation_nonce_expiry", "expires_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    issuer_node_id: Mapped[str] = mapped_column(String(96), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(96), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FederationRateWindow(Base):
    __tablename__ = "federation_rate_windows"
    __table_args__ = (
        UniqueConstraint("organization_id", "issuer_node_id", name="uq_federation_rate_issuer"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    issuer_node_id: Mapped[str] = mapped_column(String(96), nullable=False)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
