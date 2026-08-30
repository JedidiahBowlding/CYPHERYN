from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import InvestigationStatus, JobStatus, TargetType


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)


class OrganizationRead(ApiModel):
    id: str
    name: str
    created_at: datetime


class ReportBrandingUpdate(BaseModel):
    report_title: str = Field(default="CYPHERYN", min_length=1, max_length=200)
    report_accent: str = Field(default="#147d72", pattern=r"^#[0-9a-fA-F]{6}$")
    logo_data_url: str | None = Field(default=None, max_length=750000)


class ReportBrandingRead(BaseModel):
    report_title: str
    report_accent: str
    logo_configured: bool


class InvestigationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)


class InvestigationRead(ApiModel):
    id: str
    organization_id: str
    owner_id: str
    name: str
    description: str
    status: InvestigationStatus
    created_at: datetime


class StixBundleImport(BaseModel):
    bundle: dict
    source: str = Field(default="stix_bundle", min_length=2, max_length=100)
    default_ttl_days: int = Field(default=90, ge=1, le=3650)


class StixImportResult(BaseModel):
    imported: int
    updated: int
    active_indicators: int
    expired_indicators: int
    correlations: int
    object_types: dict[str, int]


class ThreatIntelObjectRead(ApiModel):
    id: str
    organization_id: str
    stix_id: str
    object_type: str
    name: str
    description: str
    pattern: str
    confidence: int
    valid_from: datetime | None
    valid_until: datetime | None
    revoked: bool
    source: str
    external_references: list
    labels: list
    created_at: datetime
    modified_at: datetime
    imported_at: datetime


class MalwareHashRequest(BaseModel):
    sha256: str = Field(pattern="^[a-fA-F0-9]{64}$")
    filename: str = Field(default="hash-only", min_length=1, max_length=255)
    authorization_confirmed: bool


class MalwareSampleRead(ApiModel):
    id: str
    investigation_id: str
    original_filename: str
    size_bytes: int | None
    md5: str | None
    sha1: str | None
    sha256: str
    analysis_type: str
    verdict: str
    clamav_result: dict
    yara_matches: list
    intelligence_matches: list
    authorized_at: datetime
    created_at: datetime


class IdentityReviewRequest(BaseModel):
    status: str = Field(pattern="^(unreviewed|confirmed|false_positive)$")
    evidence_note: str = Field(default="", max_length=5000)

    @model_validator(mode="after")
    def require_supporting_evidence(self) -> "IdentityReviewRequest":
        if self.status in {"confirmed", "false_positive"} and not self.evidence_note.strip():
            raise ValueError("A supporting evidence note is required")
        return self


class SigmaRuleImport(BaseModel):
    content: str = Field(min_length=20, max_length=500_000)


class DetectionRuleRead(ApiModel):
    id: str
    organization_id: str
    rule_id: str
    title: str
    source_format: str
    level: str
    logsource: dict
    tags: list
    enabled: bool
    created_at: datetime
    updated_at: datetime


class NetworkDetectionRead(ApiModel):
    id: str
    investigation_id: str
    source: str
    event_type: str
    signature: str
    severity: str
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    protocol: str
    correlated_entity_ids: list
    raw_event: dict
    observed_at: datetime
    created_at: datetime


class NetworkIngestResult(BaseModel):
    source: str
    imported: int
    correlated: int
    skipped: int


class AuthorizationCreate(BaseModel):
    basis: str = Field(min_length=5, max_length=5000)
    passive_allowed: bool = True
    active_allowed: bool = False
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def dates_are_ordered(self) -> "AuthorizationCreate":
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class AuthorizationRead(ApiModel):
    id: str
    organization_id: str
    authorizer_id: str
    basis: str
    passive_allowed: bool
    active_allowed: bool
    valid_from: datetime
    valid_until: datetime
    revoked_at: datetime | None


class TargetCreate(BaseModel):
    authorization_id: str
    target_type: TargetType
    value: str = Field(min_length=1, max_length=2048)
    include_descendants: bool = False


class TargetAuthorizationUpdate(BaseModel):
    authorization_id: str


class TargetRead(ApiModel):
    id: str
    investigation_id: str
    authorization_id: str
    target_type: TargetType
    raw_value: str
    canonical_value: str
    include_descendants: bool
    created_at: datetime


class CollectionJobRead(ApiModel):
    id: str
    correlation_id: str
    investigation_id: str
    target_id: str
    requested_by_id: str | None
    provider: str
    profile: str
    status: JobStatus
    result_count: int
    attempt: int
    max_attempts: int
    lease_owner: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    cancellation_requested_at: datetime | None
    error_summary: str | None
    created_at: datetime
    started_at: datetime | None
    ended_at: datetime | None


class CollectionRequest(BaseModel):
    provider: str = Field(default="safe_mock", min_length=2, max_length=100)
    target_id: str | None = None
    active_attack_approved: bool = False


class CollectionJobEventRead(ApiModel):
    id: str
    job_id: str
    event_type: str
    from_status: str | None
    to_status: str
    message: str
    details: dict
    occurred_at: datetime


class ProviderControlSettings(BaseModel):
    kill_switch: bool = False
    jobs_per_hour: int = Field(default=60, ge=1, le=10000)
    timeout_seconds: int = Field(default=20, ge=1, le=300)
    failure_threshold: int = Field(default=3, ge=1, le=20)
    cooldown_seconds: int = Field(default=300, ge=1, le=86400)
    collection_url: str | None = None
    default_ttl_days: int = Field(default=90, ge=1, le=3650)
    minimum_confidence: int = Field(default=70, ge=50, le=95)
    top_sites: int = Field(default=50, ge=10, le=500)


class ProviderConfigurationUpsert(BaseModel):
    enabled: bool = False
    credentials: dict[str, str] | None = None
    settings: ProviderControlSettings = Field(default_factory=ProviderControlSettings)


class ProviderConfigurationRead(BaseModel):
    id: str
    organization_id: str
    provider: str
    enabled: bool
    credentials_configured: bool
    settings: dict
    updated_at: datetime


class ProviderDescriptor(BaseModel):
    name: str
    target_types: list[str]
    passive_only: bool
    requires_credentials: bool
    available: bool = True
    version: str | None = None
    tier: str
    contract_tested: bool


class ProviderRuntimeRead(BaseModel):
    provider: str
    enabled: bool
    kill_switch: bool
    jobs_per_hour: int
    timeout_seconds: int
    failure_threshold: int
    cooldown_seconds: int
    consecutive_failures: int
    circuit_open_until: datetime | None
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_error: str | None


class EvidenceSourceRead(ApiModel):
    id: str
    investigation_id: str
    job_id: str
    target_id: str
    authorization_id: str
    provider: str
    provider_version: str
    ruleset_version: str
    query: str
    raw_response_hash: str | None
    redacted_payload: dict
    redaction_policy: str
    previous_integrity_hash: str | None
    integrity_hash: str | None
    retrieved_at: datetime
    retain_until: datetime


class ClaimObservationRead(ApiModel):
    id: str
    investigation_id: str
    source_id: str
    entity_id: str | None
    relationship_id: str | None
    claim_class: str
    confidence: int
    observed_at: datetime


class EntityRead(ApiModel):
    id: str
    investigation_id: str
    entity_type: str
    canonical_value: str
    confidence: int
    provider: str
    attributes: dict
    observed_at: datetime


class RelationshipRead(ApiModel):
    id: str
    investigation_id: str
    subject_entity_id: str
    predicate: str
    object_entity_id: str
    claim_class: str
    confidence: int
    provider: str
    created_at: datetime


class FindingRead(ApiModel):
    id: str
    investigation_id: str
    source_id: str
    entity_id: str | None
    rule_id: str
    title: str
    description: str
    severity: str
    status: str
    confidence: int
    asset_value: str
    provider: str
    evidence_observed_at: datetime | None
    verification_job_id: str | None
    verification_requested_at: datetime | None
    last_verified_at: datetime | None
    resolved_at: datetime | None
    clean_observations: int
    remediation_notes: str
    owner: str
    due_at: datetime | None
    verification_state: str
    direct_observed_at: datetime | None
    provider_observed_at: datetime | None
    verification_history: list[dict]
    corroborating_providers: list[str]
    exception_reason: str
    exception_expires_at: datetime | None
    risk_accepted_by_id: str | None
    risk_accepted_at: datetime | None
    monitoring_enabled: bool
    monitoring_interval_minutes: int | None
    next_monitor_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FindingStatusUpdate(BaseModel):
    status: str | None = Field(
        default=None,
        pattern="^(open|acknowledged|verifying|resolved|dismissed|risk_accepted|false_positive)$",
    )
    remediation_notes: str | None = Field(default=None, max_length=5000)
    owner: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    exception_reason: str | None = Field(default=None, max_length=5000)
    exception_expires_at: datetime | None = None
    monitoring_enabled: bool | None = None
    monitoring_interval_minutes: int | None = Field(default=None, ge=5, le=525600)

    @model_validator(mode="after")
    def contains_update(self) -> "FindingStatusUpdate":
        if not any(
            value is not None
            for value in (
                self.status,
                self.remediation_notes,
                self.owner,
                self.due_at,
                self.exception_reason,
                self.exception_expires_at,
                self.monitoring_enabled,
                self.monitoring_interval_minutes,
            )
        ):
            raise ValueError("At least one finding field must be updated")
        if self.status in {"risk_accepted", "false_positive"} and not (
            self.exception_reason and self.exception_reason.strip()
        ):
            raise ValueError("An exception reason is required")
        if self.status == "risk_accepted" and self.exception_expires_at is None:
            raise ValueError("Risk acceptance requires an expiration date")
        return self


class NotificationPreferenceUpsert(BaseModel):
    email_enabled: bool = False
    email_to: str = Field(default="", max_length=320)
    webhook_enabled: bool = False
    webhook_url: str = Field(default="", max_length=1000)
    webhook_secret: str | None = Field(default=None, max_length=500)
    quiet_start_hour: int | None = Field(default=None, ge=0, le=23)
    quiet_end_hour: int | None = Field(default=None, ge=0, le=23)
    maintenance_starts_at: datetime | None = None
    maintenance_ends_at: datetime | None = None
    dedupe_minutes: int = Field(default=60, ge=1, le=10080)

    @model_validator(mode="after")
    def validate_delivery(self) -> "NotificationPreferenceUpsert":
        if self.email_enabled and "@" not in self.email_to:
            raise ValueError("A notification email address is required")
        if self.webhook_enabled and not self.webhook_url:
            raise ValueError("A webhook URL is required")
        if (self.quiet_start_hour is None) != (self.quiet_end_hour is None):
            raise ValueError("Both quiet-period hours are required")
        if self.maintenance_starts_at and self.maintenance_ends_at:
            if self.maintenance_ends_at <= self.maintenance_starts_at:
                raise ValueError("Maintenance end must follow its start")
        return self


class NotificationPreferenceRead(ApiModel):
    organization_id: str
    email_enabled: bool
    email_to: str
    webhook_enabled: bool
    webhook_url: str
    webhook_secret_configured: bool
    quiet_start_hour: int | None
    quiet_end_hour: int | None
    maintenance_starts_at: datetime | None
    maintenance_ends_at: datetime | None
    dedupe_minutes: int
    updated_at: datetime


class AlertNotificationRead(ApiModel):
    id: str
    organization_id: str
    investigation_id: str | None
    finding_id: str | None
    event_type: str
    severity: str
    title: str
    message: str
    occurrence_count: int
    last_seen_at: datetime
    read_at: datetime | None
    external_suppressed_reason: str
    email_status: str
    webhook_status: str
    delivery_error: str
    created_at: datetime


class MonitorScheduleCreate(BaseModel):
    target_id: str
    provider: str = Field(min_length=2, max_length=100)
    interval_minutes: int = Field(default=1440, ge=5, le=525600)
    enabled: bool = True


class MonitorScheduleUpdate(BaseModel):
    interval_minutes: int | None = Field(default=None, ge=5, le=525600)
    enabled: bool | None = None


class MonitorScheduleRead(ApiModel):
    id: str
    investigation_id: str
    target_id: str
    provider: str
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_job_id: str | None
    created_at: datetime
    updated_at: datetime


class EvidenceChangeRead(ApiModel):
    id: str
    investigation_id: str
    target_id: str
    provider: str
    previous_source_id: str
    current_source_id: str
    change_type: str
    severity: str
    summary: str
    details: dict
    acknowledged_at: datetime | None
    created_at: datetime


class AnalysisSnapshotRead(ApiModel):
    id: str
    investigation_id: str
    generated_by_id: str
    risk_score: int
    risk_level: str
    title: str
    executive_summary: str
    claims: list
    correlations: list
    recommendations: list
    metrics: dict
    engine_version: str
    created_at: datetime


class NarrativeSnapshotRead(ApiModel):
    id: str
    investigation_id: str
    analysis_snapshot_id: str
    generated_by_id: str
    model: str
    executive_summary: str
    technical_summary: str
    key_points: list
    classification: str
    created_at: datetime


class ReportScheduleCreate(BaseModel):
    style: str = Field(default="technical", pattern="^(executive|technical)$")
    interval_minutes: int = Field(default=10080, ge=60, le=525600)
    enabled: bool = True


class ReportScheduleRead(ApiModel):
    id: str
    investigation_id: str
    created_by_id: str
    style: str
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime


class ReportArtifactRead(ApiModel):
    id: str
    investigation_id: str
    schedule_id: str | None
    generated_by_id: str
    style: str
    filename: str
    media_type: str
    sha256: str
    created_at: datetime


class InvestigationWorkspace(BaseModel):
    investigation: InvestigationRead
    targets: list[TargetRead]
    jobs: list[CollectionJobRead]
    job_events: list[CollectionJobEventRead]
    evidence_sources: list[EvidenceSourceRead]
    claim_observations: list[ClaimObservationRead]
    entities: list[EntityRead]
    relationships: list[RelationshipRead]
    monitor_schedules: list[MonitorScheduleRead]
    evidence_changes: list[EvidenceChangeRead]
    analysis_snapshots: list[AnalysisSnapshotRead]
    narrative_snapshots: list[NarrativeSnapshotRead]
