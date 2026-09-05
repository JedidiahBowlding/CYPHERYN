import base64
import binascii
import ipaddress
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .analysis import build_analysis
from .audit import record_audit
from .auth import Principal, get_current_user, get_principal, membership_for, require_writer
from .config import get_settings
from .database import Base, engine, get_db
from .detection_engine import export_suricata, ingest_network_events, parse_sigma
from .federation_api import router as federation_router
from .integrity import verify_audit_event, verify_evidence_source
from .integrity_anchor import latest_anchor_metadata
from .job_events import append_job_event
from .legal import CURRENT_AGREEMENTS, current_acceptance
from .local_ai import LocalNarrativeError, generate_local_narrative
from .malware_analysis import correlate_hashes, quarantine_file, scan_clamav, scan_yara
from .models import (
    AlertNotification,
    AnalysisSnapshot,
    AuditEvent,
    Authorization,
    ClaimObservation,
    CollectionJob,
    CollectionJobEvent,
    DetectionRule,
    Entity,
    EvidenceChange,
    EvidenceSource,
    Finding,
    Investigation,
    JobStatus,
    LegalAcceptance,
    MalwareSample,
    Membership,
    MembershipRole,
    MonitorSchedule,
    NarrativeSnapshot,
    NetworkDetection,
    NotificationPreference,
    Organization,
    ProviderConfiguration,
    ProviderRuntimeState,
    Relationship,
    ReportArtifact,
    ReportSchedule,
    Target,
    TargetType,
    ThreatIntelObject,
    User,
)
from .normalization import canonicalize_target
from .notifications import emit_notification, validate_webhook_url
from .observability import (
    correlation_id,
    correlation_id_context,
    operational_snapshot,
    prometheus_metrics,
    structured_log,
)
from .provider_certification import contract_tested, provider_tier, verification_freshness
from .provider_contract import registry
from .provider_safety import ProviderBlockedError, controls_for, enforce_enqueue
from .provider_secrets import ProviderSecretError, encrypt_credentials
from .providers import register_builtin_providers
from .report_exports import (
    findings_csv,
    json_export,
    sha256,
    stix_export,
    timeline_csv,
    timeline_records,
)
from .reporting import build_pdf_report
from .schemas import (
    AlertNotificationRead,
    AnalysisSnapshotRead,
    AuthorizationCreate,
    AuthorizationRead,
    CollectionJobRead,
    CollectionRequest,
    DetectionRuleRead,
    EntityRead,
    EvidenceChangeRead,
    FindingRead,
    FindingStatusUpdate,
    IdentityReviewRequest,
    InvestigationCreate,
    InvestigationRead,
    InvestigationWorkspace,
    LegalAcceptanceCreate,
    LegalAcceptanceStatus,
    MalwareHashRequest,
    MalwareSampleRead,
    MonitorScheduleCreate,
    MonitorScheduleRead,
    MonitorScheduleUpdate,
    NarrativeSnapshotRead,
    NetworkDetectionRead,
    NetworkIngestResult,
    NotificationPreferenceRead,
    NotificationPreferenceUpsert,
    OrganizationCreate,
    OrganizationRead,
    ProviderConfigurationRead,
    ProviderConfigurationUpsert,
    ProviderDescriptor,
    ProviderRuntimeRead,
    PublicPlatformStats,
    ReportArtifactRead,
    ReportBrandingRead,
    ReportBrandingUpdate,
    ReportScheduleCreate,
    ReportScheduleRead,
    SigmaRuleImport,
    StixBundleImport,
    StixImportResult,
    TargetAuthorizationUpdate,
    TargetCreate,
    TargetRead,
    ThreatIntelObjectRead,
)
from .stix_ingest import import_stix_bundle

register_builtin_providers(registry)


def provider_version_label(provider) -> str:
    declared = getattr(type(provider), "version", None)
    if isinstance(declared, str) and declared:
        return declared
    return (
        "installed; exact version captured with evidence"
        if getattr(provider, "available", True)
        else "not installed"
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    from .schema_upgrade import upgrade_existing_schema

    upgrade_existing_schema()
    yield


app = FastAPI(
    title="CYPHERYN API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
app.include_router(federation_router)


@app.get("/api/public/stats", response_model=PublicPlatformStats)
def public_platform_stats(db: Session = Depends(get_db)) -> PublicPlatformStats:
    """Return a deliberately narrow aggregate with no account attributes."""
    registered_users = db.scalar(select(func.count(User.id))) or 0
    return PublicPlatformStats(registered_users=registered_users)


@app.get("/api/v1/legal/status", response_model=LegalAcceptanceStatus)
def legal_status(
    principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> LegalAcceptanceStatus:
    user = db.scalar(select(User).where(User.external_subject == principal.subject))
    acceptance = current_acceptance(db, user.id) if user else None
    return LegalAcceptanceStatus(
        required=acceptance is None,
        accepted=acceptance is not None,
        terms_version=CURRENT_AGREEMENTS.terms_version,
        responsible_use_version=CURRENT_AGREEMENTS.responsible_use_version,
        effective_date=CURRENT_AGREEMENTS.effective_date.isoformat(),
        last_updated=CURRENT_AGREEMENTS.last_updated.isoformat(),
        accepted_at=acceptance.accepted_at if acceptance else None,
    )


@app.post("/api/v1/legal/acceptance", response_model=LegalAcceptanceStatus)
def accept_legal_agreements(
    payload: LegalAcceptanceCreate,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> LegalAcceptanceStatus:
    if not payload.accepted:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Affirmative acceptance is required"
        )
    if (
        payload.terms_version != CURRENT_AGREEMENTS.terms_version
        or payload.responsible_use_version != CURRENT_AGREEMENTS.responsible_use_version
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Agreement versions changed; review and accept the current agreements",
        )
    user = db.scalar(select(User).where(User.external_subject == principal.subject))
    if user is None:
        user = User(external_subject=principal.subject, email=principal.email)
        db.add(user)
        db.flush()
    acceptance = current_acceptance(db, user.id)
    if acceptance is None:
        acceptance = LegalAcceptance(
            user_id=user.id,
            terms_version=CURRENT_AGREEMENTS.terms_version,
            responsible_use_version=CURRENT_AGREEMENTS.responsible_use_version,
        )
        db.add(acceptance)
        db.commit()
        db.refresh(acceptance)
    return LegalAcceptanceStatus(
        required=False,
        accepted=True,
        terms_version=CURRENT_AGREEMENTS.terms_version,
        responsible_use_version=CURRENT_AGREEMENTS.responsible_use_version,
        effective_date=CURRENT_AGREEMENTS.effective_date.isoformat(),
        last_updated=CURRENT_AGREEMENTS.last_updated.isoformat(),
        accepted_at=acceptance.accepted_at,
    )

settings = get_settings()
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-Dev-Subject",
            "X-Dev-Email",
            "X-Correlation-ID",
        ],
        expose_headers=[
            "Content-Disposition",
            "Digest",
            "X-Content-SHA256",
            "X-Correlation-ID",
        ],
    )


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    request_correlation_id = correlation_id(request.headers.get("X-Correlation-ID"))
    token = correlation_id_context.set(request_correlation_id)
    started = datetime.now(UTC)
    try:
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = request_correlation_id
        structured_log(
            "http.request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round((datetime.now(UTC) - started).total_seconds() * 1000, 3),
        )
        return response
    finally:
        correlation_id_context.reset(token)


@app.get("/health/live", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"])
def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(select(1))
    return {"status": "ready"}


@app.get("/health/workers", tags=["health"])
def worker_health(db: Session = Depends(get_db)) -> dict:
    snapshot = operational_snapshot(db)
    return {
        "status": "healthy" if snapshot["worker_healthy"] else "degraded",
        "worker_healthy": snapshot["worker_healthy"],
        "workers": snapshot["workers"],
        "queue": snapshot["queue"],
    }


@app.get("/metrics", include_in_schema=False)
def metrics(db: Session = Depends(get_db)) -> Response:
    return Response(
        prometheus_metrics(operational_snapshot(db)),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.post("/api/v1/organizations", response_model=OrganizationRead, status_code=201)
def create_organization(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Organization:
    organization = Organization(name=payload.name)
    db.add(organization)
    db.flush()
    db.add(
        Membership(
            organization_id=organization.id,
            user_id=user.id,
            role=MembershipRole.ORGANIZATION_ADMIN,
        )
    )
    record_audit(
        db,
        organization_id=organization.id,
        actor_id=user.id,
        action="organization.create",
        object_type="organization",
        object_id=organization.id,
    )
    db.commit()
    db.refresh(organization)
    return organization


@app.get("/api/v1/organizations", response_model=list[OrganizationRead])
def list_organizations(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[Organization]:
    return list(
        db.scalars(
            select(Organization)
            .join(Membership)
            .where(Membership.user_id == user.id)
            .order_by(Organization.created_at)
        )
    )


@app.post(
    "/api/v1/organizations/{organization_id}/investigations",
    response_model=InvestigationRead,
    status_code=201,
)
def create_investigation(
    organization_id: str,
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Investigation:
    require_writer(db, user.id, organization_id)
    investigation = Investigation(
        organization_id=organization_id,
        owner_id=user.id,
        name=payload.name,
        description=payload.description,
    )
    db.add(investigation)
    db.flush()
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action="investigation.create",
        object_type="investigation",
        object_id=investigation.id,
    )
    db.commit()
    db.refresh(investigation)
    return investigation


@app.get(
    "/api/v1/organizations/{organization_id}/investigations",
    response_model=list[InvestigationRead],
)
def list_investigations(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    membership_for(db, user.id, organization_id)
    latest_scan = (
        select(
            CollectionJob.investigation_id,
            func.max(CollectionJob.ended_at).label("last_scanned_at"),
        )
        .where(CollectionJob.status == JobStatus.COMPLETED)
        .group_by(CollectionJob.investigation_id)
        .subquery()
    )
    rows = db.execute(
        select(Investigation, latest_scan.c.last_scanned_at)
        .outerjoin(latest_scan, latest_scan.c.investigation_id == Investigation.id)
        .where(Investigation.organization_id == organization_id)
        .order_by(
            latest_scan.c.last_scanned_at.desc().nullslast(),
            Investigation.created_at.desc(),
        )
    )
    return [
        {
            "id": investigation.id,
            "organization_id": investigation.organization_id,
            "owner_id": investigation.owner_id,
            "name": investigation.name,
            "description": investigation.description,
            "status": investigation.status,
            "created_at": investigation.created_at,
            "last_scanned_at": last_scanned_at,
        }
        for investigation, last_scanned_at in rows
    ]


@app.post(
    "/api/v1/investigations/{investigation_id}/stix/import",
    response_model=StixImportResult,
)
def import_stix(
    investigation_id: str,
    payload: StixBundleImport,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    try:
        result = import_stix_bundle(
            db,
            investigation,
            payload.bundle,
            source=payload.source,
            default_ttl_days=payload.default_ttl_days,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="threat_intelligence.stix_import",
        object_type="investigation",
        object_id=investigation.id,
    )
    db.commit()
    return result


@app.get(
    "/api/v1/organizations/{organization_id}/threat-intelligence",
    response_model=list[ThreatIntelObjectRead],
)
def list_threat_intelligence(
    organization_id: str,
    active_only: bool = True,
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ThreatIntelObject]:
    membership_for(db, user.id, organization_id)
    query = select(ThreatIntelObject).where(ThreatIntelObject.organization_id == organization_id)
    if active_only:
        query = query.where(
            ThreatIntelObject.revoked.is_(False),
            or_(
                ThreatIntelObject.valid_until.is_(None),
                ThreatIntelObject.valid_until > datetime.now(UTC),
            ),
        )
    return list(db.scalars(query.order_by(ThreatIntelObject.modified_at.desc()).limit(limit)))


@app.patch("/api/v1/entities/{entity_id}/identity-review", response_model=EntityRead)
def review_identity_candidate(
    entity_id: str,
    payload: IdentityReviewRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Entity:
    entity = db.get(Entity, entity_id)
    investigation = db.get(Investigation, entity.investigation_id) if entity else None
    if entity is None or investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    if entity.entity_type not in {"identity_profile", "breach_exposure"}:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Entity is not reviewable identity evidence",
        )
    entity.attributes = {
        **(entity.attributes or {}),
        "review_status": payload.status,
        "review_evidence_note": payload.evidence_note.strip(),
        "reviewed_at": datetime.now(UTC).isoformat(),
        "reviewed_by_id": user.id,
    }
    candidate_relationships = list(
        db.scalars(
            select(Relationship).where(
                Relationship.investigation_id == investigation.id,
                Relationship.object_entity_id == entity.id,
                Relationship.predicate == "CANDIDATE_MATCH",
            )
        )
    )
    if payload.status == "false_positive":
        entity.confidence = 0
        for relationship in candidate_relationships:
            relationship.confidence = 0
            relationship.claim_class = "FALSE_POSITIVE"
    elif payload.status == "confirmed":
        for relationship in candidate_relationships:
            relationship.claim_class = "CORROBORATED_IDENTITY"
        organization_entity = db.scalar(
            select(Entity).where(
                Entity.investigation_id == investigation.id,
                Entity.entity_type == "organization",
            )
        )
        if organization_entity is not None:
            affiliation = db.scalar(
                select(Relationship).where(
                    Relationship.investigation_id == investigation.id,
                    Relationship.subject_entity_id == entity.id,
                    Relationship.predicate == "verified_affiliation",
                    Relationship.object_entity_id == organization_entity.id,
                )
            )
            if affiliation is None:
                db.add(
                    Relationship(
                        investigation_id=investigation.id,
                        subject_entity_id=entity.id,
                        predicate="verified_affiliation",
                        object_entity_id=organization_entity.id,
                        claim_class="ANALYST_CORROBORATED",
                        confidence=entity.confidence,
                        provider="analyst_review",
                    )
                )
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action=f"identity.review.{payload.status}",
        object_type="entity",
        object_id=entity.id,
    )
    db.commit()
    db.refresh(entity)
    return entity


@app.get(
    "/api/v1/investigations/{investigation_id}/malware/samples",
    response_model=list[MalwareSampleRead],
)
def list_malware_samples(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[MalwareSample]:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return list(
        db.scalars(
            select(MalwareSample)
            .where(MalwareSample.investigation_id == investigation_id)
            .order_by(MalwareSample.created_at.desc())
        )
    )


@app.post(
    "/api/v1/investigations/{investigation_id}/malware/hashes",
    response_model=MalwareSampleRead,
    status_code=201,
)
def analyze_malware_hash(
    investigation_id: str,
    payload: MalwareHashRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MalwareSample:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    if not payload.authorization_confirmed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Authorization confirmation required"
        )
    sha256 = payload.sha256.lower()
    matches = correlate_hashes(db, investigation.organization_id, [sha256])
    sample = MalwareSample(
        investigation_id=investigation_id,
        uploaded_by_id=user.id,
        original_filename=payload.filename,
        sha256=sha256,
        analysis_type="hash",
        verdict="malicious" if matches else "unknown",
        intelligence_matches=matches,
    )
    db.add(sample)
    db.flush()
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="malware.hash_analyze",
        object_type="malware_sample",
        object_id=sample.id,
    )
    db.commit()
    db.refresh(sample)
    return sample


@app.post(
    "/api/v1/investigations/{investigation_id}/malware/samples",
    response_model=MalwareSampleRead,
    status_code=201,
)
async def analyze_malware_sample(
    investigation_id: str,
    request: Request,
    filename: str = Query(default="sample.bin", min_length=1, max_length=255),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MalwareSample:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    if request.headers.get("X-Analysis-Authorization") != "confirmed":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Authorization confirmation required"
        )
    content_length = int(request.headers.get("content-length") or 0)
    if content_length > settings.malware_max_upload_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Sample exceeds 25 MiB limit")
    data = await request.body()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Sample is empty")
    if len(data) > settings.malware_max_upload_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Sample exceeds 25 MiB limit")
    safe_filename = Path(filename).name[:255] or "sample.bin"
    path, digests = quarantine_file(data, settings.quarantine_dir)
    clamav = scan_clamav(path, settings.clamav_database_dir)
    rules_path = Path(__file__).resolve().parents[2] / "rules" / "cypheryn.yar"
    yara_matches = scan_yara(path, rules_path)
    intel_matches = correlate_hashes(db, investigation.organization_id, list(digests.values()))
    verdict = (
        "malicious"
        if clamav.get("status") == "infected" or intel_matches
        else "suspicious"
        if yara_matches
        else "clean"
        if clamav.get("status") == "clean"
        else "unknown"
    )
    sample = MalwareSample(
        investigation_id=investigation_id,
        uploaded_by_id=user.id,
        original_filename=safe_filename,
        quarantine_name=path.name,
        size_bytes=len(data),
        md5=digests["md5"],
        sha1=digests["sha1"],
        sha256=digests["sha256"],
        analysis_type="file",
        verdict=verdict,
        clamav_result=clamav,
        yara_matches=yara_matches,
        intelligence_matches=intel_matches,
    )
    db.add(sample)
    db.flush()
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="malware.sample_analyze",
        object_type="malware_sample",
        object_id=sample.id,
    )
    db.commit()
    db.refresh(sample)
    return sample


@app.get(
    "/api/v1/organizations/{organization_id}/detection-rules",
    response_model=list[DetectionRuleRead],
)
def list_detection_rules(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[DetectionRule]:
    membership_for(db, user.id, organization_id)
    return list(
        db.scalars(
            select(DetectionRule)
            .where(DetectionRule.organization_id == organization_id)
            .order_by(DetectionRule.updated_at.desc())
        )
    )


@app.post(
    "/api/v1/organizations/{organization_id}/detection-rules/sigma",
    response_model=DetectionRuleRead,
    status_code=201,
)
def import_sigma_rule(
    organization_id: str,
    payload: SigmaRuleImport,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DetectionRule:
    require_writer(db, user.id, organization_id)
    try:
        parsed = parse_sigma(payload.content)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    rule = db.scalar(
        select(DetectionRule).where(
            DetectionRule.organization_id == organization_id,
            DetectionRule.rule_id == parsed["rule_id"],
        )
    )
    if rule is None:
        rule = DetectionRule(
            organization_id=organization_id,
            rule_id=parsed["rule_id"],
            title=parsed["title"],
            content=payload.content,
        )
        db.add(rule)
    rule.title = parsed["title"]
    rule.level = parsed["level"]
    rule.logsource = parsed["logsource"]
    rule.tags = parsed["tags"]
    rule.content = payload.content
    rule.updated_at = datetime.now(UTC)
    db.flush()
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action="detection_rule.sigma_import",
        object_type="detection_rule",
        object_id=rule.id,
    )
    db.commit()
    db.refresh(rule)
    return rule


@app.get("/api/v1/organizations/{organization_id}/detection-rules/sigma/export")
def export_sigma_rules(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    membership_for(db, user.id, organization_id)
    rules = db.scalars(
        select(DetectionRule).where(
            DetectionRule.organization_id == organization_id,
            DetectionRule.source_format == "sigma",
            DetectionRule.enabled.is_(True),
        )
    )
    content = "\n---\n".join(rule.content.rstrip() for rule in rules) + "\n"
    return Response(
        content,
        media_type="application/yaml",
        headers={"Content-Disposition": 'attachment; filename="cypheryn-sigma-rules.yml"'},
    )


@app.get("/api/v1/organizations/{organization_id}/detection-rules/suricata/export")
def export_suricata_rules(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    membership_for(db, user.id, organization_id)
    return Response(
        export_suricata(db, organization_id),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="cypheryn-stix.rules"'},
    )


@app.get(
    "/api/v1/investigations/{investigation_id}/network-detections",
    response_model=list[NetworkDetectionRead],
)
def list_network_detections(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[NetworkDetection]:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return list(
        db.scalars(
            select(NetworkDetection)
            .where(NetworkDetection.investigation_id == investigation_id)
            .order_by(NetworkDetection.observed_at.desc())
            .limit(5000)
        )
    )


@app.post(
    "/api/v1/investigations/{investigation_id}/network-detections/{source}",
    response_model=NetworkIngestResult,
)
async def ingest_network_detection_log(
    investigation_id: str,
    source: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    if source not in {"suricata", "zeek"}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unsupported network detection source")
    if request.headers.get("X-Analysis-Authorization") != "confirmed":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Authorization confirmation required"
        )
    if int(request.headers.get("content-length") or 0) > 10 * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Log exceeds 10 MiB limit")
    data = await request.body()
    if not data or len(data) > 10 * 1024 * 1024:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A JSON-lines log is required")
    result = ingest_network_events(db, investigation, source, data)
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action=f"network_detection.{source}_import",
        object_type="investigation",
        object_id=investigation.id,
    )
    db.commit()
    return result


def _notification_preference_payload(preference: NotificationPreference) -> dict:
    return {
        "organization_id": preference.organization_id,
        "email_enabled": preference.email_enabled,
        "email_to": preference.email_to,
        "webhook_enabled": preference.webhook_enabled,
        "webhook_url": preference.webhook_url,
        "webhook_secret_configured": bool(preference.encrypted_webhook_secret),
        "quiet_start_hour": preference.quiet_start_hour,
        "quiet_end_hour": preference.quiet_end_hour,
        "maintenance_starts_at": preference.maintenance_starts_at,
        "maintenance_ends_at": preference.maintenance_ends_at,
        "dedupe_minutes": preference.dedupe_minutes,
        "updated_at": preference.updated_at,
    }


@app.get(
    "/api/v1/organizations/{organization_id}/notification-preferences",
    response_model=NotificationPreferenceRead,
)
def get_notification_preferences(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership_for(db, user.id, organization_id)
    preference = db.scalar(
        select(NotificationPreference).where(
            NotificationPreference.organization_id == organization_id
        )
    )
    if preference is None:
        preference = NotificationPreference(organization_id=organization_id)
        db.add(preference)
        db.commit()
        db.refresh(preference)
    return _notification_preference_payload(preference)


@app.put(
    "/api/v1/organizations/{organization_id}/notification-preferences",
    response_model=NotificationPreferenceRead,
)
def update_notification_preferences(
    organization_id: str,
    payload: NotificationPreferenceUpsert,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership = require_writer(db, user.id, organization_id)
    if membership.role != MembershipRole.ORGANIZATION_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin approval required")
    webhook_url = payload.webhook_url.strip()
    if payload.webhook_enabled:
        try:
            webhook_url = validate_webhook_url(webhook_url)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    preference = db.scalar(
        select(NotificationPreference).where(
            NotificationPreference.organization_id == organization_id
        )
    )
    if preference is None:
        preference = NotificationPreference(organization_id=organization_id)
        db.add(preference)
    preference.email_enabled = payload.email_enabled
    preference.email_to = payload.email_to.strip()
    preference.webhook_enabled = payload.webhook_enabled
    preference.webhook_url = webhook_url
    preference.quiet_start_hour = payload.quiet_start_hour
    preference.quiet_end_hour = payload.quiet_end_hour
    preference.maintenance_starts_at = payload.maintenance_starts_at
    preference.maintenance_ends_at = payload.maintenance_ends_at
    preference.dedupe_minutes = payload.dedupe_minutes
    preference.updated_at = datetime.now(UTC)
    if payload.webhook_secret is not None:
        if not settings.provider_encryption_key:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Provider encryption key is not configured",
            )
        preference.encrypted_webhook_secret = encrypt_credentials(
            {"secret": payload.webhook_secret}, settings.provider_encryption_key
        )
    db.flush()
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action="notifications.preferences.update",
        object_type="notification_preference",
        object_id=preference.id,
    )
    db.commit()
    db.refresh(preference)
    return _notification_preference_payload(preference)


@app.get(
    "/api/v1/organizations/{organization_id}/notifications",
    response_model=list[AlertNotificationRead],
)
def list_notifications(
    organization_id: str,
    unread_only: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[AlertNotification]:
    membership_for(db, user.id, organization_id)
    query = select(AlertNotification).where(AlertNotification.organization_id == organization_id)
    if unread_only:
        query = query.where(AlertNotification.read_at.is_(None))
    return list(db.scalars(query.order_by(AlertNotification.last_seen_at.desc()).limit(limit)))


@app.patch("/api/v1/notifications/{notification_id}/read", response_model=AlertNotificationRead)
def mark_notification_read(
    notification_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AlertNotification:
    notification = db.get(AlertNotification, notification_id)
    if notification is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, notification.organization_id)
    notification.read_at = datetime.now(UTC)
    db.commit()
    db.refresh(notification)
    return notification


@app.get(
    "/api/v1/organizations/{organization_id}/findings",
    response_model=list[FindingRead],
)
def list_findings(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[Finding]:
    membership_for(db, user.id, organization_id)
    return list(
        db.scalars(
            select(Finding)
            .join(Investigation)
            .where(Investigation.organization_id == organization_id)
            .order_by(Finding.created_at.desc())
        )
    )


@app.patch("/api/v1/findings/{finding_id}", response_model=FindingRead)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Finding:
    finding = db.get(Finding, finding_id)
    investigation = db.get(Investigation, finding.investigation_id) if finding else None
    if finding is None or investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    previous_status = finding.status
    if payload.status is not None:
        finding.status = payload.status
        if payload.status == "resolved":
            finding.resolved_at = datetime.now(UTC)
        elif payload.status in {"open", "verifying"}:
            finding.resolved_at = None
        if payload.status in {"risk_accepted", "false_positive"}:
            finding.risk_accepted_by_id = user.id
            finding.risk_accepted_at = datetime.now(UTC)
        elif payload.status == "open":
            finding.risk_accepted_by_id = None
            finding.risk_accepted_at = None
            finding.exception_reason = ""
            finding.exception_expires_at = None
    if payload.remediation_notes is not None:
        finding.remediation_notes = payload.remediation_notes
    if payload.owner is not None:
        finding.owner = payload.owner
    if payload.due_at is not None:
        finding.due_at = payload.due_at
    if payload.exception_reason is not None:
        finding.exception_reason = payload.exception_reason.strip()
    if payload.exception_expires_at is not None:
        finding.exception_expires_at = payload.exception_expires_at
    if payload.monitoring_interval_minutes is not None:
        finding.monitoring_interval_minutes = payload.monitoring_interval_minutes
        if finding.monitoring_enabled:
            finding.next_monitor_at = datetime.now(UTC) + timedelta(
                minutes=payload.monitoring_interval_minutes
            )
    if payload.monitoring_enabled is not None:
        finding.monitoring_enabled = payload.monitoring_enabled
        if payload.monitoring_enabled:
            interval = finding.monitoring_interval_minutes or 1440
            finding.monitoring_interval_minutes = interval
            finding.next_monitor_at = datetime.now(UTC) + timedelta(minutes=interval)
        else:
            finding.next_monitor_at = None
    finding.updated_at = datetime.now(UTC)
    if finding.status != previous_status:
        event_type = (
            "finding.resolved"
            if finding.status == "resolved"
            else "finding.reopened"
            if previous_status == "resolved" and finding.status == "open"
            else "finding.changed"
        )
        emit_notification(
            db,
            organization_id=investigation.organization_id,
            investigation_id=investigation.id,
            finding_id=finding.id,
            event_type=event_type,
            severity=finding.severity,
            title=f"Finding {event_type.rsplit('.', 1)[-1]}: {finding.title}",
            message=f"Finding status changed from {previous_status} to {finding.status}.",
            dedupe_key=f"{event_type}:{finding.id}:{finding.status}",
        )
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action=f"finding.{payload.status or 'updated'}",
        object_type="finding",
        object_id=finding.id,
    )
    db.commit()
    db.refresh(finding)
    return finding


@app.get("/api/v1/findings/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Finding:
    finding = db.get(Finding, finding_id)
    investigation = db.get(Investigation, finding.investigation_id) if finding else None
    if finding is None or investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return finding


@app.post(
    "/api/v1/findings/{finding_id}/verify",
    response_model=CollectionJobRead,
    status_code=202,
)
def request_finding_verification(
    finding_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionJob:
    finding = db.get(Finding, finding_id)
    investigation = db.get(Investigation, finding.investigation_id) if finding else None
    source = db.get(EvidenceSource, finding.source_id) if finding else None
    target = db.get(Target, source.target_id) if source else None
    if finding is None or investigation is None or source is None or target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    try:
        provider = registry.get("direct_verifier")
        enforce_enqueue(db, investigation, provider.name)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Provider unavailable") from exc
    except ProviderBlockedError as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
    direct_target = target
    service_match = re.fullmatch(r"(\[[^]]+\]|[^:]+):(\d+)/(tcp|udp)", finding.asset_value)
    if service_match:
        address = service_match.group(1).strip("[]")
        try:
            canonical_address = str(ipaddress.ip_address(address))
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "The finding does not contain a directly verifiable IP service",
            ) from exc
        direct_target = db.scalar(
            select(Target).where(
                Target.investigation_id == investigation.id,
                Target.target_type == TargetType.IP_ADDRESS,
                Target.canonical_value == canonical_address,
            )
        )
        if direct_target is None:
            direct_target = Target(
                investigation_id=investigation.id,
                authorization_id=target.authorization_id,
                target_type=TargetType.IP_ADDRESS,
                raw_value=canonical_address,
                canonical_value=canonical_address,
            )
            db.add(direct_target)
            db.flush()
    authorization = db.get(Authorization, direct_target.authorization_id)
    now = datetime.now(UTC)
    valid_until = authorization.valid_until if authorization else now
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=UTC)
    if (
        authorization is None
        or not authorization.active_allowed
        or authorization.revoked_at is not None
        or valid_until <= now
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Explicit, unexpired active authorization is required for direct verification",
        )
    job = CollectionJob(
        correlation_id=correlation_id_context.get() or correlation_id(),
        investigation_id=investigation.id,
        target_id=direct_target.id,
        requested_by_id=user.id,
        provider=provider.name,
        profile="passive" if provider.capabilities.passive_only else "active",
        status=JobStatus.QUEUED,
        # A vulnerability scan is one durable remote operation. Retrying it
        # twenty times can create duplicate Greenbone tasks and hide a stuck
        # cancellation; the provider resumes its deterministic task instead.
        max_attempts=3,
    )
    db.add(job)
    db.flush()
    append_job_event(
        db,
        job,
        "verification_queued",
        JobStatus.QUEUED,
        message=f"Independent direct verification requested for {finding.asset_value}",
        details={
            "finding_id": finding.id,
            "rule_id": finding.rule_id,
            "origin_provider": finding.provider,
        },
    )
    if finding.status != "verifying":
        finding.clean_observations = 0
    finding.status = "verifying"
    finding.verification_state = "queued"
    finding.verification_job_id = job.id
    finding.verification_requested_at = datetime.now(UTC)
    finding.updated_at = datetime.now(UTC)
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="finding.verification_requested",
        object_type="finding",
        object_id=finding.id,
    )
    db.commit()
    db.refresh(job)
    return job


@app.post(
    "/api/v1/organizations/{organization_id}/authorizations",
    response_model=AuthorizationRead,
    status_code=201,
)
def create_authorization(
    organization_id: str,
    payload: AuthorizationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Authorization:
    membership = require_writer(db, user.id, organization_id)
    if payload.active_allowed and membership.role != MembershipRole.ORGANIZATION_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin approval required for active scope")
    authorization = Authorization(
        organization_id=organization_id,
        authorizer_id=user.id,
        **payload.model_dump(exclude={"active_scope_confirmed"}),
    )
    db.add(authorization)
    db.flush()
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action="authorization.create",
        object_type="authorization",
        object_id=authorization.id,
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@app.post(
    "/api/v1/investigations/{investigation_id}/targets",
    response_model=TargetRead,
    status_code=201,
)
def add_target(
    investigation_id: str,
    payload: TargetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Target:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    authorization = db.get(Authorization, payload.authorization_id)
    now = datetime.now(UTC)
    valid_from = (
        authorization.valid_from.replace(tzinfo=UTC)
        if authorization and authorization.valid_from.tzinfo is None
        else authorization.valid_from
        if authorization
        else now
    )
    valid_until = (
        authorization.valid_until.replace(tzinfo=UTC)
        if authorization and authorization.valid_until.tzinfo is None
        else authorization.valid_until
        if authorization
        else now
    )
    if (
        authorization is None
        or authorization.organization_id != investigation.organization_id
        or authorization.revoked_at is not None
        or valid_from > now
        or valid_until <= now
        or not authorization.passive_allowed
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Valid passive authorization required"
        )
    target = Target(
        investigation_id=investigation_id,
        authorization_id=authorization.id,
        target_type=payload.target_type,
        raw_value=payload.value,
        canonical_value=canonicalize_target(payload.target_type, payload.value),
        include_descendants=payload.include_descendants,
    )
    db.add(target)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Target already exists") from exc
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="target.create",
        object_type="target",
        object_id=target.id,
    )
    db.commit()
    db.refresh(target)
    return target


@app.get("/api/v1/investigations/{investigation_id}/targets", response_model=list[TargetRead])
def list_targets(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[Target]:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return list(
        db.scalars(
            select(Target)
            .where(Target.investigation_id == investigation_id)
            .order_by(Target.created_at)
        )
    )


@app.put(
    "/api/v1/investigations/{investigation_id}/targets/{target_id}/authorization",
    response_model=TargetRead,
)
def update_target_authorization(
    investigation_id: str,
    target_id: str,
    payload: TargetAuthorizationUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Target:
    investigation = db.get(Investigation, investigation_id)
    target = db.get(Target, target_id)
    if investigation is None or target is None or target.investigation_id != investigation_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership = require_writer(db, user.id, investigation.organization_id)
    if membership.role != MembershipRole.ORGANIZATION_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin approval required")
    authorization = db.get(Authorization, payload.authorization_id)
    now = datetime.now(UTC)
    valid_until = authorization.valid_until if authorization else now
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=UTC)
    if (
        authorization is None
        or authorization.organization_id != investigation.organization_id
        or authorization.revoked_at is not None
        or valid_until <= now
        or not authorization.active_allowed
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Valid active authorization required",
        )
    target.authorization_id = authorization.id
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="target.authorization.update",
        object_type="target",
        object_id=target.id,
    )
    db.commit()
    db.refresh(target)
    return target


@app.get("/api/v1/investigations/{investigation_id}", response_model=InvestigationRead)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Investigation:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return investigation


@app.get(
    "/api/v1/investigations/{investigation_id}/workspace",
    response_model=InvestigationWorkspace,
)
def get_investigation_workspace(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    investigation = get_investigation(investigation_id, db, user)
    return {
        "investigation": investigation,
        "targets": list(
            db.scalars(select(Target).where(Target.investigation_id == investigation_id))
        ),
        "jobs": list(
            db.scalars(
                select(CollectionJob)
                .where(CollectionJob.investigation_id == investigation_id)
                .order_by(CollectionJob.created_at.desc())
            )
        ),
        "job_events": list(
            db.scalars(
                select(CollectionJobEvent)
                .join(CollectionJob)
                .where(CollectionJob.investigation_id == investigation_id)
                .order_by(CollectionJobEvent.occurred_at.desc())
            )
        ),
        "evidence_sources": list(
            db.scalars(
                select(EvidenceSource)
                .where(EvidenceSource.investigation_id == investigation_id)
                .order_by(EvidenceSource.retrieved_at.desc())
            )
        ),
        "claim_observations": list(
            db.scalars(
                select(ClaimObservation)
                .where(ClaimObservation.investigation_id == investigation_id)
                .order_by(ClaimObservation.observed_at.desc())
            )
        ),
        "entities": list(
            db.scalars(select(Entity).where(Entity.investigation_id == investigation_id))
        ),
        "relationships": list(
            db.scalars(
                select(Relationship).where(Relationship.investigation_id == investigation_id)
            )
        ),
        "monitor_schedules": list(
            db.scalars(
                select(MonitorSchedule)
                .where(MonitorSchedule.investigation_id == investigation_id)
                .order_by(MonitorSchedule.created_at.desc())
            )
        ),
        "evidence_changes": list(
            db.scalars(
                select(EvidenceChange)
                .where(EvidenceChange.investigation_id == investigation_id)
                .order_by(EvidenceChange.created_at.desc())
            )
        ),
        "analysis_snapshots": list(
            db.scalars(
                select(AnalysisSnapshot)
                .where(AnalysisSnapshot.investigation_id == investigation_id)
                .order_by(AnalysisSnapshot.created_at.desc())
                .limit(20)
            )
        ),
        "narrative_snapshots": list(
            db.scalars(
                select(NarrativeSnapshot)
                .where(NarrativeSnapshot.investigation_id == investigation_id)
                .order_by(NarrativeSnapshot.created_at.desc())
                .limit(20)
            )
        ),
    }


@app.post(
    "/api/v1/investigations/{investigation_id}/analysis",
    response_model=AnalysisSnapshotRead,
    status_code=201,
)
def generate_analysis_snapshot(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AnalysisSnapshot:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    snapshot = AnalysisSnapshot(
        investigation_id=investigation.id,
        generated_by_id=user.id,
        **build_analysis(db, investigation),
    )
    db.add(snapshot)
    db.flush()
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="analysis.generate",
        object_type="analysis_snapshot",
        object_id=snapshot.id,
    )
    db.commit()
    db.refresh(snapshot)
    return snapshot


@app.post(
    "/api/v1/investigations/{investigation_id}/analysis/local-narrative",
    response_model=NarrativeSnapshotRead,
    status_code=201,
)
def generate_local_ai_narrative(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> NarrativeSnapshot:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    snapshot = db.scalar(
        select(AnalysisSnapshot)
        .where(AnalysisSnapshot.investigation_id == investigation.id)
        .order_by(AnalysisSnapshot.created_at.desc())
    )
    if snapshot is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Generate an analysis snapshot first")
    try:
        narrative = generate_local_narrative(
            snapshot,
            settings.local_ai_url,
            settings.local_ai_model,
            settings.local_ai_timeout_seconds,
        )
    except LocalNarrativeError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    stored = NarrativeSnapshot(
        investigation_id=investigation.id,
        analysis_snapshot_id=snapshot.id,
        generated_by_id=user.id,
        model=settings.local_ai_model,
        **narrative,
    )
    db.add(stored)
    db.flush()
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="analysis.local_narrative.generate",
        object_type="narrative_snapshot",
        object_id=stored.id,
    )
    db.commit()
    db.refresh(stored)
    return stored


@app.get("/api/v1/investigations/{investigation_id}/reports/pdf")
def download_pdf_report(
    investigation_id: str,
    style: str = Query(default="technical", pattern="^(executive|technical)$"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    snapshot = db.scalar(
        select(AnalysisSnapshot)
        .where(AnalysisSnapshot.investigation_id == investigation.id)
        .order_by(AnalysisSnapshot.created_at.desc())
    )
    if snapshot is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Generate an analysis snapshot first")
    targets = list(db.scalars(select(Target).where(Target.investigation_id == investigation.id)))
    findings = list(db.scalars(select(Finding).where(Finding.investigation_id == investigation.id)))
    sources = list(
        db.scalars(
            select(EvidenceSource)
            .where(EvidenceSource.investigation_id == investigation.id)
            .order_by(EvidenceSource.retrieved_at.desc())
        )
    )
    narrative = db.scalar(
        select(NarrativeSnapshot)
        .where(NarrativeSnapshot.analysis_snapshot_id == snapshot.id)
        .order_by(NarrativeSnapshot.created_at.desc())
    )
    organization = db.get(Organization, investigation.organization_id)
    anchor = latest_anchor_metadata(
        Path(get_settings().integrity_anchor_store_dir), investigation.id
    )
    content = build_pdf_report(
        investigation,
        snapshot,
        targets,
        findings,
        sources,
        style,
        narrative,
        brand_name=organization.report_title if organization else "CYPHERYN",
        brand_accent=organization.report_accent if organization else "#147d72",
        brand_logo=organization.report_logo if organization else None,
        integrity_anchor=anchor,
    )
    filename = f"cypheryn-{investigation.id[:8]}-{style}.pdf"
    digest = sha256(content)
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="report.export.pdf",
        object_type="investigation",
        object_id=investigation.id,
        reason_code=f"sha256:{digest[:16]}",
    )
    db.commit()
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Digest": f"sha-256={digest}",
            "X-Content-SHA256": digest,
        },
    )


def _export_records(db: Session, investigation: Investigation) -> dict:
    jobs = select(CollectionJob.id).where(CollectionJob.investigation_id == investigation.id)
    return {
        "targets": list(
            db.scalars(select(Target).where(Target.investigation_id == investigation.id))
        ),
        "findings": list(
            db.scalars(select(Finding).where(Finding.investigation_id == investigation.id))
        ),
        "sources": list(
            db.scalars(
                select(EvidenceSource).where(EvidenceSource.investigation_id == investigation.id)
            )
        ),
        "changes": list(
            db.scalars(
                select(EvidenceChange).where(EvidenceChange.investigation_id == investigation.id)
            )
        ),
        "job_events": list(
            db.scalars(select(CollectionJobEvent).where(CollectionJobEvent.job_id.in_(jobs)))
        ),
        "entities": list(
            db.scalars(select(Entity).where(Entity.investigation_id == investigation.id))
        ),
        "relationships": list(
            db.scalars(
                select(Relationship).where(Relationship.investigation_id == investigation.id)
            )
        ),
    }


@app.get("/api/v1/investigations/{investigation_id}/reports/export")
def download_evidence_export(
    investigation_id: str,
    format: str = Query(pattern="^(json|csv|stix|timeline)$"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    data = _export_records(db, investigation)
    if format == "json":
        content = json_export(
            investigation,
            **data,
            integrity_anchor=latest_anchor_metadata(
                Path(get_settings().integrity_anchor_store_dir), investigation.id
            ),
        )
        media_type, extension = "application/json", "json"
    elif format == "csv":
        content = findings_csv(data["findings"])
        media_type, extension = "text/csv", "csv"
    elif format == "stix":
        content = stix_export(
            investigation, data["findings"], data["entities"], data["relationships"]
        )
        media_type, extension = "application/stix+json", "stix.json"
    else:
        content = timeline_csv(
            timeline_records(data["sources"], data["changes"], data["findings"], data["job_events"])
        )
        media_type, extension = "text/csv", "timeline.csv"
    digest = sha256(content)
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action=f"report.export.{format}",
        object_type="investigation",
        object_id=investigation.id,
        reason_code=f"sha256:{digest[:16]}",
    )
    db.commit()
    filename = f"cypheryn-{investigation.id[:8]}-{extension}"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Digest": f"sha-256={digest}",
            "X-Content-SHA256": digest,
        },
    )


@app.get(
    "/api/v1/organizations/{organization_id}/report-branding",
    response_model=ReportBrandingRead,
)
def get_report_branding(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ReportBrandingRead:
    organization = db.get(Organization, organization_id)
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, organization_id)
    return ReportBrandingRead(
        report_title=organization.report_title,
        report_accent=organization.report_accent,
        logo_configured=bool(organization.report_logo),
    )


@app.put(
    "/api/v1/organizations/{organization_id}/report-branding",
    response_model=ReportBrandingRead,
)
def update_report_branding(
    organization_id: str,
    payload: ReportBrandingUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ReportBrandingRead:
    organization = db.get(Organization, organization_id)
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership = membership_for(db, user.id, organization_id)
    if membership.role != MembershipRole.ORGANIZATION_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Organization admin role required")
    organization.report_title = payload.report_title
    organization.report_accent = payload.report_accent
    if payload.logo_data_url is not None:
        if payload.logo_data_url == "":
            organization.report_logo = None
            organization.report_logo_mime = ""
        else:
            match = re.fullmatch(
                r"data:(image/(?:png|jpeg));base64,([A-Za-z0-9+/=]+)", payload.logo_data_url
            )
            if match is None:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "PNG or JPEG logo required"
                )
            try:
                logo = base64.b64decode(match.group(2), validate=True)
            except binascii.Error as exc:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid logo data"
                ) from exc
            if len(logo) > 500_000:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Logo exceeds 500 KB")
            organization.report_logo = logo
            organization.report_logo_mime = match.group(1)
    db.commit()
    return ReportBrandingRead(
        report_title=organization.report_title,
        report_accent=organization.report_accent,
        logo_configured=bool(organization.report_logo),
    )


@app.get(
    "/api/v1/investigations/{investigation_id}/report-schedules",
    response_model=list[ReportScheduleRead],
)
def list_report_schedules(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ReportSchedule]:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return list(
        db.scalars(
            select(ReportSchedule).where(ReportSchedule.investigation_id == investigation_id)
        )
    )


@app.post(
    "/api/v1/investigations/{investigation_id}/report-schedules",
    response_model=ReportScheduleRead,
    status_code=201,
)
def create_report_schedule(
    investigation_id: str,
    payload: ReportScheduleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ReportSchedule:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    schedule = ReportSchedule(
        investigation_id=investigation.id,
        created_by_id=user.id,
        style=payload.style,
        interval_minutes=payload.interval_minutes,
        enabled=payload.enabled,
        next_run_at=datetime.now(UTC),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


@app.get(
    "/api/v1/investigations/{investigation_id}/report-artifacts",
    response_model=list[ReportArtifactRead],
)
def list_report_artifacts(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ReportArtifact]:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return list(
        db.scalars(
            select(ReportArtifact)
            .where(ReportArtifact.investigation_id == investigation_id)
            .order_by(ReportArtifact.created_at.desc())
        )
    )


@app.get("/api/v1/report-artifacts/{artifact_id}/download")
def download_report_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    artifact = db.get(ReportArtifact, artifact_id)
    investigation = db.get(Investigation, artifact.investigation_id) if artifact else None
    if artifact is None or investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership_for(db, user.id, investigation.organization_id)
    return Response(
        content=artifact.content,
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{artifact.filename}"',
            "Digest": f"sha-256={artifact.sha256}",
            "X-Content-SHA256": artifact.sha256,
        },
    )


@app.post(
    "/api/v1/investigations/{investigation_id}/monitors",
    response_model=MonitorScheduleRead,
    status_code=201,
)
def create_monitor_schedule(
    investigation_id: str,
    payload: MonitorScheduleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MonitorSchedule:
    investigation = db.get(Investigation, investigation_id)
    target = db.get(Target, payload.target_id)
    if investigation is None or target is None or target.investigation_id != investigation_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    try:
        provider = registry.get(payload.provider)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider") from exc
    if target.target_type.value not in provider.capabilities.target_types:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Provider does not support target"
        )
    schedule = db.scalar(
        select(MonitorSchedule).where(
            MonitorSchedule.target_id == target.id,
            MonitorSchedule.provider == provider.name,
        )
    )
    now = datetime.now(UTC)
    if schedule is None:
        schedule = MonitorSchedule(
            investigation_id=investigation_id,
            target_id=target.id,
            provider=provider.name,
            interval_minutes=payload.interval_minutes,
            enabled=payload.enabled,
            next_run_at=now,
        )
        db.add(schedule)
    else:
        schedule.interval_minutes = payload.interval_minutes
        schedule.enabled = payload.enabled
        schedule.next_run_at = now
        schedule.updated_at = now
    db.commit()
    db.refresh(schedule)
    return schedule


@app.patch("/api/v1/monitors/{schedule_id}", response_model=MonitorScheduleRead)
def update_monitor_schedule(
    schedule_id: str,
    payload: MonitorScheduleUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MonitorSchedule:
    schedule = db.get(MonitorSchedule, schedule_id)
    investigation = db.get(Investigation, schedule.investigation_id) if schedule else None
    if schedule is None or investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    if payload.interval_minutes is not None:
        schedule.interval_minutes = payload.interval_minutes
    if payload.enabled is not None:
        schedule.enabled = payload.enabled
    if schedule.enabled:
        schedule.next_run_at = datetime.now(UTC)
    schedule.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(schedule)
    return schedule


@app.post("/api/v1/changes/{change_id}/acknowledge", response_model=EvidenceChangeRead)
def acknowledge_evidence_change(
    change_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EvidenceChange:
    change = db.get(EvidenceChange, change_id)
    investigation = db.get(Investigation, change.investigation_id) if change else None
    if change is None or investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    change.acknowledged_at = datetime.now(UTC)
    db.commit()
    db.refresh(change)
    return change


@app.post(
    "/api/v1/investigations/{investigation_id}/collect",
    response_model=CollectionJobRead,
    status_code=202,
)
def enqueue_collection(
    investigation_id: str,
    payload: CollectionRequest = CollectionRequest(),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionJob:
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    membership = require_writer(db, user.id, investigation.organization_id)
    target = (
        db.get(Target, payload.target_id)
        if payload.target_id
        else db.scalar(
            select(Target)
            .where(Target.investigation_id == investigation_id)
            .order_by(Target.created_at)
        )
    )
    if target is not None and target.investigation_id != investigation_id:
        target = None
    if target is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Add an authorized target first")

    try:
        provider = registry.get(payload.provider)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider") from exc
    if target.target_type.value not in provider.capabilities.target_types:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Provider does not support this target type",
        )
    if not provider.capabilities.passive_only:
        authorization = db.get(Authorization, target.authorization_id)
        now = datetime.now(UTC)
        valid_from = (
            authorization.valid_from.replace(tzinfo=UTC)
            if authorization and authorization.valid_from.tzinfo is None
            else authorization.valid_from
            if authorization
            else now
        )
        valid_until = (
            authorization.valid_until.replace(tzinfo=UTC)
            if authorization and authorization.valid_until.tzinfo is None
            else authorization.valid_until
            if authorization
            else now
        )
        if (
            authorization is None
            or authorization.organization_id != investigation.organization_id
            or not authorization.active_allowed
            or authorization.revoked_at is not None
            or valid_from > now
            or valid_until <= now
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Explicit, current active authorization is required for this provider",
            )
    if provider.name == "zap_active" and (
        not payload.active_attack_approved or membership.role != MembershipRole.ORGANIZATION_ADMIN
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "ZAP active attack requires explicit per-run administrator approval",
        )
    if provider.capabilities.requires_credentials:
        configuration = db.scalar(
            select(ProviderConfiguration).where(
                ProviderConfiguration.organization_id == investigation.organization_id,
                ProviderConfiguration.provider == provider.name,
            )
        )
        if not configuration or not configuration.encrypted_credentials:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Provider credentials are required",
            )
    try:
        enforce_enqueue(db, investigation, provider.name)
    except ProviderBlockedError as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc

    job = CollectionJob(
        correlation_id=correlation_id_context.get() or correlation_id(),
        investigation_id=investigation_id,
        target_id=target.id,
        requested_by_id=user.id,
        provider=provider.name,
        profile=(
            "active_attack"
            if provider.name == "zap_active"
            else "passive"
            if provider.capabilities.passive_only
            else "active"
        ),
        status=JobStatus.QUEUED,
    )
    db.add(job)
    db.flush()
    append_job_event(
        db,
        job,
        "queued",
        JobStatus.QUEUED,
        message=f"{provider.name} {job.profile} collection queued",
        details={"provider": job.provider, "profile": job.profile},
    )
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="collection.queued",
        object_type="collection_job",
        object_id=job.id,
    )
    db.commit()
    db.refresh(job)
    return job


@app.post("/api/v1/jobs/{job_id}/cancel", response_model=CollectionJobRead)
def cancel_collection_job(
    job_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionJob:
    job = db.get(CollectionJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    investigation = db.get(Investigation, job.investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    require_writer(db, user.id, investigation.organization_id)
    if job.status in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}:
        return job
    now = datetime.now(UTC)
    job.cancellation_requested_at = now
    if job.status == JobStatus.QUEUED:
        previous = job.status
        job.status = JobStatus.CANCELLED
        job.ended_at = now
        append_job_event(
            db,
            job,
            "cancelled",
            JobStatus.CANCELLED,
            from_status=previous,
            message="Cancelled before worker claim",
        )
    else:
        append_job_event(
            db,
            job,
            "cancellation_requested",
            JobStatus.RUNNING,
            from_status=JobStatus.RUNNING,
            message="Worker cancellation requested",
        )
    record_audit(
        db,
        organization_id=investigation.organization_id,
        actor_id=user.id,
        action="collection.cancel.requested",
        object_type="collection_job",
        object_id=job.id,
    )
    db.commit()
    db.refresh(job)
    return job


@app.get("/api/v1/providers", response_model=list[ProviderDescriptor])
def list_provider_descriptors() -> list[dict]:
    return [
        {
            "name": provider.name,
            "target_types": sorted(provider.capabilities.target_types),
            "passive_only": provider.capabilities.passive_only,
            "requires_credentials": provider.capabilities.requires_credentials,
            "available": bool(getattr(provider, "available", True)),
            "version": provider_version_label(provider),
            "tier": provider_tier(provider.name).value,
            "contract_tested": contract_tested(provider.name),
        }
        for provider in registry.list()
    ]


@app.get(
    "/api/v1/organizations/{organization_id}/providers",
    response_model=list[ProviderConfigurationRead],
)
def list_provider_configurations(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    membership_for(db, user.id, organization_id)
    configurations = db.scalars(
        select(ProviderConfiguration)
        .where(ProviderConfiguration.organization_id == organization_id)
        .order_by(ProviderConfiguration.provider)
    )
    return [_provider_configuration_payload(item) for item in configurations]


@app.put(
    "/api/v1/organizations/{organization_id}/providers/{provider_name}",
    response_model=ProviderConfigurationRead,
)
def upsert_provider_configuration(
    organization_id: str,
    provider_name: str,
    payload: ProviderConfigurationUpsert,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership = require_writer(db, user.id, organization_id)
    if membership.role != MembershipRole.ORGANIZATION_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin approval required")
    try:
        registry.get(provider_name)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider") from exc
    configuration = db.scalar(
        select(ProviderConfiguration).where(
            ProviderConfiguration.organization_id == organization_id,
            ProviderConfiguration.provider == provider_name,
        )
    )
    if configuration is None:
        configuration = ProviderConfiguration(
            organization_id=organization_id,
            provider=provider_name,
        )
        db.add(configuration)
    configuration.enabled = payload.enabled
    configuration.settings = payload.settings.model_dump()
    configuration.updated_at = datetime.now(UTC)
    if payload.credentials is not None:
        if not settings.provider_encryption_key:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Provider encryption key is not configured",
            )
        try:
            configuration.encrypted_credentials = encrypt_credentials(
                payload.credentials, settings.provider_encryption_key
            )
        except ProviderSecretError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Provider encryption key is invalid",
            ) from exc
        runtime = db.scalar(
            select(ProviderRuntimeState).where(
                ProviderRuntimeState.organization_id == organization_id,
                ProviderRuntimeState.provider == provider_name,
            )
        )
        if runtime is not None:
            runtime.consecutive_failures = 0
            runtime.circuit_open_until = None
            runtime.last_error = None
            runtime.updated_at = datetime.now(UTC)
    db.flush()
    record_audit(
        db,
        organization_id=organization_id,
        actor_id=user.id,
        action="provider.configuration.update",
        object_type="provider_configuration",
        object_id=configuration.id,
    )
    db.commit()
    db.refresh(configuration)
    return _provider_configuration_payload(configuration)


def _provider_configuration_payload(configuration: ProviderConfiguration) -> dict:
    return {
        "id": configuration.id,
        "organization_id": configuration.organization_id,
        "provider": configuration.provider,
        "enabled": configuration.enabled,
        "credentials_configured": bool(configuration.encrypted_credentials),
        "settings": configuration.settings,
        "updated_at": configuration.updated_at,
    }


@app.get(
    "/api/v1/organizations/{organization_id}/providers/{provider_name}/runtime",
    response_model=ProviderRuntimeRead,
)
def get_provider_runtime(
    organization_id: str,
    provider_name: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership_for(db, user.id, organization_id)
    try:
        registry.get(provider_name)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider") from exc
    controls = controls_for(db, organization_id, provider_name)
    runtime = db.scalar(
        select(ProviderRuntimeState).where(
            ProviderRuntimeState.organization_id == organization_id,
            ProviderRuntimeState.provider == provider_name,
        )
    )
    return {
        "provider": provider_name,
        **controls.__dict__,
        "consecutive_failures": runtime.consecutive_failures if runtime else 0,
        "circuit_open_until": runtime.circuit_open_until if runtime else None,
        "last_success_at": runtime.last_success_at if runtime else None,
        "last_failure_at": runtime.last_failure_at if runtime else None,
        "last_error": runtime.last_error if runtime else None,
    }


@app.get("/api/v1/organizations/{organization_id}/platform-assurance")
def get_platform_assurance(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership_for(db, user.id, organization_id)
    configurations = {
        item.provider: item
        for item in db.scalars(
            select(ProviderConfiguration).where(
                ProviderConfiguration.organization_id == organization_id
            )
        )
    }
    provider_status = []
    for provider in registry.list():
        configuration = configurations.get(provider.name)
        installed = bool(getattr(provider, "available", True))
        enabled = (
            configuration.enabled
            if configuration
            else not provider.capabilities.requires_credentials
        )
        credentials_ready = not provider.capabilities.requires_credentials or bool(
            configuration and configuration.encrypted_credentials
        )
        runtime = db.scalar(
            select(ProviderRuntimeState).where(
                ProviderRuntimeState.organization_id == organization_id,
                ProviderRuntimeState.provider == provider.name,
            )
        )
        provider_status.append(
            {
                "provider": provider.name,
                "tier": provider_tier(provider.name).value,
                "contract_tested": contract_tested(provider.name),
                "mode": "passive" if provider.capabilities.passive_only else "active",
                "version": provider_version_label(provider),
                "ready": installed and enabled and credentials_ready,
                "supported": provider_tier(provider.name).value == "supported",
                "installed": installed,
                "configured": enabled and credentials_ready,
                "healthy": bool(
                    installed
                    and enabled
                    and credentials_ready
                    and not (runtime and runtime.circuit_open_until)
                    and (not runtime or runtime.consecutive_failures == 0)
                ),
                "live_verified": bool(
                    runtime
                    and runtime.last_success_at
                    and (
                        not runtime.last_failure_at
                        or runtime.last_success_at >= runtime.last_failure_at
                    )
                ),
                "last_verified_at": runtime.last_success_at if runtime else None,
                "verification_freshness": verification_freshness(
                    runtime.last_success_at if runtime else None
                ),
                "configuration": (
                    "ready"
                    if enabled and credentials_ready
                    else "credentials_required"
                    if not credentials_ready
                    else "disabled"
                ),
                "health": (
                    "circuit_open"
                    if runtime and runtime.circuit_open_until
                    else "healthy"
                    if not runtime or runtime.consecutive_failures == 0
                    else "degraded"
                ),
                "status": (
                    "live_verified"
                    if runtime
                    and runtime.last_success_at
                    and (
                        not runtime.last_failure_at
                        or runtime.last_success_at >= runtime.last_failure_at
                    )
                    else "healthy"
                    if installed
                    and enabled
                    and credentials_ready
                    and not (runtime and runtime.circuit_open_until)
                    and (not runtime or runtime.consecutive_failures == 0)
                    else "configured"
                    if enabled and credentials_ready
                    else "installed"
                    if installed
                    else provider_tier(provider.name).value
                ),
            }
        )
    investigation_ids = select(Investigation.id).where(
        Investigation.organization_id == organization_id
    )
    completed_evidence = (
        select(EvidenceSource.id)
        .join(CollectionJob, CollectionJob.id == EvidenceSource.job_id)
        .where(
            EvidenceSource.investigation_id.in_(investigation_ids),
            CollectionJob.status == JobStatus.COMPLETED,
        )
    )
    evidence_total = db.scalar(select(func.count()).select_from(completed_evidence.subquery())) or 0
    evidence_hashed = (
        db.scalar(
            select(func.count()).select_from(
                completed_evidence.where(
                    EvidenceSource.raw_response_hash.is_not(None),
                ).subquery()
            )
        )
        or 0
    )
    evidence_sealed = (
        db.scalar(
            select(func.count()).select_from(
                completed_evidence.where(
                    EvidenceSource.integrity_hash.is_not(None),
                ).subquery()
            )
        )
        or 0
    )
    audit_count = (
        db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.organization_id == organization_id)
        )
        or 0
    )
    integrity = _organization_integrity_report(db, organization_id)
    return {
        "requirements": [
            {
                "name": "Active authorization",
                "status": "enforced",
                "evidence": "enqueue + execution revalidation",
            },
            {
                "name": "Provider modes",
                "status": "enforced",
                "evidence": "passive/active capability contract",
            },
            {
                "name": "Integration readiness",
                "status": "enforced",
                "evidence": "installation, enablement, credentials, circuit",
            },
            {
                "name": "Credential secrecy",
                "status": "enforced",
                "evidence": "encrypted envelope; boolean-only API status",
            },
            {
                "name": "Evidence redaction",
                "status": "enforced",
                "evidence": "central recursive sanitizer central-default-v2",
            },
            {
                "name": "Evidence integrity",
                "status": "verified" if integrity["valid"] else "attention",
                "evidence": (
                    f"{evidence_sealed}/{evidence_total} completed sources hash-chained; "
                    f"{integrity['broken_records']} broken record(s)"
                ),
            },
            {
                "name": "Durable jobs",
                "status": "enforced",
                "evidence": "leases, retries, cancellation, timeout, event history",
            },
            {
                "name": "Audit history",
                "status": "enforced",
                "evidence": f"{audit_count} organization audit events",
            },
            {
                "name": "Version provenance",
                "status": "enforced",
                "evidence": "provider and ruleset version per evidence source",
            },
            {
                "name": "Evidence hashing",
                "status": "enforced",
                "evidence": f"{evidence_hashed}/{evidence_total} completed evidence sources hashed",
            },
            {
                "name": "Finding normalization",
                "status": "enforced",
                "evidence": "canonical assets + database uniqueness + reconciliation",
            },
            {
                "name": "Grounded AI",
                "status": "enforced",
                "evidence": "unsupported claim references discarded",
            },
            {
                "name": "Provider test coverage",
                "status": "enforced",
                "evidence": f"{len(registry.list())} registered adapters under contract regression",
            },
        ],
        "providers": provider_status,
        "integrity": integrity,
    }


def _organization_integrity_report(db: Session, organization_id: str) -> dict:
    investigation_ids = select(Investigation.id).where(
        Investigation.organization_id == organization_id
    )
    sources = list(
        db.scalars(
            select(EvidenceSource)
            .where(EvidenceSource.investigation_id.in_(investigation_ids))
            .order_by(
                EvidenceSource.investigation_id,
                EvidenceSource.retrieved_at,
                EvidenceSource.id,
            )
        )
    )
    audits = list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.occurred_at, AuditEvent.id)
        )
    )
    broken = 0
    evidence_sealed = 0
    previous_by_investigation: dict[str, str | None] = {}
    for source in sources:
        if not source.integrity_hash:
            continue
        evidence_sealed += 1
        previous = previous_by_investigation.get(source.investigation_id)
        if source.previous_integrity_hash != previous or not verify_evidence_source(source):
            broken += 1
        previous_by_investigation[source.investigation_id] = source.integrity_hash
    audit_sealed = 0
    previous_audit: str | None = None
    for event in audits:
        if not event.integrity_hash:
            continue
        audit_sealed += 1
        if event.previous_integrity_hash != previous_audit or not verify_audit_event(event):
            broken += 1
        previous_audit = event.integrity_hash
    return {
        "valid": broken == 0,
        "broken_records": broken,
        "evidence_records": len(sources),
        "evidence_sealed": evidence_sealed,
        "audit_records": len(audits),
        "audit_sealed": audit_sealed,
    }


@app.get("/api/v1/organizations/{organization_id}/integrity")
def get_organization_integrity(
    organization_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    membership_for(db, user.id, organization_id)
    return _organization_integrity_report(db, organization_id)
