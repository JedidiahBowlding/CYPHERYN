import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .analysis import build_analysis
from .audit import record_audit
from .config import get_settings
from .database import Base, SessionLocal, engine
from .integrity import seal_evidence_source
from .job_events import append_job_event
from .local_ai import LocalNarrativeError, generate_local_narrative
from .models import (
    AlertNotification,
    AnalysisSnapshot,
    Authorization,
    ClaimObservation,
    CollectionJob,
    Entity,
    EvidenceChange,
    EvidenceSource,
    Finding,
    Investigation,
    JobStatus,
    MonitorSchedule,
    NarrativeSnapshot,
    Organization,
    ProviderConfiguration,
    Relationship,
    ReportArtifact,
    ReportSchedule,
    Target,
    TargetType,
)
from .notifications import deliver_pending_notifications, emit_notification
from .provider_contract import ProviderContext, registry
from .provider_safety import (
    ProviderBlockedError,
    enforce_enqueue,
    enforce_execution,
    record_failure,
    record_success,
)
from .provider_secrets import decrypt_credentials
from .providers import register_builtin_providers
from .report_exports import sha256
from .reporting import build_pdf_report
from .schema_upgrade import upgrade_existing_schema
from .security_controls import redact_payload, redact_text

LEASE_SECONDS = 30


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def compare_redacted_payloads(previous: dict, current: dict) -> dict:
    """Return bounded top-level changes without introducing unredacted data."""
    previous = _without_volatile_fields(previous)
    current = _without_volatile_fields(current)
    changed = []
    for key in sorted(set(previous) | set(current)):
        before = previous.get(key)
        after = current.get(key)
        if before == after:
            continue
        changed.append(
            {
                "field": key,
                "before": json.dumps(before, sort_keys=True, default=str)[:500],
                "after": json.dumps(after, sort_keys=True, default=str)[:500],
            }
        )
    return {"changed_fields": changed[:50], "changed_field_count": len(changed)}


def _without_volatile_fields(value):
    """Remove provider timestamps that create noise without changing security posture."""
    if isinstance(value, dict):
        return {
            key: _without_volatile_fields(item)
            for key, item in value.items()
            if key not in {"scan_time", "retrieved_at"}
        }
    if isinstance(value, list):
        return [
            _without_volatile_fields(item)
            for item in value
            if not (isinstance(item, dict) and item.get("action") == "last update of RDAP database")
        ]
    return value


def record_evidence_change(db: Session, source: EvidenceSource) -> EvidenceChange | None:
    previous = db.scalar(
        select(EvidenceSource)
        .where(
            EvidenceSource.investigation_id == source.investigation_id,
            EvidenceSource.target_id == source.target_id,
            EvidenceSource.provider == source.provider,
            EvidenceSource.id != source.id,
            EvidenceSource.raw_response_hash.is_not(None),
        )
        .order_by(EvidenceSource.retrieved_at.desc())
    )
    if previous is None or previous.raw_response_hash == source.raw_response_hash:
        return None
    details = compare_redacted_payloads(
        previous.redacted_payload or {}, source.redacted_payload or {}
    )
    field_count = details["changed_field_count"]
    if field_count == 0:
        return None
    change = EvidenceChange(
        investigation_id=source.investigation_id,
        target_id=source.target_id,
        provider=source.provider,
        previous_source_id=previous.id,
        current_source_id=source.id,
        severity="medium" if field_count >= 3 else "info",
        summary=f"{source.provider} evidence changed in {field_count} field(s)",
        details=details,
    )
    db.add(change)
    return change


def reconcile_findings(
    db: Session,
    source: EvidenceSource,
    candidates: list[dict],
) -> None:
    observed: set[tuple[str, str]] = set()
    for candidate in candidates[:100]:
        rule_id = str(candidate["rule_id"])
        asset_value = str(candidate["asset_value"])[:2048]
        observed.add((rule_id, asset_value))
        entity = db.scalar(
            select(Entity).where(
                Entity.investigation_id == source.investigation_id,
                Entity.canonical_value == candidate.get("entity_value"),
            )
        )
        finding = db.scalar(
            select(Finding)
            .where(
                Finding.investigation_id == source.investigation_id,
                Finding.provider == source.provider,
                Finding.rule_id == rule_id,
                Finding.asset_value == asset_value,
            )
            .order_by(Finding.created_at.desc())
        )
        if finding is None and (
            rule_id.startswith("web.cwe.") or rule_id.startswith("vuln.cve.CVE-")
        ):
            finding = db.scalar(
                select(Finding)
                .where(
                    Finding.investigation_id == source.investigation_id,
                    Finding.rule_id == rule_id,
                    Finding.asset_value == asset_value,
                    Finding.provider.in_(["nuclei", "zap_passive", "zap_active", "openvas"]),
                )
                .order_by(Finding.created_at.desc())
            )
        if finding is None:
            finding = Finding(
                investigation_id=source.investigation_id,
                source_id=source.id,
                entity_id=entity.id if entity else None,
                rule_id=rule_id,
                title=str(candidate["title"])[:300],
                description=str(candidate["description"]),
                severity=str(candidate["severity"]),
                confidence=int(candidate.get("confidence", 80)),
                asset_value=asset_value,
                provider=source.provider,
                evidence_observed_at=source.retrieved_at,
                provider_observed_at=_provider_observed_at(source, asset_value),
            )
            db.add(finding)
            db.flush()
            investigation = db.get(Investigation, source.investigation_id)
            if investigation:
                emit_notification(
                    db,
                    organization_id=investigation.organization_id,
                    investigation_id=investigation.id,
                    finding_id=finding.id,
                    event_type="finding.opened",
                    severity=finding.severity,
                    title=f"Finding opened: {finding.title}",
                    message=f"{finding.asset_value} · {finding.description[:500]}",
                    dedupe_key=f"finding.opened:{finding.id}",
                )
        else:
            previous_status = finding.status
            previous_values = (finding.title, finding.description, finding.severity)
            providers = set(finding.corroborating_providers or [])
            if finding.provider != source.provider:
                providers.add(source.provider)
            finding.corroborating_providers = sorted(providers)
            finding.source_id = source.id
            finding.entity_id = entity.id if entity else finding.entity_id
            finding.title = str(candidate["title"])[:300]
            finding.description = str(candidate["description"])
            finding.severity = str(candidate["severity"])
            finding.confidence = int(candidate.get("confidence", 80))
            exception_expires_at = finding.exception_expires_at
            if exception_expires_at and exception_expires_at.tzinfo is None:
                exception_expires_at = exception_expires_at.replace(tzinfo=UTC)
            exception_active = finding.status == "false_positive" or (
                finding.status == "risk_accepted"
                and exception_expires_at is not None
                and exception_expires_at > now_utc()
            )
            if not exception_active:
                finding.status = "open"
            finding.clean_observations = 0
            finding.resolved_at = None
            finding.evidence_observed_at = source.retrieved_at
            finding.provider_observed_at = _provider_observed_at(source, asset_value)
            if finding.verification_requested_at:
                finding.last_verified_at = source.retrieved_at
            finding.updated_at = now_utc()
            investigation = db.get(Investigation, source.investigation_id)
            if investigation and previous_status == "resolved" and finding.status == "open":
                emit_notification(
                    db,
                    organization_id=investigation.organization_id,
                    investigation_id=investigation.id,
                    finding_id=finding.id,
                    event_type="finding.reopened",
                    severity=finding.severity,
                    title=f"Finding reopened: {finding.title}",
                    message=f"New evidence was observed for {finding.asset_value}.",
                    dedupe_key=f"finding.reopened:{finding.id}",
                )
            elif investigation and previous_values != (
                finding.title,
                finding.description,
                finding.severity,
            ):
                emit_notification(
                    db,
                    organization_id=investigation.organization_id,
                    investigation_id=investigation.id,
                    finding_id=finding.id,
                    event_type="finding.changed",
                    severity=finding.severity,
                    title=f"Finding changed: {finding.title}",
                    message=f"Finding evidence changed for {finding.asset_value}.",
                    dedupe_key=f"finding.changed:{finding.id}:{source.raw_response_hash}",
                )
    active_findings = db.scalars(
        select(Finding)
        .join(EvidenceSource, Finding.source_id == EvidenceSource.id)
        .where(
            Finding.investigation_id == source.investigation_id,
            Finding.provider == source.provider,
            EvidenceSource.target_id == source.target_id,
            Finding.status.in_(["open", "acknowledged", "verifying"]),
        )
    )
    for finding in active_findings:
        if (finding.rule_id, finding.asset_value) not in observed:
            previous_status = finding.status
            finding.clean_observations = (finding.clean_observations or 0) + 1
            finding.last_verified_at = source.retrieved_at
            finding.evidence_observed_at = source.retrieved_at
            if finding.clean_observations >= 2:
                finding.status = "resolved"
                finding.resolved_at = now_utc()
            else:
                finding.status = "verifying"
            finding.updated_at = now_utc()
            if finding.status == "resolved" and previous_status != "resolved":
                investigation = db.get(Investigation, source.investigation_id)
                if investigation:
                    emit_notification(
                        db,
                        organization_id=investigation.organization_id,
                        investigation_id=investigation.id,
                        finding_id=finding.id,
                        event_type="finding.resolved",
                        severity="info",
                        title=f"Finding resolved: {finding.title}",
                        message=f"Two clean observations were recorded for {finding.asset_value}.",
                        dedupe_key=f"finding.resolved:{finding.id}",
                    )


def _provider_observed_at(source: EvidenceSource, asset_value: str) -> datetime:
    payload = source.redacted_payload or {}
    match = re.fullmatch(r"(?:\[[^]]+\]|[^:]+):(\d+)/(tcp|udp)", asset_value)
    if match:
        port, protocol = int(match.group(1)), match.group(2)
        stack = [payload]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if (
                    item.get("port") == port
                    and str(item.get("transport", "")).lower() == protocol
                    and item.get("scan_time")
                ):
                    try:
                        return datetime.fromisoformat(str(item["scan_time"]).replace("Z", "+00:00"))
                    except ValueError:
                        break
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    return source.retrieved_at


def apply_direct_verification(db: Session, job: CollectionJob, payload: dict) -> None:
    finding = db.scalar(select(Finding).where(Finding.verification_job_id == job.id))
    if finding is None:
        return
    previous_status = finding.status
    observed_at = now_utc()
    if payload.get("observed_at"):
        try:
            observed_at = datetime.fromisoformat(str(payload["observed_at"]).replace("Z", "+00:00"))
        except ValueError:
            pass
    finding.direct_observed_at = observed_at
    finding.last_verified_at = observed_at
    if finding.provider_observed_at is None:
        origin_source = db.get(EvidenceSource, finding.source_id)
        if origin_source is not None:
            finding.provider_observed_at = _provider_observed_at(origin_source, finding.asset_value)
    match = re.fullmatch(r"(\[[^]]+\]|[^:]+):(\d+)/(tcp|udp)", finding.asset_value)
    direct_state = "inconclusive"
    if match:
        address = match.group(1).strip("[]")
        port, protocol = int(match.group(2)), match.group(3)
        service = next(
            (
                item
                for item in payload.get("services", [])
                if item.get("address") == address
                and item.get("port") == port
                and item.get("protocol") == protocol
            ),
            None,
        )
        direct_state = str(service.get("state")) if service else "inconclusive"
    if direct_state == "responded":
        classification = "confirmed"
        finding.status = "open"
        finding.clean_observations = 0
        finding.resolved_at = None
    elif direct_state == "refused":
        finding.clean_observations = (finding.clean_observations or 0) + 1
        classification = (
            "fixed" if finding.clean_observations >= 2 else "fixed_pending_confirmation"
        )
        finding.status = "resolved" if finding.clean_observations >= 2 else "verifying"
        if finding.status == "resolved":
            finding.resolved_at = observed_at
    else:
        age = observed_at - _aware(
            finding.provider_observed_at or finding.evidence_observed_at or observed_at
        )
        classification = "stale" if age >= timedelta(hours=24) else "inconclusive"
        finding.status = "verifying"
    finding.verification_state = classification
    history = list(finding.verification_history or [])
    history.append(
        {
            "observed_at": observed_at.isoformat(),
            "classification": classification,
            "direct_state": direct_state,
            "provider": "direct_verifier",
            "job_id": job.id,
        }
    )
    finding.verification_history = history[-50:]
    finding.updated_at = observed_at
    investigation = db.get(Investigation, finding.investigation_id)
    if investigation and finding.status != previous_status:
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
            message=f"Direct verification classified {finding.asset_value} as {classification}.",
            dedupe_key=f"{event_type}:{finding.id}:{classification}",
        )


def enqueue_due_schedules(session_factory=SessionLocal) -> int:
    now = now_utc()
    queued = 0
    with session_factory() as db:
        schedules = list(
            db.scalars(
                select(MonitorSchedule).where(
                    MonitorSchedule.enabled.is_(True),
                    MonitorSchedule.next_run_at <= now,
                )
            )
        )
        for schedule in schedules:
            target = db.get(Target, schedule.target_id)
            investigation = db.get(Investigation, schedule.investigation_id)
            if target is None or investigation is None:
                schedule.enabled = False
                continue
            provider = registry.get(schedule.provider)
            authorization = db.get(Authorization, target.authorization_id)
            if not provider.capabilities.passive_only and (
                authorization is None
                or not authorization.active_allowed
                or authorization.revoked_at is not None
                or _aware(authorization.valid_until) <= now
            ):
                schedule.enabled = False
                continue
            configuration = db.scalar(
                select(ProviderConfiguration).where(
                    ProviderConfiguration.organization_id == investigation.organization_id,
                    ProviderConfiguration.provider == provider.name,
                )
            )
            ready = not provider.capabilities.requires_credentials or bool(
                configuration and configuration.enabled and configuration.encrypted_credentials
            )
            existing = db.scalar(
                select(CollectionJob).where(
                    CollectionJob.target_id == target.id,
                    CollectionJob.provider == provider.name,
                    CollectionJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]),
                )
            )
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            schedule.updated_at = now
            if not ready or existing is not None:
                continue
            try:
                enforce_enqueue(db, investigation, provider.name)
            except ProviderBlockedError:
                continue
            job = CollectionJob(
                investigation_id=investigation.id,
                target_id=target.id,
                requested_by_id=investigation.owner_id,
                provider=provider.name,
                profile="passive" if provider.capabilities.passive_only else "active",
                status=JobStatus.QUEUED,
            )
            db.add(job)
            db.flush()
            append_job_event(
                db,
                job,
                "scheduled",
                JobStatus.QUEUED,
                message=f"Scheduled {provider.name} monitoring run queued",
                details={"schedule_id": schedule.id},
            )
            schedule.last_job_id = job.id
            queued += 1
        db.commit()
    return queued


def enqueue_due_finding_monitors(session_factory=SessionLocal) -> int:
    now = now_utc()
    queued = 0
    with session_factory() as db:
        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.monitoring_enabled.is_(True),
                    Finding.next_monitor_at.is_not(None),
                    Finding.next_monitor_at <= now,
                    Finding.status.not_in(["dismissed", "false_positive", "risk_accepted"]),
                )
            )
        )
        for finding in findings:
            investigation = db.get(Investigation, finding.investigation_id)
            source = db.get(EvidenceSource, finding.source_id)
            target = db.get(Target, source.target_id) if source else None
            interval = max(5, min(finding.monitoring_interval_minutes or 1440, 525600))
            finding.next_monitor_at = now + timedelta(minutes=interval)
            if investigation is None or target is None:
                finding.monitoring_enabled = False
                continue
            service_finding = bool(
                re.fullmatch(r"(\[[^]]+\]|[^:]+):(\d+)/(tcp|udp)", finding.asset_value)
            )
            provider_name = "direct_verifier" if service_finding else finding.provider
            job_target = target
            if service_finding:
                match = re.fullmatch(r"(\[[^]]+\]|[^:]+):(\d+)/(tcp|udp)", finding.asset_value)
                if match is None:
                    continue
                address = match.group(1).strip("[]")
                try:
                    canonical_address = str(ipaddress.ip_address(address))
                except ValueError:
                    finding.monitoring_enabled = False
                    continue
                job_target = db.scalar(
                    select(Target).where(
                        Target.investigation_id == investigation.id,
                        Target.target_type == TargetType.IP_ADDRESS,
                        Target.canonical_value == canonical_address,
                    )
                )
                if job_target is None:
                    job_target = Target(
                        investigation_id=investigation.id,
                        authorization_id=target.authorization_id,
                        target_type=TargetType.IP_ADDRESS,
                        raw_value=canonical_address,
                        canonical_value=canonical_address,
                        include_descendants=False,
                    )
                    db.add(job_target)
                    db.flush()
            try:
                provider = registry.get(provider_name)
            except LookupError:
                continue
            authorization = db.get(Authorization, job_target.authorization_id)
            if not provider.capabilities.passive_only and (
                authorization is None
                or not authorization.active_allowed
                or authorization.revoked_at is not None
                or _aware(authorization.valid_until) <= now
            ):
                emit_notification(
                    db,
                    organization_id=investigation.organization_id,
                    investigation_id=investigation.id,
                    finding_id=finding.id,
                    event_type="monitor.authorization_expired",
                    severity="medium",
                    title="Finding monitor needs renewed authorization",
                    message=f"Monitoring could not run for {finding.asset_value}.",
                    dedupe_key=f"monitor.authorization:{finding.id}",
                )
                continue
            existing = db.scalar(
                select(CollectionJob).where(
                    CollectionJob.investigation_id == investigation.id,
                    CollectionJob.target_id == job_target.id,
                    CollectionJob.provider == provider_name,
                    CollectionJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]),
                )
            )
            if existing:
                continue
            try:
                enforce_enqueue(db, investigation, provider_name)
            except ProviderBlockedError:
                continue
            job = CollectionJob(
                investigation_id=investigation.id,
                target_id=job_target.id,
                requested_by_id=investigation.owner_id,
                provider=provider_name,
                profile="passive" if provider.capabilities.passive_only else "active",
                status=JobStatus.QUEUED,
            )
            db.add(job)
            db.flush()
            append_job_event(
                db,
                job,
                "finding_monitor_scheduled",
                JobStatus.QUEUED,
                message=f"Scheduled verification for finding {finding.id}",
                details={"finding_id": finding.id, "interval_minutes": interval},
            )
            if provider_name == "direct_verifier":
                finding.verification_job_id = job.id
                finding.verification_requested_at = now
                finding.verification_state = "queued"
            queued += 1
        db.commit()
    return queued


def monitor_job_health(session_factory=SessionLocal) -> int:
    now = now_utc()
    emitted = 0
    with session_factory() as db:
        delayed = list(
            db.scalars(
                select(CollectionJob).where(
                    or_(
                        (
                            (CollectionJob.status == JobStatus.QUEUED)
                            & (CollectionJob.created_at < now - timedelta(minutes=15))
                        ),
                        (
                            (CollectionJob.status == JobStatus.RUNNING)
                            & (CollectionJob.lease_expires_at.is_not(None))
                            & (CollectionJob.lease_expires_at < now)
                        ),
                    )
                )
            )
        )
        for job in delayed:
            key = f"job.delayed:{job.id}"
            already = db.scalar(
                select(AlertNotification.id).where(AlertNotification.dedupe_key == key)
            )
            if already:
                continue
            investigation = db.get(Investigation, job.investigation_id)
            if investigation:
                emit_notification(
                    db,
                    organization_id=investigation.organization_id,
                    investigation_id=investigation.id,
                    event_type="job.delayed",
                    severity="medium",
                    title=f"Collection job delayed: {job.provider}",
                    message=f"Job {job.id} has not progressed within the expected window.",
                    dedupe_key=key,
                )
                emitted += 1
        db.commit()
    return emitted


def regenerate_monitoring_summary(
    db: Session, job: CollectionJob, *, generate_ai: bool = True
) -> None:
    scheduled = db.scalar(select(MonitorSchedule.id).where(MonitorSchedule.last_job_id == job.id))
    finding_monitor = db.scalar(select(Finding.id).where(Finding.verification_job_id == job.id))
    if not scheduled and not finding_monitor:
        return
    investigation = db.get(Investigation, job.investigation_id)
    if investigation is None:
        return
    snapshot = AnalysisSnapshot(
        investigation_id=investigation.id,
        generated_by_id=job.requested_by_id or investigation.owner_id,
        **build_analysis(db, investigation),
    )
    db.add(snapshot)
    db.flush()
    if not generate_ai:
        return
    settings = get_settings()
    try:
        narrative = generate_local_narrative(
            snapshot,
            settings.local_ai_url,
            settings.local_ai_model,
            settings.local_ai_timeout_seconds,
        )
    except LocalNarrativeError:
        return
    db.add(
        NarrativeSnapshot(
            investigation_id=investigation.id,
            analysis_snapshot_id=snapshot.id,
            generated_by_id=job.requested_by_id or investigation.owner_id,
            model=settings.local_ai_model,
            **narrative,
        )
    )


def enqueue_discovered_ip_enrichment(
    db: Session,
    investigation: Investigation,
    source_target: Target,
    requested_by_id: str | None,
    discovered_ips: list[str],
) -> int:
    queued = 0
    for address in discovered_ips[:100]:
        target = db.scalar(
            select(Target).where(
                Target.investigation_id == investigation.id,
                Target.target_type == TargetType.IP_ADDRESS,
                Target.canonical_value == address,
            )
        )
        if target is None:
            target = Target(
                investigation_id=investigation.id,
                authorization_id=source_target.authorization_id,
                target_type=TargetType.IP_ADDRESS,
                raw_value=address,
                canonical_value=address,
                include_descendants=False,
            )
            db.add(target)
            db.flush()
        for provider in registry.list():
            if (
                provider.name in {"safe_mock", "local_observer", "dns_discovery"}
                or "ip_address" not in provider.capabilities.target_types
                or not provider.capabilities.passive_only
            ):
                continue
            if provider.name == "censys" and ipaddress.ip_address(address).version != 4:
                continue
            configuration = db.scalar(
                select(ProviderConfiguration).where(
                    ProviderConfiguration.organization_id == investigation.organization_id,
                    ProviderConfiguration.provider == provider.name,
                )
            )
            if provider.capabilities.requires_credentials and (
                not configuration
                or not configuration.enabled
                or not configuration.encrypted_credentials
            ):
                continue
            existing = db.scalar(
                select(CollectionJob).where(
                    CollectionJob.investigation_id == investigation.id,
                    CollectionJob.target_id == target.id,
                    CollectionJob.provider == provider.name,
                )
            )
            if existing is not None:
                continue
            try:
                enforce_enqueue(db, investigation, provider.name)
            except ProviderBlockedError:
                continue
            job = CollectionJob(
                investigation_id=investigation.id,
                target_id=target.id,
                requested_by_id=requested_by_id,
                provider=provider.name,
                profile="passive",
                status=JobStatus.QUEUED,
            )
            db.add(job)
            db.flush()
            append_job_event(
                db,
                job,
                "auto_enrichment_queued",
                JobStatus.QUEUED,
                message=f"{provider.name} queued for DNS-discovered IP {address}",
                details={"source": "dns_discovery", "address": address},
            )
            queued += 1
    return queued


def enqueue_discovered_domain_dns(
    db: Session,
    investigation: Investigation,
    source_target: Target,
    requested_by_id: str | None,
    discovered_domains: list[str],
) -> int:
    if not source_target.include_descendants:
        return 0
    queued = 0
    suffix = f".{source_target.canonical_value}"
    for domain in discovered_domains[:500]:
        if not domain.endswith(suffix):
            continue
        target = db.scalar(
            select(Target).where(
                Target.investigation_id == investigation.id,
                Target.target_type == TargetType.DOMAIN,
                Target.canonical_value == domain,
            )
        )
        if target is None:
            target = Target(
                investigation_id=investigation.id,
                authorization_id=source_target.authorization_id,
                target_type=TargetType.DOMAIN,
                raw_value=domain,
                canonical_value=domain,
                include_descendants=False,
            )
            db.add(target)
            db.flush()
        existing = db.scalar(
            select(CollectionJob).where(
                CollectionJob.investigation_id == investigation.id,
                CollectionJob.target_id == target.id,
                CollectionJob.provider == "dns_discovery",
            )
        )
        if existing is not None:
            continue
        try:
            enforce_enqueue(db, investigation, "dns_discovery")
        except ProviderBlockedError:
            continue
        job = CollectionJob(
            investigation_id=investigation.id,
            target_id=target.id,
            requested_by_id=requested_by_id,
            provider="dns_discovery",
            profile="passive",
            status=JobStatus.QUEUED,
        )
        db.add(job)
        db.flush()
        append_job_event(
            db,
            job,
            "subdomain_dns_queued",
            JobStatus.QUEUED,
            message=f"DNS discovery queued for certificate name {domain}",
            details={"source": "certificate_transparency", "domain": domain},
        )
        queued += 1
    return queued


def now_utc() -> datetime:
    return datetime.now(UTC)


def recover_expired_jobs(db: Session) -> int:
    now = now_utc()
    jobs = list(
        db.scalars(
            select(CollectionJob).where(
                CollectionJob.status == JobStatus.RUNNING,
                or_(
                    CollectionJob.lease_expires_at.is_(None),
                    CollectionJob.lease_expires_at < now,
                ),
            )
        )
    )
    for job in jobs:
        job.lease_owner = None
        job.lease_expires_at = None
        if job.cancellation_requested_at:
            job.status = JobStatus.CANCELLED
            job.ended_at = now
            append_job_event(
                db,
                job,
                "cancelled",
                JobStatus.CANCELLED,
                from_status=JobStatus.RUNNING,
                message="Cancellation completed after lease expiry",
            )
        elif job.attempt >= job.max_attempts:
            job.status = JobStatus.FAILED
            job.error_summary = "Worker lease expired after maximum attempts"
            job.ended_at = now
            append_job_event(
                db,
                job,
                "failed",
                JobStatus.FAILED,
                from_status=JobStatus.RUNNING,
                message=job.error_summary,
            )
        else:
            job.status = JobStatus.QUEUED
            job.error_summary = "Recovered after worker lease expired"
            append_job_event(
                db,
                job,
                "lease_recovered",
                JobStatus.QUEUED,
                from_status=JobStatus.RUNNING,
                message=job.error_summary,
            )
    db.commit()
    return len(jobs)


def claim_next_job(db: Session, worker_id: str) -> CollectionJob | None:
    recover_expired_jobs(db)
    candidate = db.scalar(
        select(CollectionJob)
        .where(CollectionJob.status == JobStatus.QUEUED)
        .order_by(CollectionJob.created_at)
        .limit(1)
    )
    if candidate is None:
        return None
    now = now_utc()
    claimed = db.execute(
        update(CollectionJob)
        .where(
            CollectionJob.id == candidate.id,
            CollectionJob.status == JobStatus.QUEUED,
        )
        .values(
            status=JobStatus.RUNNING,
            attempt=CollectionJob.attempt + 1,
            started_at=now,
            heartbeat_at=now,
            lease_owner=worker_id,
            lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
            error_summary=None,
        )
    )
    db.commit()
    if claimed.rowcount != 1:
        return None
    job = db.get(CollectionJob, candidate.id)
    if job:
        append_job_event(
            db,
            job,
            "claimed",
            JobStatus.RUNNING,
            from_status=JobStatus.QUEUED,
            message=f"Claimed by {worker_id}",
            details={"attempt": job.attempt},
        )
        db.commit()
    return job


def get_or_create_entity(
    db: Session, investigation_id: str, entity_type: str, value: str, confidence: int
) -> Entity:
    entity = db.scalar(
        select(Entity).where(
            Entity.investigation_id == investigation_id,
            Entity.entity_type == entity_type,
            Entity.canonical_value == value,
        )
    )
    if entity is None:
        entity = Entity(
            investigation_id=investigation_id,
            entity_type=entity_type,
            canonical_value=value,
            confidence=confidence,
            provider="safe_mock",
            attributes={"classification": "OBSERVED_FACT", "synthetic": True},
        )
        db.add(entity)
        db.flush()
    return entity


def get_or_create_relationship(
    db: Session,
    investigation_id: str,
    subject_id: str,
    predicate: str,
    object_id: str,
    confidence: int,
) -> Relationship:
    relationship = db.scalar(
        select(Relationship).where(
            Relationship.investigation_id == investigation_id,
            Relationship.subject_entity_id == subject_id,
            Relationship.predicate == predicate,
            Relationship.object_entity_id == object_id,
            Relationship.provider == "safe_mock",
        )
    )
    if relationship is None:
        relationship = Relationship(
            investigation_id=investigation_id,
            subject_entity_id=subject_id,
            predicate=predicate,
            object_entity_id=object_id,
            confidence=confidence,
            provider="safe_mock",
        )
        db.add(relationship)
    return relationship


def execute_safe_mock(db: Session, job: CollectionJob) -> int:
    target = db.get(Target, job.target_id)
    if target is None:
        raise RuntimeError("Authorized target no longer exists")
    root = get_or_create_entity(
        db, job.investigation_id, target.target_type.value, target.canonical_value, 100
    )
    results = [root]
    if target.target_type.value == "domain":
        digest = hashlib.sha256(target.canonical_value.encode()).hexdigest()
        octet = 10 + int(digest[:2], 16) % 200
        host = get_or_create_entity(
            db, job.investigation_id, "subdomain", f"www.{target.canonical_value}", 96
        )
        ip = get_or_create_entity(db, job.investigation_id, "ip_address", f"203.0.113.{octet}", 94)
        certificate = get_or_create_entity(
            db, job.investigation_id, "certificate", f"sha256:{digest[:24]}", 91
        )
        results.extend([host, ip, certificate])
        get_or_create_relationship(db, job.investigation_id, root.id, "HAS_SUBDOMAIN", host.id, 96)
        get_or_create_relationship(db, job.investigation_id, host.id, "RESOLVES_TO", ip.id, 94)
        get_or_create_relationship(
            db, job.investigation_id, host.id, "USES_CERTIFICATE", certificate.id, 91
        )
    return len(results)


def process_one(
    worker_id: str = "test-worker", session_factory=SessionLocal
) -> CollectionJob | None:
    with session_factory() as db:
        job = claim_next_job(db, worker_id)
        if job is None:
            return None
        job_id = job.id
        try:
            db.refresh(job)
            if job.cancellation_requested_at:
                job.status = JobStatus.CANCELLED
                job.ended_at = now_utc()
                append_job_event(
                    db,
                    job,
                    "cancelled",
                    JobStatus.CANCELLED,
                    from_status=JobStatus.RUNNING,
                    message="Cancelled before provider execution",
                )
            else:
                target = db.get(Target, job.target_id)
                if target is None:
                    raise RuntimeError("Authorized target no longer exists")
                provider = registry.get(job.provider)
                if target.target_type.value not in provider.capabilities.target_types:
                    raise RuntimeError("Provider does not support this target type")
                investigation = db.get(Investigation, job.investigation_id)
                if investigation is None:
                    raise RuntimeError("Investigation no longer exists")
                if not provider.capabilities.passive_only:
                    authorization = db.get(Authorization, target.authorization_id)
                    execution_time = now_utc()
                    if (
                        authorization is None
                        or authorization.organization_id != investigation.organization_id
                        or not authorization.active_allowed
                        or authorization.revoked_at is not None
                        or _aware(authorization.valid_from) > execution_time
                        or _aware(authorization.valid_until) <= execution_time
                    ):
                        raise RuntimeError(
                            "Active authorization expired or was revoked before execution"
                        )
                controls = enforce_execution(db, investigation, provider.name)
                credentials = {}
                configuration = db.scalar(
                    select(ProviderConfiguration).where(
                        ProviderConfiguration.organization_id == investigation.organization_id,
                        ProviderConfiguration.provider == provider.name,
                    )
                )
                if provider.capabilities.requires_credentials:
                    if not configuration or not configuration.encrypted_credentials:
                        raise RuntimeError("Provider credentials are required")
                    encryption_key = get_settings().provider_encryption_key
                    if not encryption_key:
                        raise RuntimeError("Provider encryption key is not configured")
                    credentials = decrypt_credentials(
                        configuration.encrypted_credentials, encryption_key
                    )
                retrieved_at = now_utc()
                source = EvidenceSource(
                    investigation_id=job.investigation_id,
                    job_id=job.id,
                    target_id=target.id,
                    authorization_id=target.authorization_id,
                    provider=provider.name,
                    provider_version=str(getattr(provider, "version", None) or "unknown")[:100],
                    ruleset_version="unknown",
                    redaction_policy="central-default-v2",
                    query=target.canonical_value,
                    retrieved_at=retrieved_at,
                    retain_until=retrieved_at + timedelta(days=30),
                )
                db.add(source)
                db.flush()
                # Persist the attempt before an external tool runs. Keeping this write
                # transaction open would block cancellation and UI writes in SQLite.
                db.commit()
                result = provider.collect(
                    ProviderContext(
                        db=db,
                        job=job,
                        target=target,
                        settings=configuration.settings if configuration else {},
                        credentials=credentials,
                        deadline_at=retrieved_at + timedelta(seconds=controls.timeout_seconds),
                    )
                )
                auto_enrichment_jobs = 0
                if provider.name == "dns_discovery":
                    auto_enrichment_jobs = enqueue_discovered_ip_enrichment(
                        db,
                        investigation,
                        target,
                        job.requested_by_id,
                        [str(item) for item in result.metadata.get("discovered_ips", [])],
                    )
                elif provider.name == "certificate_transparency":
                    auto_enrichment_jobs = enqueue_discovered_domain_dns(
                        db,
                        investigation,
                        target,
                        job.requested_by_id,
                        [str(item) for item in result.metadata.get("discovered_domains", [])],
                    )
                elif provider.name == "subfinder":
                    auto_enrichment_jobs = enqueue_discovered_domain_dns(
                        db,
                        investigation,
                        target,
                        job.requested_by_id,
                        [str(item) for item in result.metadata.get("discovered_domains", [])],
                    )
                if now_utc() > retrieved_at + timedelta(seconds=controls.timeout_seconds):
                    raise TimeoutError(
                        f"Provider exceeded {controls.timeout_seconds} second timeout"
                    )
                job.result_count = result.result_count
                redacted_payload = redact_payload(
                    result.redacted_payload
                    or {
                        "provider": provider.name,
                        "result_count": result.result_count,
                        **result.metadata,
                    }
                )
                source.ruleset_version = str(
                    result.metadata.get("ruleset_version")
                    or result.metadata.get("engine_version")
                    or getattr(provider, "ruleset_version", None)
                    or "provider-native"
                )[:100]
                canonical_payload = json.dumps(
                    redacted_payload, separators=(",", ":"), sort_keys=True
                ).encode()
                source.redacted_payload = redacted_payload
                fingerprint = (result.response_fingerprint or "").lower()
                source.raw_response_hash = (
                    fingerprint
                    if re.fullmatch(r"[0-9a-f]{64}", fingerprint)
                    else hashlib.sha256(canonical_payload).hexdigest()
                )
                seal_evidence_source(db, source)
                record_evidence_change(db, source)
                reconcile_findings(db, source, list(result.metadata.get("finding_candidates", [])))
                if provider.name == "direct_verifier":
                    apply_direct_verification(
                        db, job, dict(result.metadata.get("direct_verification", {}))
                    )
                for entity_id in result.entity_ids:
                    entity = db.get(Entity, entity_id)
                    if entity:
                        db.add(
                            ClaimObservation(
                                investigation_id=job.investigation_id,
                                source_id=source.id,
                                entity_id=entity.id,
                                claim_class=str(
                                    entity.attributes.get("classification", "OBSERVED_FACT")
                                ),
                                confidence=entity.confidence,
                                observed_at=retrieved_at,
                            )
                        )
                for relationship_id in result.relationship_ids:
                    relationship = db.get(Relationship, relationship_id)
                    if relationship:
                        db.add(
                            ClaimObservation(
                                investigation_id=job.investigation_id,
                                source_id=source.id,
                                relationship_id=relationship.id,
                                claim_class=relationship.claim_class,
                                confidence=relationship.confidence,
                                observed_at=retrieved_at,
                            )
                        )
                db.flush()
                db.refresh(job)
                if job.cancellation_requested_at:
                    job.status = JobStatus.CANCELLED
                    append_job_event(
                        db,
                        job,
                        "cancelled",
                        JobStatus.CANCELLED,
                        from_status=JobStatus.RUNNING,
                        message="Cancelled after provider execution",
                    )
                else:
                    job.status = JobStatus.COMPLETED
                    append_job_event(
                        db,
                        job,
                        "completed",
                        JobStatus.COMPLETED,
                        from_status=JobStatus.RUNNING,
                        message=f"Stored {job.result_count} normalized results",
                        details={
                            **result.metadata,
                            "auto_enrichment_jobs": auto_enrichment_jobs,
                        },
                    )
                    investigation = db.get(Investigation, job.investigation_id)
                    if investigation:
                        investigation.status = "ACTIVE"
                    record_success(db, investigation.organization_id, provider.name)
                    if job.requested_by_id:
                        record_audit(
                            db,
                            organization_id=investigation.organization_id,
                            actor_id=job.requested_by_id,
                            action="collection.completed",
                            object_type="collection_job",
                            object_id=job.id,
                        )
                    regenerate_monitoring_summary(
                        db, job, generate_ai=session_factory is SessionLocal
                    )
                job.ended_at = now_utc()
            job.lease_owner = None
            job.lease_expires_at = None
            db.commit()
        except Exception as exc:
            db.rollback()
            failed = db.get(CollectionJob, job_id)
            if failed:
                failed.lease_owner = None
                failed.lease_expires_at = None
                failed.error_summary = redact_text(str(exc))[:500]
                failed_investigation = db.get(Investigation, failed.investigation_id)
                if failed_investigation:
                    record_failure(
                        db,
                        failed_investigation.organization_id,
                        failed.provider,
                        failed.error_summary,
                    )
                if failed.attempt >= failed.max_attempts:
                    failed.status = JobStatus.FAILED
                    failed.ended_at = now_utc()
                    append_job_event(
                        db,
                        failed,
                        "failed",
                        JobStatus.FAILED,
                        from_status=JobStatus.RUNNING,
                        message=failed.error_summary or "Provider failed",
                    )
                    if failed_investigation:
                        if failed.requested_by_id:
                            record_audit(
                                db,
                                organization_id=failed_investigation.organization_id,
                                actor_id=failed.requested_by_id,
                                action="collection.failed",
                                object_type="collection_job",
                                object_id=failed.id,
                                decision="denied",
                                reason_code="execution_failed",
                            )
                        emit_notification(
                            db,
                            organization_id=failed_investigation.organization_id,
                            investigation_id=failed_investigation.id,
                            event_type="job.failed",
                            severity="high",
                            title=f"Collection job failed: {failed.provider}",
                            message=failed.error_summary or "Provider failed after all retries.",
                            dedupe_key=f"job.failed:{failed.id}",
                        )
                else:
                    failed.status = JobStatus.QUEUED
                    append_job_event(
                        db,
                        failed,
                        "retry_queued",
                        JobStatus.QUEUED,
                        from_status=JobStatus.RUNNING,
                        message=failed.error_summary or "Provider failed",
                        details={"attempt": failed.attempt},
                    )
                db.commit()
        return db.get(CollectionJob, job_id)


def generate_due_reports(session_factory=SessionLocal) -> int:
    now = now_utc()
    generated = 0
    with session_factory() as db:
        schedules = list(
            db.scalars(
                select(ReportSchedule).where(
                    ReportSchedule.enabled.is_(True), ReportSchedule.next_run_at <= now
                )
            )
        )
        for schedule in schedules:
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            investigation = db.get(Investigation, schedule.investigation_id)
            if investigation is None:
                schedule.enabled = False
                continue
            snapshot = db.scalar(
                select(AnalysisSnapshot)
                .where(AnalysisSnapshot.investigation_id == investigation.id)
                .order_by(AnalysisSnapshot.created_at.desc())
            )
            if snapshot is None:
                continue
            targets = list(
                db.scalars(select(Target).where(Target.investigation_id == investigation.id))
            )
            findings = list(
                db.scalars(select(Finding).where(Finding.investigation_id == investigation.id))
            )
            sources = list(
                db.scalars(
                    select(EvidenceSource).where(
                        EvidenceSource.investigation_id == investigation.id
                    )
                )
            )
            narrative = db.scalar(
                select(NarrativeSnapshot)
                .where(NarrativeSnapshot.analysis_snapshot_id == snapshot.id)
                .order_by(NarrativeSnapshot.created_at.desc())
            )
            organization = db.get(Organization, investigation.organization_id)
            content = build_pdf_report(
                investigation,
                snapshot,
                targets,
                findings,
                sources,
                schedule.style,
                narrative,
                brand_name=organization.report_title if organization else "SignalTrace",
                brand_accent=organization.report_accent if organization else "#147d72",
                brand_logo=organization.report_logo if organization else None,
            )
            filename = f"signaltrace-{investigation.id[:8]}-{schedule.style}-{now:%Y%m%d-%H%M}.pdf"
            db.add(
                ReportArtifact(
                    investigation_id=investigation.id,
                    schedule_id=schedule.id,
                    generated_by_id=schedule.created_by_id,
                    style=schedule.style,
                    filename=filename,
                    media_type="application/pdf",
                    content=content,
                    sha256=sha256(content),
                )
            )
            schedule.last_run_at = now
            emit_notification(
                db,
                organization_id=investigation.organization_id,
                investigation_id=investigation.id,
                event_type="report.generated",
                severity="info",
                title=f"Scheduled {schedule.style} report generated",
                message=f"{filename} is ready in the report center.",
                dedupe_key=f"report.generated:{schedule.id}:{now.isoformat()}",
            )
            generated += 1
        db.commit()
    return generated


def main() -> None:
    Base.metadata.create_all(bind=engine)
    upgrade_existing_schema()
    register_builtin_providers(registry)
    worker_id = os.getenv("WORKER_ID", f"{socket.gethostname()}:{os.getpid()}")
    print(f"job worker ready: {worker_id}", flush=True)
    while True:
        enqueue_due_schedules()
        enqueue_due_finding_monitors()
        monitor_job_health()
        deliver_pending_notifications()
        generate_due_reports()
        processed = process_one(worker_id)
        if processed is None:
            time.sleep(1)


if __name__ == "__main__":
    main()


register_builtin_providers(registry)
