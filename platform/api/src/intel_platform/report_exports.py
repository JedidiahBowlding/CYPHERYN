import csv
import hashlib
import io
import json
import uuid
from datetime import UTC, datetime

from .models import (
    CollectionJobEvent,
    Entity,
    EvidenceChange,
    EvidenceSource,
    Finding,
    Investigation,
    Relationship,
    Target,
)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def finding_record(item: Finding) -> dict:
    return {
        "id": item.id,
        "rule_id": item.rule_id,
        "title": item.title,
        "description": item.description,
        "severity": item.severity,
        "status": item.status,
        "confidence": item.confidence,
        "asset": item.asset_value,
        "provider": item.provider,
        "provider_observed_at": iso(item.provider_observed_at or item.evidence_observed_at),
        "direct_observed_at": iso(item.direct_observed_at),
        "created_at": iso(item.created_at),
        "updated_at": iso(item.updated_at),
        "resolved_at": iso(item.resolved_at),
        "verification_history": item.verification_history or [],
        "corroborating_providers": item.corroborating_providers or [],
        "remediation_notes": item.remediation_notes,
    }


def timeline_records(
    sources: list[EvidenceSource],
    changes: list[EvidenceChange],
    findings: list[Finding],
    job_events: list[CollectionJobEvent],
) -> list[dict]:
    events: list[dict] = []
    for source in sources:
        events.append(
            {
                "timestamp": iso(source.retrieved_at),
                "event_type": "evidence.retrieved",
                "provider": source.provider,
                "object_id": source.id,
                "summary": f"Retrieved evidence for {source.query}",
                "observation_type": "provider",
                "sha256": source.raw_response_hash or "",
                "integrity_hash": source.integrity_hash or "",
            }
        )
    for change in changes:
        events.append(
            {
                "timestamp": iso(change.created_at),
                "event_type": f"evidence.{change.change_type}",
                "provider": change.provider,
                "object_id": change.id,
                "summary": change.summary,
                "observation_type": "comparison",
                "sha256": "",
            }
        )
    for finding in findings:
        events.append(
            {
                "timestamp": iso(finding.created_at),
                "event_type": "finding.opened",
                "provider": finding.provider,
                "object_id": finding.id,
                "summary": finding.title,
                "observation_type": "provider",
                "sha256": "",
            }
        )
        for entry in finding.verification_history or []:
            events.append(
                {
                    "timestamp": entry.get("observed_at"),
                    "event_type": f"finding.{entry.get('classification', 'verified')}",
                    "provider": entry.get("provider", "direct_verifier"),
                    "object_id": finding.id,
                    "summary": f"{finding.title}: {entry.get('direct_state', 'observed')}",
                    "observation_type": "direct",
                    "sha256": "",
                }
            )
        if finding.resolved_at:
            events.append(
                {
                    "timestamp": iso(finding.resolved_at),
                    "event_type": "finding.resolved",
                    "provider": finding.provider,
                    "object_id": finding.id,
                    "summary": finding.title,
                    "observation_type": "lifecycle",
                    "sha256": "",
                }
            )
    for event in job_events:
        events.append(
            {
                "timestamp": iso(event.occurred_at),
                "event_type": f"job.{event.event_type}",
                "provider": "",
                "object_id": event.job_id,
                "summary": event.message,
                "observation_type": "job",
                "sha256": "",
            }
        )
    return sorted(events, key=lambda item: item["timestamp"] or "")


def json_export(
    investigation: Investigation,
    targets: list[Target],
    findings: list[Finding],
    sources: list[EvidenceSource],
    changes: list[EvidenceChange],
    job_events: list[CollectionJobEvent],
    entities: list[Entity],
    relationships: list[Relationship],
) -> bytes:
    generated = datetime.now(UTC).isoformat()
    body = {
        "schema": "signaltrace-investigation-export-v2",
        "generated_at": generated,
        "investigation": {
            "id": investigation.id,
            "name": investigation.name,
            "description": investigation.description,
            "status": str(investigation.status),
        },
        "targets": [
            {"type": item.target_type.value, "value": item.canonical_value} for item in targets
        ],
        "findings": [finding_record(item) for item in findings],
        "evidence_sources": [
            {
                "id": item.id,
                "provider": item.provider,
                "provider_version": item.provider_version,
                "ruleset_version": item.ruleset_version,
                "query": item.query,
                "retrieved_at": iso(item.retrieved_at),
                "raw_response_sha256": item.raw_response_hash,
                "previous_integrity_hash": item.previous_integrity_hash,
                "integrity_hash": item.integrity_hash,
                "redacted_payload": item.redacted_payload,
            }
            for item in sources
        ],
        "entities": [
            {
                "id": item.id,
                "type": item.entity_type,
                "value": item.canonical_value,
                "confidence": item.confidence,
            }
            for item in entities
        ],
        "relationships": [
            {
                "id": item.id,
                "source_ref": item.subject_entity_id,
                "relationship_type": item.predicate,
                "target_ref": item.object_entity_id,
                "confidence": item.confidence,
                "provider": item.provider,
            }
            for item in relationships
        ],
        "timeline": timeline_records(sources, changes, findings, job_events),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    wrapper = {
        "manifest": {"algorithm": "SHA-256", "content_sha256": sha256(canonical)},
        "data": body,
    }
    return json.dumps(wrapper, indent=2, default=str).encode()


def findings_csv(findings: list[Finding]) -> bytes:
    output = io.StringIO()
    fields = [
        "id",
        "severity",
        "status",
        "title",
        "asset",
        "provider",
        "confidence",
        "provider_observed_at",
        "direct_observed_at",
        "resolved_at",
        "remediation_notes",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for finding in findings:
        record = finding_record(finding)
        writer.writerow({key: record.get(key, "") for key in fields})
    return output.getvalue().encode()


def timeline_csv(records: list[dict]) -> bytes:
    output = io.StringIO()
    fields = [
        "timestamp",
        "event_type",
        "observation_type",
        "provider",
        "object_id",
        "summary",
        "sha256",
        "integrity_hash",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue().encode()


def _stix_id(kind: str, local_id: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'signaltrace:' + local_id)}"


def stix_export(
    investigation: Investigation,
    findings: list[Finding],
    entities: list[Entity],
    relationships: list[Relationship],
) -> bytes:
    now = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": _stix_id("identity", investigation.id),
            "created": now,
            "modified": now,
            "name": "SignalTrace",
            "identity_class": "system",
        }
    ]
    refs: dict[str, str] = {}
    type_map = {
        "domain": "domain-name",
        "subdomain": "domain-name",
        "ip_address": "ipv4-addr",
        "url": "url",
        "email": "email-addr",
        "file_hash": "file",
    }
    for entity in entities:
        stix_type = type_map.get(str(entity.entity_type))
        if not stix_type:
            continue
        stix_id = _stix_id(stix_type, entity.id)
        refs[entity.id] = stix_id
        obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id}
        if stix_type == "file":
            obj["hashes"] = {"SHA-256": entity.canonical_value.removeprefix("sha256:")}
        else:
            obj["value"] = entity.canonical_value
        objects.append(obj)
    for relation in relationships:
        if relation.subject_entity_id not in refs or relation.object_entity_id not in refs:
            continue
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship", relation.id),
                "created": now,
                "modified": now,
                "relationship_type": "related-to",
                "source_ref": refs[relation.subject_entity_id],
                "target_ref": refs[relation.object_entity_id],
                "description": relation.predicate,
            }
        )
    for finding in findings:
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": _stix_id("note", finding.id),
                "created": now,
                "modified": now,
                "abstract": finding.title,
                "content": finding.description,
                "authors": ["SignalTrace"],
                "labels": [finding.severity, finding.status, finding.provider],
                "object_refs": [_stix_id("identity", investigation.id)],
                "x_signaltrace_status": finding.status,
                "x_signaltrace_provider_observed_at": iso(finding.provider_observed_at),
                "x_signaltrace_direct_observed_at": iso(finding.direct_observed_at),
                "x_signaltrace_verification_history": finding.verification_history or [],
            }
        )
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", investigation.id + now),
        "objects": objects,
    }
    return json.dumps(bundle, indent=2).encode()
