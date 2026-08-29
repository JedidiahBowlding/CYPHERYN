from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Entity, Investigation, Relationship, ThreatIntelObject

SUPPORTED_TYPES = {
    "indicator",
    "malware",
    "campaign",
    "threat-actor",
    "infrastructure",
    "attack-pattern",
    "tool",
    "vulnerability",
    "identity",
    "location",
    "relationship",
}
PATTERN_VALUE = re.compile(
    r"(?P<kind>domain-name|ipv4-addr|ipv6-addr|url|email-addr):value\s*=\s*['\"](?P<value>[^'\"]+)['\"]",
    re.IGNORECASE,
)
PATTERN_HASH = re.compile(
    r"file:hashes\.(?:'|\")?(?P<algorithm>MD5|SHA-1|SHA-256|SHA-512)(?:'|\")?\s*=\s*['\"](?P<value>[a-fA-F0-9]+)['\"]",
    re.IGNORECASE,
)
ENTITY_TYPES = {
    "domain-name": "domain",
    "ipv4-addr": "ip_address",
    "ipv6-addr": "ip_address",
    "url": "url",
    "email-addr": "email_address",
}


def _timestamp(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else result.replace(tzinfo=UTC)


def _bounded_raw(item: dict) -> dict:
    allowed = {
        "type",
        "spec_version",
        "id",
        "created",
        "modified",
        "created_by_ref",
        "name",
        "description",
        "labels",
        "confidence",
        "revoked",
        "pattern",
        "pattern_type",
        "valid_from",
        "valid_until",
        "indicator_types",
        "malware_types",
        "campaign_types",
        "threat_actor_types",
        "infrastructure_types",
        "external_references",
        "source_ref",
        "target_ref",
        "relationship_type",
    }
    return {key: value for key, value in item.items() if key in allowed}


def _entity(
    db: Session,
    investigation_id: str,
    entity_type: str,
    value: str,
    confidence: int,
    attributes: dict,
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
            canonical_value=value[:2048],
            confidence=confidence,
            provider="stix",
            attributes=attributes,
        )
        db.add(entity)
        db.flush()
    else:
        entity.confidence = max(entity.confidence, confidence)
        entity.attributes = {**(entity.attributes or {}), **attributes}
    return entity


def import_stix_bundle(
    db: Session,
    investigation: Investigation,
    bundle: dict,
    *,
    source: str,
    default_ttl_days: int,
) -> dict:
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("A STIX 2.x bundle with an objects array is required")
    objects = bundle["objects"]
    if len(objects) > 5000:
        raise ValueError("STIX bundle exceeds the 5,000 object limit")
    now = datetime.now(UTC)
    imported = updated = active = expired = correlations = 0
    counts: Counter[str] = Counter()
    entity_by_stix: dict[str, Entity] = {}

    for item in objects:
        if not isinstance(item, dict):
            continue
        object_type = str(item.get("type") or "")
        stix_id = str(item.get("id") or "")
        if object_type not in SUPPORTED_TYPES or not stix_id.startswith(f"{object_type}--"):
            continue
        if object_type == "relationship":
            continue
        confidence = max(0, min(int(item.get("confidence", 50) or 50), 100))
        valid_from = _timestamp(item.get("valid_from"))
        valid_until = _timestamp(item.get("valid_until"))
        modified = _timestamp(item.get("modified")) or _timestamp(item.get("created")) or now
        if object_type == "indicator" and valid_until is None:
            valid_until = max(modified, valid_from or modified) + timedelta(days=default_ttl_days)
        record = db.scalar(
            select(ThreatIntelObject).where(
                ThreatIntelObject.organization_id == investigation.organization_id,
                ThreatIntelObject.stix_id == stix_id,
            )
        )
        values = {
            "object_type": object_type,
            "name": str(item.get("name") or "")[:500],
            "description": str(item.get("description") or ""),
            "pattern": str(item.get("pattern") or ""),
            "confidence": confidence,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "revoked": bool(item.get("revoked", False)),
            "source": source,
            "external_references": list(item.get("external_references") or [])[:50],
            "labels": list(item.get("labels") or [])[:50],
            "raw_object": _bounded_raw(item),
            "modified_at": modified,
            "imported_at": now,
        }
        if record is None:
            record = ThreatIntelObject(
                organization_id=investigation.organization_id,
                stix_id=stix_id,
                **values,
            )
            db.add(record)
            imported += 1
        else:
            for key, value in values.items():
                setattr(record, key, value)
            updated += 1
        counts[object_type] += 1
        is_active = not record.revoked and (valid_until is None or valid_until > now)
        if object_type == "indicator":
            if is_active:
                active += 1
            else:
                expired += 1
        entity_by_stix[stix_id] = _entity(
            db,
            investigation.id,
            "threat_indicator" if object_type == "indicator" else object_type.replace("-", "_"),
            stix_id,
            confidence,
            {
                "stix_id": stix_id,
                "name": values["name"],
                "source": source,
                "valid_until": valid_until.isoformat() if valid_until else None,
                "active": is_active,
            },
        )

        if object_type == "indicator" and is_active:
            pattern = values["pattern"]
            matches = [
                (ENTITY_TYPES[match.group("kind").lower()], match.group("value"))
                for match in PATTERN_VALUE.finditer(pattern)
            ]
            matches.extend(
                ("file_hash", match.group("value").lower())
                for match in PATTERN_HASH.finditer(pattern)
            )
            indicator_entity = entity_by_stix[stix_id]
            for entity_type, value in matches[:50]:
                canonical = (
                    value.lower()
                    if entity_type in {"domain", "email_address", "file_hash"}
                    else value
                )
                assets = list(
                    db.scalars(
                        select(Entity).where(
                            Entity.investigation_id == investigation.id,
                            Entity.entity_type == entity_type,
                            Entity.canonical_value == canonical,
                        )
                    )
                )
                for asset in assets:
                    relationship = db.scalar(
                        select(Relationship).where(
                            Relationship.investigation_id == investigation.id,
                            Relationship.subject_entity_id == indicator_entity.id,
                            Relationship.predicate == "matches_asset",
                            Relationship.object_entity_id == asset.id,
                            Relationship.provider == "stix",
                        )
                    )
                    if relationship is None:
                        db.add(
                            Relationship(
                                investigation_id=investigation.id,
                                subject_entity_id=indicator_entity.id,
                                predicate="matches_asset",
                                object_entity_id=asset.id,
                                claim_class="CORRELATED_INTELLIGENCE",
                                confidence=confidence,
                                provider="stix",
                            )
                        )
                        correlations += 1

    for item in objects:
        if not isinstance(item, dict) or item.get("type") != "relationship":
            continue
        subject = entity_by_stix.get(str(item.get("source_ref") or ""))
        target = entity_by_stix.get(str(item.get("target_ref") or ""))
        predicate = str(item.get("relationship_type") or "related_to")[:80]
        if not subject or not target:
            continue
        existing = db.scalar(
            select(Relationship).where(
                Relationship.investigation_id == investigation.id,
                Relationship.subject_entity_id == subject.id,
                Relationship.predicate == predicate,
                Relationship.object_entity_id == target.id,
                Relationship.provider == "stix",
            )
        )
        if existing is None:
            db.add(
                Relationship(
                    investigation_id=investigation.id,
                    subject_entity_id=subject.id,
                    predicate=predicate,
                    object_entity_id=target.id,
                    claim_class="IMPORTED_INTELLIGENCE",
                    confidence=min(subject.confidence, target.confidence),
                    provider="stix",
                )
            )

    return {
        "imported": imported,
        "updated": updated,
        "active_indicators": active,
        "expired_indicators": expired,
        "correlations": correlations,
        "object_types": dict(sorted(counts.items())),
    }
