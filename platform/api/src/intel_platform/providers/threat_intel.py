import base64
import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

MAX_RESPONSE_BYTES = 1_000_000


class ThreatIntelProvider:
    name: str
    target_types: frozenset[str]

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            target_types=self.target_types,
            passive_only=True,
            requires_credentials=True,
        )

    def collect(self, context: ProviderContext) -> ProviderResult:
        request = self.build_request(context)
        timeout = self._remaining_timeout(context)
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            with client.stream(**request) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise RuntimeError(f"{self.name} response exceeded size limit")
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise RuntimeError(f"{self.name} response must be a JSON object")
        return self.normalize(context, payload)

    def build_request(self, context: ProviderContext) -> dict:
        raise NotImplementedError

    def _remaining_timeout(self, context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 20.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, (deadline - datetime.now(UTC)).total_seconds())

    def normalize(self, context: ProviderContext, payload: dict) -> ProviderResult:
        db, job, target = context.db, context.job, context.target
        root = self._entity(
            db, job.investigation_id, target.target_type.value, target.canonical_value, 100
        )
        summary, associations = self.extract_intelligence(payload)
        finding_candidates = summary.pop("_finding_candidates", [])
        record_value = f"{self.name}:{target.target_type.value}:{target.canonical_value}"
        record = self._entity(
            db,
            job.investigation_id,
            "intelligence_record",
            record_value,
            90,
            {"provider": self.name, **summary},
        )
        relationship = self._relationship(
            db, job.investigation_id, root.id, "ENRICHED_BY", record.id, 90
        )
        entities = [root, record]
        relationships = [relationship]
        for association in associations[:100]:
            entity = self._entity(
                db,
                job.investigation_id,
                association["entity_type"],
                association["value"],
                association.get("confidence", 85),
                association.get("attributes", {}),
            )
            entities.append(entity)
            relationships.append(
                self._relationship(
                    db,
                    job.investigation_id,
                    root.id,
                    association["predicate"],
                    entity.id,
                    association.get("confidence", 85),
                )
            )
        fingerprint = hashlib.sha256(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        redacted = {"summary": summary, "associations": associations[:100]}
        redacted.update(
            {
                "provider": self.name,
                "target_type": target.target_type.value,
                "target": target.canonical_value,
            }
        )
        db.flush()
        return ProviderResult(
            result_count=len({item.id for item in entities}),
            entity_ids=tuple(dict.fromkeys(item.id for item in entities)),
            relationship_ids=tuple(dict.fromkeys(item.id for item in relationships)),
            metadata={
                "synthetic": False,
                "target": target.canonical_value,
                "finding_candidates": finding_candidates,
            },
            response_fingerprint=fingerprint,
            redacted_payload=redacted,
        )

    def redact(self, payload: dict) -> dict:
        return {
            "response_keys": sorted(str(key) for key in payload)[:40],
            "response_status": payload.get("status") or payload.get("query_status"),
        }

    def extract_intelligence(self, payload: dict) -> tuple[dict, list[dict]]:
        return self.redact(payload), []

    def _entity(
        self,
        db,
        investigation_id: str,
        entity_type: str,
        value: str,
        confidence: int,
        attributes: dict | None = None,
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
                provider=self.name,
                attributes={"classification": "OBSERVED_FACT", "synthetic": False},
            )
            db.add(entity)
            db.flush()
        if attributes:
            entity.attributes = {
                **(entity.attributes or {}),
                **attributes,
                "classification": "OBSERVED_FACT",
                "synthetic": False,
            }
            entity.confidence = confidence
        return entity

    def _relationship(
        self,
        db,
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
                Relationship.provider == self.name,
            )
        )
        if relationship is None:
            relationship = Relationship(
                investigation_id=investigation_id,
                subject_entity_id=subject_id,
                predicate=predicate,
                object_entity_id=object_id,
                confidence=confidence,
                provider=self.name,
            )
            db.add(relationship)
        return relationship


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    target_types = frozenset({"domain", "ip_address", "url"})

    def build_request(self, context: ProviderContext) -> dict:
        value = context.target.canonical_value
        kind = {"domain": "domains", "ip_address": "ip_addresses", "url": "urls"}[
            context.target.target_type.value
        ]
        if kind == "urls":
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return {
            "method": "GET",
            "url": f"https://www.virustotal.com/api/v3/{kind}/{quote(value, safe='')}",
            "headers": {"x-apikey": context.credentials["api_key"]},
        }

    def extract_intelligence(self, payload: dict) -> tuple[dict, list[dict]]:
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        counts = {
            key: int(stats.get(key, 0) or 0)
            for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
        }
        verdict = (
            "malicious_detections"
            if counts["malicious"]
            else ("suspicious_detections" if counts["suspicious"] else "no_detections")
        )
        categories = sorted({str(value) for value in (attributes.get("categories") or {}).values()})
        return {
            "kind": "virustotal_verdict",
            "verdict": verdict,
            "analysis_stats": counts,
            "reputation": attributes.get("reputation"),
            "total_votes": attributes.get("total_votes") or {},
            "categories": categories[:30],
            "tags": [str(item) for item in (attributes.get("tags") or [])[:30]],
            "last_analysis_date": attributes.get("last_analysis_date"),
        }, []


class ShodanProvider(ThreatIntelProvider):
    name = "shodan"
    target_types = frozenset({"ip_address"})

    def build_request(self, context: ProviderContext) -> dict:
        target = quote(context.target.canonical_value, safe="")
        return {
            "method": "GET",
            "url": f"https://api.shodan.io/shodan/host/{target}",
            "params": {"key": context.credentials["api_key"], "minify": "true"},
        }


class GreyNoiseProvider(ThreatIntelProvider):
    name = "greynoise"
    target_types = frozenset({"ip_address"})

    def build_request(self, context: ProviderContext) -> dict:
        target = quote(context.target.canonical_value, safe="")
        return {
            "method": "GET",
            "url": f"https://api.greynoise.io/v3/community/{target}",
            "headers": {"key": context.credentials["api_key"]},
        }


class AlienVaultOtxProvider(ThreatIntelProvider):
    name = "alienvault_otx"
    target_types = frozenset({"domain", "ip_address", "url"})

    def build_request(self, context: ProviderContext) -> dict:
        kind = {"domain": "domain", "ip_address": "IPv4", "url": "url"}[
            context.target.target_type.value
        ]
        target = quote(context.target.canonical_value, safe="")
        return {
            "method": "GET",
            "url": f"https://otx.alienvault.com/api/v1/indicators/{kind}/{target}/general",
            "headers": {"X-OTX-API-KEY": context.credentials["api_key"]},
        }

    def extract_intelligence(self, payload: dict) -> tuple[dict, list[dict]]:
        pulse_info = payload.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        associations: list[dict] = []
        families: set[str] = set()
        for pulse in pulses[:50]:
            pulse_id = str(pulse.get("id") or pulse.get("name") or "").strip()
            if not pulse_id:
                continue
            pulse_families = []
            for family in pulse.get("malware_families") or []:
                value = str(
                    family.get("display_name") if isinstance(family, dict) else family
                ).strip()
                if value:
                    families.add(value)
                    pulse_families.append(value)
            associations.append(
                {
                    "entity_type": "otx_pulse",
                    "value": pulse_id,
                    "predicate": "MENTIONED_IN",
                    "confidence": 85,
                    "attributes": {
                        "name": str(pulse.get("name") or pulse_id)[:300],
                        "description": str(pulse.get("description") or "")[:1000],
                        "tags": [str(item) for item in (pulse.get("tags") or [])[:30]],
                        "adversary": str(pulse.get("adversary") or "")[:200],
                        "modified": pulse.get("modified"),
                        "malware_families": pulse_families,
                    },
                }
            )
        associations.extend(
            {
                "entity_type": "malware_family",
                "value": family,
                "predicate": "ASSOCIATED_WITH_MALWARE",
                "confidence": 85,
                "attributes": {"source": "alienvault_otx"},
            }
            for family in sorted(families)
        )
        return {
            "kind": "otx_pulse_summary",
            "pulse_count": int(pulse_info.get("count", len(pulses)) or 0),
            "returned_pulses": len(pulses),
            "malware_families": sorted(families),
        }, associations


class AbuseIpDbProvider(ThreatIntelProvider):
    name = "abuseipdb"
    target_types = frozenset({"ip_address"})

    def build_request(self, context: ProviderContext) -> dict:
        return {
            "method": "GET",
            "url": "https://api.abuseipdb.com/api/v2/check",
            "params": {"ipAddress": context.target.canonical_value, "maxAgeInDays": "90"},
            "headers": {"Key": context.credentials["api_key"], "Accept": "application/json"},
        }


class CensysProvider(ThreatIntelProvider):
    name = "censys"
    target_types = frozenset({"ip_address"})

    def build_request(self, context: ProviderContext) -> dict:
        target = quote(context.target.canonical_value, safe="")
        token = context.credentials.get("personal_access_token") or context.credentials["api_id"]
        return {
            "method": "GET",
            "url": f"https://api.platform.censys.io/v3/global/asset/host/{target}",
            "headers": {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.censys.api.v3.host.v1+json",
            },
        }

    def extract_intelligence(self, payload: dict) -> tuple[dict, list[dict]]:
        resource = payload.get("result", {}).get("resource", {})
        address = str(resource.get("ip") or "unknown")
        autonomous_system = resource.get("autonomous_system") or {}
        location = resource.get("location") or {}
        associations: list[dict] = []
        services: list[dict] = []
        finding_candidates: list[dict] = []
        for service in resource.get("services") or []:
            port = int(service.get("port", 0) or 0)
            if not port:
                continue
            transport = str(service.get("transport_protocol") or "unknown").lower()
            protocol = str(service.get("protocol") or "unknown").upper()
            software = [
                {
                    "vendor": item.get("vendor"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                }
                for item in (service.get("software") or [])[:20]
            ]
            value = f"{address}:{port}/{transport}"
            normalized = {
                "port": port,
                "transport": transport,
                "protocol": protocol,
                "software": software,
                "scan_time": service.get("scan_time"),
            }
            services.append(normalized)
            associations.append(
                {
                    "entity_type": "network_service",
                    "value": value,
                    "predicate": "EXPOSES_SERVICE",
                    "confidence": 95,
                    "attributes": normalized,
                }
            )
            if port not in {80, 443}:
                finding_candidates.append(
                    {
                        "rule_id": "censys.unexpected_public_service",
                        "title": f"Unexpected public {protocol} service",
                        "description": (
                            f"Censys observed {protocol} over {transport.upper()} on port {port}. "
                            "Confirm that this service is intentionally exposed and "
                            "access-controlled."
                        ),
                        "severity": "medium",
                        "confidence": 85,
                        "asset_value": value,
                        "entity_value": value,
                    }
                )
        if autonomous_system.get("asn"):
            associations.append(
                {
                    "entity_type": "autonomous_system",
                    "value": f"AS{autonomous_system['asn']}",
                    "predicate": "ANNOUNCED_BY",
                    "confidence": 95,
                    "attributes": {
                        "name": autonomous_system.get("name"),
                        "description": autonomous_system.get("description"),
                        "bgp_prefix": autonomous_system.get("bgp_prefix"),
                        "country_code": autonomous_system.get("country_code"),
                    },
                }
            )
        operating_system = resource.get("operating_system") or {}
        return {
            "kind": "censys_host_summary",
            "ip": address,
            "service_count": int(resource.get("service_count", len(services)) or 0),
            "services": services,
            "autonomous_system": autonomous_system,
            "location": {
                "country": location.get("country"),
                "country_code": location.get("country_code"),
                "city": location.get("city"),
            },
            "operating_system": operating_system,
            "dns_names": [str(item) for item in (resource.get("dns", {}).get("names") or [])[:100]],
            "_finding_candidates": finding_candidates,
        }, associations


class UrlHausProvider(ThreatIntelProvider):
    name = "urlhaus"
    target_types = frozenset({"domain", "url"})

    def build_request(self, context: ProviderContext) -> dict:
        key = "url" if context.target.target_type.value == "url" else "host"
        return {
            "method": "POST",
            "url": f"https://urlhaus-api.abuse.ch/v1/{key}/",
            "data": {key: context.target.canonical_value},
            "headers": {"Auth-Key": context.credentials["auth_key"]},
        }


class AbuseChProvider(ThreatIntelProvider):
    name = "abuse_ch"
    target_types = frozenset({"domain", "ip_address", "url"})

    def build_request(self, context: ProviderContext) -> dict:
        return {
            "method": "POST",
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "json": {
                "query": "search_ioc",
                "search_term": context.target.canonical_value,
                "exact_match": True,
            },
            "headers": {"Auth-Key": context.credentials["auth_key"]},
        }

    def extract_intelligence(self, payload: dict) -> tuple[dict, list[dict]]:
        records = payload.get("data") if isinstance(payload.get("data"), list) else []
        associations: list[dict] = []
        families: set[str] = set()
        for item in records[:100]:
            record_id = str(item.get("id") or item.get("ioc") or "").strip()
            if not record_id:
                continue
            malware = str(item.get("malware_printable") or item.get("malware") or "").strip()
            if malware:
                families.add(malware)
            confidence = max(0, min(100, int(item.get("confidence_level", 85) or 85)))
            associations.append(
                {
                    "entity_type": "threatfox_record",
                    "value": f"threatfox:{record_id}",
                    "predicate": "MATCHED_THREAT_RECORD",
                    "confidence": confidence,
                    "attributes": {
                        "ioc": item.get("ioc"),
                        "ioc_type": item.get("ioc_type"),
                        "threat_type": item.get("threat_type"),
                        "threat_type_desc": item.get("threat_type_desc"),
                        "malware": malware or None,
                        "first_seen": item.get("first_seen"),
                        "last_seen": item.get("last_seen"),
                        "tags": [str(v) for v in (item.get("tags") or [])[:30]],
                        "reference": item.get("reference"),
                    },
                }
            )
        associations.extend(
            {
                "entity_type": "malware_family",
                "value": family,
                "predicate": "ASSOCIATED_WITH_MALWARE",
                "confidence": 90,
                "attributes": {"source": "threatfox"},
            }
            for family in sorted(families)
        )
        return {
            "kind": "threatfox_summary",
            "query_status": payload.get("query_status"),
            "match_count": len(records),
            "malware_families": sorted(families),
        }, associations


THREAT_PROVIDERS = (
    VirusTotalProvider,
    ShodanProvider,
    GreyNoiseProvider,
    AlienVaultOtxProvider,
    AbuseIpDbProvider,
    CensysProvider,
    UrlHausProvider,
    AbuseChProvider,
)
