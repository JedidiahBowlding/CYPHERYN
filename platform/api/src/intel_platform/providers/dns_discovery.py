import hashlib
import ipaddress
import json

import dns.exception
import dns.resolver
from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class DnsDiscoveryProvider:
    name = "dns_discovery"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain"}), passive_only=True, requires_credentials=False
    )
    record_types = ("A", "AAAA", "MX", "CNAME", "TXT", "CAA", "NS")

    def collect(self, context: ProviderContext) -> ProviderResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 6
        answers: dict[str, list[str]] = {}
        for record_type in self.record_types:
            try:
                response = resolver.resolve(
                    context.target.canonical_value, record_type, search=False
                )
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                answers[record_type] = []
                continue
            answers[record_type] = sorted({item.to_text().strip() for item in response})
        return self.normalize(context, answers)

    def normalize(self, context: ProviderContext, answers: dict[str, list[str]]) -> ProviderResult:
        db, job, target = context.db, context.job, context.target
        root = self._entity(db, job.investigation_id, "domain", target.canonical_value, 100)
        entities = [root]
        relationships = []
        discovered_ips: set[str] = set()
        mappings = {
            "MX": ("mail_server", "HAS_MAIL_SERVER"),
            "NS": ("nameserver", "HAS_NAMESERVER"),
            "CNAME": ("domain", "ALIASES_TO"),
            "TXT": ("dns_txt", "PUBLISHES_TXT"),
            "CAA": ("certificate_authority", "AUTHORIZES_CA"),
        }
        normalized: dict[str, list[str]] = {}
        for record_type, values in answers.items():
            normalized[record_type] = []
            for raw_value in values[:100]:
                value = raw_value.rstrip(".")
                if record_type == "MX":
                    parts = value.split(maxsplit=1)
                    value = (parts[1] if len(parts) == 2 else parts[0]).rstrip(".")
                elif record_type == "TXT":
                    value = value.strip('"')[:1000]
                elif record_type == "CAA":
                    value = value[:1000]
                if record_type in {"A", "AAAA"}:
                    try:
                        value = ipaddress.ip_address(value).compressed
                    except ValueError:
                        continue
                    entity_type, predicate = "ip_address", "RESOLVES_TO"
                    discovered_ips.add(value)
                else:
                    entity_type, predicate = mappings[record_type]
                normalized[record_type].append(value)
                entity = self._entity(db, job.investigation_id, entity_type, value, 98)
                entities.append(entity)
                relationships.append(
                    self._relationship(db, job.investigation_id, root.id, predicate, entity.id, 98)
                )
        fingerprint = hashlib.sha256(
            json.dumps(answers, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        db.flush()
        return ProviderResult(
            result_count=len({item.id for item in entities}),
            entity_ids=tuple(dict.fromkeys(item.id for item in entities)),
            relationship_ids=tuple(dict.fromkeys(item.id for item in relationships)),
            metadata={
                "synthetic": False,
                "target": target.canonical_value,
                "discovered_ips": sorted(discovered_ips),
            },
            response_fingerprint=fingerprint,
            redacted_payload={"records": normalized},
        )

    def _entity(self, db, investigation_id: str, entity_type: str, value: str, confidence: int):
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
        return entity

    def _relationship(
        self,
        db,
        investigation_id: str,
        subject_id: str,
        predicate: str,
        object_id: str,
        confidence: int,
    ):
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
