import hashlib

from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class SafeMockProvider:
    name = "safe_mock"
    capabilities = ProviderCapabilities(
        target_types=frozenset(
            {
                "domain",
                "ip_address",
                "asn",
                "url",
                "email_address",
                "username",
                "organization",
                "person",
            }
        ),
        passive_only=True,
        requires_credentials=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        db, job, target = context.db, context.job, context.target
        root = self._entity(
            db, job.investigation_id, target.target_type.value, target.canonical_value, 100
        )
        results = [root]
        relationships = []
        if target.target_type.value == "domain":
            digest = hashlib.sha256(target.canonical_value.encode()).hexdigest()
            octet = 10 + int(digest[:2], 16) % 200
            host = self._entity(
                db, job.investigation_id, "subdomain", f"www.{target.canonical_value}", 96
            )
            ip = self._entity(db, job.investigation_id, "ip_address", f"203.0.113.{octet}", 94)
            certificate = self._entity(
                db, job.investigation_id, "certificate", f"sha256:{digest[:24]}", 91
            )
            results.extend([host, ip, certificate])
            relationships.extend(
                [
                    self._relationship(
                        db, job.investigation_id, root.id, "HAS_SUBDOMAIN", host.id, 96
                    ),
                    self._relationship(db, job.investigation_id, host.id, "RESOLVES_TO", ip.id, 94),
                    self._relationship(
                        db,
                        job.investigation_id,
                        host.id,
                        "USES_CERTIFICATE",
                        certificate.id,
                        91,
                    ),
                ]
            )
        db.flush()
        return ProviderResult(
            result_count=len(results),
            entity_ids=tuple(item.id for item in results),
            relationship_ids=tuple(item.id for item in relationships),
            metadata={"synthetic": True, "target": target.canonical_value},
        )

    def _entity(
        self, db, investigation_id: str, entity_type: str, value: str, confidence: int
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
                attributes={"classification": "OBSERVED_FACT", "synthetic": True},
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
