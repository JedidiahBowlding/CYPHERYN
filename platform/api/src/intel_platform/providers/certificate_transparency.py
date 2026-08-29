import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

MAX_RESPONSE_BYTES = 3_000_000
MAX_CERTIFICATES = 1000
MAX_NAMES = 500


class CertificateTransparencyProvider:
    name = "certificate_transparency"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain"}), passive_only=True, requires_credentials=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        domain = context.target.canonical_value
        timeout = self._remaining_timeout(context)
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            try:
                payload = self._read_list(
                    client,
                    f"https://crt.sh/?q={quote(f'%.{domain}', safe='')}&output=json",
                )
            except (httpx.HTTPError, json.JSONDecodeError, RuntimeError):
                certspotter = self._read_list(
                    client,
                    "https://api.certspotter.com/v1/issuances",
                    params={
                        "domain": domain,
                        "include_subdomains": "true",
                        "expand": "dns_names",
                    },
                )
                payload = [
                    {
                        "id": item.get("id"),
                        "name_value": "\n".join(item.get("dns_names") or []),
                        "issuer_name": "",
                        "not_before": item.get("not_before"),
                        "not_after": item.get("not_after"),
                    }
                    for item in certspotter
                ]
        return self.normalize(context, payload[:MAX_CERTIFICATES])

    @staticmethod
    def _read_list(client: httpx.Client, url: str, params: dict | None = None) -> list[dict]:
        with client.stream(
            "GET", url, params=params, headers={"Accept": "application/json"}
        ) as response:
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise RuntimeError("Certificate transparency response exceeded size limit")
        payload = json.loads(body)
        if not isinstance(payload, list):
            raise RuntimeError("Certificate transparency response must be a JSON list")
        return payload

    def _remaining_timeout(self, context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 30.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, (deadline - datetime.now(UTC)).total_seconds())

    def normalize(self, context: ProviderContext, payload: list[dict]) -> ProviderResult:
        db, job, target = context.db, context.job, context.target
        root_domain = target.canonical_value
        root = self._entity(db, job.investigation_id, "domain", root_domain, 100)
        certificates: dict[str, dict] = {}
        for item in payload:
            certificate_id = str(item.get("id") or "").strip()
            if certificate_id:
                certificates[certificate_id] = {
                    "id": certificate_id,
                    "issuer_name": str(item.get("issuer_name") or "")[:500],
                    "not_before": item.get("not_before"),
                    "not_after": item.get("not_after"),
                }
        names = self.extract_scoped_names(payload, root_domain)
        discovered = sorted(names)[:MAX_NAMES]
        entities = [root]
        relationships = []
        for name in discovered:
            subdomain = self._entity(db, job.investigation_id, "subdomain", name, 95)
            entities.append(subdomain)
            relationships.append(
                self._relationship(
                    db, job.investigation_id, root.id, "HAS_SUBDOMAIN", subdomain.id, 95
                )
            )
        fingerprint = hashlib.sha256(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        db.flush()
        return ProviderResult(
            result_count=len({entity.id for entity in entities}),
            entity_ids=tuple(dict.fromkeys(entity.id for entity in entities)),
            relationship_ids=tuple(dict.fromkeys(item.id for item in relationships)),
            metadata={
                "synthetic": False,
                "target": root_domain,
                "discovered_domains": discovered,
                "certificate_count": len(certificates),
            },
            response_fingerprint=fingerprint,
            redacted_payload={
                "discovered_domains": discovered,
                "certificate_count": len(certificates),
                "certificates": list(certificates.values())[:100],
                "truncated": len(names) > MAX_NAMES,
            },
        )

    @staticmethod
    def extract_scoped_names(payload: list[dict], root_domain: str) -> set[str]:
        names: set[str] = set()
        for item in payload:
            for raw_name in str(item.get("name_value") or "").splitlines():
                name = raw_name.strip().lower().removeprefix("*.").rstrip(".")
                try:
                    name = name.encode("idna").decode("ascii")
                except UnicodeError:
                    continue
                if name != root_domain and name.endswith(f".{root_domain}"):
                    names.add(name)
        return names

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
