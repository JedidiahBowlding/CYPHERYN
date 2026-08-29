import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from urllib.parse import quote, urlparse

import httpx
from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_RESPONSE_BYTES = 1_000_000


class RdapProvider:
    name = "rdap"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain"}),
        passive_only=True,
        requires_credentials=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        timeout = self._remaining_timeout(context)
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            bootstrap = self._read_json(client, BOOTSTRAP_URL)
            base_url = self.select_domain_service(bootstrap, context.target.canonical_value)
            query_url = (
                f"{base_url.rstrip('/')}/domain/{quote(context.target.canonical_value, safe='')}"
            )
            payload = self._read_json(client, query_url)
        return self._normalize(context, payload)

    def _remaining_timeout(self, context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 20.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, (deadline - datetime.now(UTC)).total_seconds())

    def _read_json(self, client: httpx.Client, url: str) -> dict:
        self._validate_endpoint(url)
        with client.stream(
            "GET", url, headers={"Accept": "application/rdap+json, application/json"}
        ) as response:
            response.raise_for_status()
            self._validate_endpoint(str(response.url))
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise RuntimeError("RDAP response exceeded size limit")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise RuntimeError("RDAP response must be a JSON object")
        return value

    @staticmethod
    def _validate_endpoint(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise RuntimeError("RDAP endpoint must be credential-free HTTPS")
        if parsed.port not in {None, 443}:
            raise RuntimeError("RDAP endpoint uses a disallowed port")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
                raise RuntimeError("RDAP endpoint host is disallowed") from None
        else:
            if not address.is_global:
                raise RuntimeError("RDAP endpoint address is not public")

    @classmethod
    def select_domain_service(cls, bootstrap: dict, domain: str) -> str:
        labels = domain.lower().rstrip(".").split(".")
        candidates: list[tuple[int, str]] = []
        for service in bootstrap.get("services", []):
            if not isinstance(service, list) or len(service) != 2:
                continue
            suffixes, urls = service
            for suffix in suffixes:
                normalized = str(suffix).lower().lstrip(".")
                if labels[-len(normalized.split(".")) :] == normalized.split("."):
                    for url in urls:
                        if str(url).startswith("https://"):
                            candidates.append((len(normalized), str(url)))
        if not candidates:
            raise RuntimeError("No RDAP bootstrap service found for domain")
        selected = max(candidates, key=lambda item: item[0])[1]
        cls._validate_endpoint(selected)
        return selected

    def _normalize(self, context: ProviderContext, payload: dict) -> ProviderResult:
        db, job, target = context.db, context.job, context.target
        domain = self._entity(db, job.investigation_id, "domain", target.canonical_value, 100)
        entities = [domain]
        relationships = []
        nameservers = sorted(
            {
                str(item.get("ldhName", "")).lower().rstrip(".")
                for item in payload.get("nameservers", [])
                if item.get("ldhName")
            }
        )
        for hostname in nameservers:
            nameserver = self._entity(db, job.investigation_id, "nameserver", hostname, 98)
            entities.append(nameserver)
            relationships.append(
                self._relationship(
                    db, job.investigation_id, domain.id, "HAS_NAMESERVER", nameserver.id, 98
                )
            )
        statuses = sorted({str(item) for item in payload.get("status", [])})
        events = [
            {"action": item.get("eventAction"), "date": item.get("eventDate")}
            for item in payload.get("events", [])
            if item.get("eventAction") and item.get("eventDate")
        ]
        redacted = {
            "objectClassName": payload.get("objectClassName"),
            "ldhName": payload.get("ldhName", target.canonical_value),
            "handle": payload.get("handle"),
            "status": statuses,
            "events": events,
            "nameservers": nameservers,
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        db.flush()
        return ProviderResult(
            result_count=len(entities),
            entity_ids=tuple(item.id for item in entities),
            relationship_ids=tuple(item.id for item in relationships),
            metadata={"synthetic": False, "target": target.canonical_value},
            response_fingerprint=fingerprint,
            redacted_payload=redacted,
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
