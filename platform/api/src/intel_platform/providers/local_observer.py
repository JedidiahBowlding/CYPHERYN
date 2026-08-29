import hashlib
import ipaddress
import json
import socket
import ssl
from datetime import UTC, datetime

from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

DEFAULT_PORTS = (22, 25, 53, 80, 110, 143, 443, 587, 993, 995, 8080, 8443)


class LocalObserverProvider:
    name = "local_observer"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"ip_address"}),
        passive_only=False,
        requires_credentials=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        address = ipaddress.ip_address(context.target.canonical_value)
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            raise RuntimeError("Local observer target address is not permitted")
        root = self._entity(
            context, "ip_address", context.target.canonical_value, 100, {"synthetic": False}
        )
        entities = [root]
        relationships = []
        observations = []
        for port in DEFAULT_PORTS:
            if self._cancelled_or_expired(context):
                break
            observation = self._observe_port(str(address), port, context)
            if observation is None:
                continue
            service = self._entity(
                context,
                "network_service",
                f"{address}:{port}",
                100,
                {"port": port, "synthetic": False},
            )
            entities.append(service)
            relationships.append(
                self._relationship(context, root.id, "EXPOSES_SERVICE", service.id, 100)
            )
            observations.append(observation)
        context.db.flush()
        redacted = {"target": str(address), "open_services": observations}
        fingerprint = hashlib.sha256(
            json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        return ProviderResult(
            result_count=len(entities),
            entity_ids=tuple(item.id for item in entities),
            relationship_ids=tuple(item.id for item in relationships),
            metadata={"synthetic": False, "active": True},
            response_fingerprint=fingerprint,
            redacted_payload=redacted,
        )

    def _observe_port(self, address: str, port: int, context: ProviderContext) -> dict | None:
        remaining = self._remaining_seconds(context)
        if remaining <= 0:
            return None
        timeout = min(0.75, remaining)
        try:
            with socket.create_connection((address, port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                banner = b""
                if port in {80, 8080}:
                    connection.sendall(b"HEAD / HTTP/1.0\r\nHost: authorized-target\r\n\r\n")
                try:
                    banner = connection.recv(512)
                except (TimeoutError, OSError):
                    pass
                observation = {
                    "port": port,
                    "banner_sha256": hashlib.sha256(banner).hexdigest() if banner else None,
                }
        except (TimeoutError, OSError):
            return None
        if port in {443, 8443}:
            observation["tls"] = self._tls_fingerprint(address, port, timeout)
        return observation

    @staticmethod
    def _tls_fingerprint(address: str, port: int, timeout: float) -> str | None:
        try:
            ssl_context = ssl.create_default_context()
            with socket.create_connection((address, port), timeout=timeout) as raw:
                with ssl_context.wrap_socket(raw, server_hostname=address) as secured:
                    certificate = secured.getpeercert(binary_form=True)
            return hashlib.sha256(certificate).hexdigest() if certificate else None
        except (OSError, ssl.SSLError, TimeoutError):
            return None

    @staticmethod
    def _remaining_seconds(context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 20
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(0, (deadline - datetime.now(UTC)).total_seconds())

    @staticmethod
    def _cancelled_or_expired(context: ProviderContext) -> bool:
        context.db.refresh(context.job)
        return bool(
            context.job.cancellation_requested_at
        ) or not LocalObserverProvider._remaining_seconds(context)

    def _entity(
        self,
        context: ProviderContext,
        entity_type: str,
        value: str,
        confidence: int,
        attributes: dict,
    ) -> Entity:
        entity = context.db.scalar(
            select(Entity).where(
                Entity.investigation_id == context.job.investigation_id,
                Entity.entity_type == entity_type,
                Entity.canonical_value == value,
            )
        )
        if entity is None:
            entity = Entity(
                investigation_id=context.job.investigation_id,
                entity_type=entity_type,
                canonical_value=value,
                confidence=confidence,
                provider=self.name,
                attributes={"classification": "OBSERVED_FACT", **attributes},
            )
            context.db.add(entity)
            context.db.flush()
        return entity

    def _relationship(
        self,
        context: ProviderContext,
        subject_id: str,
        predicate: str,
        object_id: str,
        confidence: int,
    ) -> Relationship:
        relationship = context.db.scalar(
            select(Relationship).where(
                Relationship.investigation_id == context.job.investigation_id,
                Relationship.subject_entity_id == subject_id,
                Relationship.predicate == predicate,
                Relationship.object_entity_id == object_id,
                Relationship.provider == self.name,
            )
        )
        if relationship is None:
            relationship = Relationship(
                investigation_id=context.job.investigation_id,
                subject_entity_id=subject_id,
                predicate=predicate,
                object_entity_id=object_id,
                confidence=confidence,
                provider=self.name,
            )
            context.db.add(relationship)
        return relationship
