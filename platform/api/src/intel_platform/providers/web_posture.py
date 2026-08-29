import hashlib
import ipaddress
import json
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlsplit

import certifi
import httpx
from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class WebPostureProvider:
    name = "web_posture"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}),
        passive_only=False,
        requires_credentials=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        host = self._host(context.target.canonical_value)
        self._require_public_host(host)
        timeout = self._remaining_timeout(context)
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            http_response = client.head(f"http://{host}/")
            https_response = client.head(f"https://{host}/")
            if https_response.status_code in {405, 501}:
                with client.stream("GET", f"https://{host}/") as response:
                    https_status = response.status_code
                    https_headers = response.headers
            else:
                https_status = https_response.status_code
                https_headers = https_response.headers
        certificate = self._certificate(host, timeout)
        observations = {
            "host": host,
            "http": {
                "status": http_response.status_code,
                "location": http_response.headers.get("location"),
            },
            "https": {
                "status": https_status,
                "headers": self._security_headers(https_headers),
                "cookies": self._cookie_posture(https_headers.get_list("set-cookie")),
            },
            "certificate": certificate,
        }
        return self.normalize(context, observations)

    @staticmethod
    def _host(value: str) -> str:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        if not parsed.hostname:
            raise RuntimeError("Web posture target has no hostname")
        return parsed.hostname.lower()

    @staticmethod
    def _require_public_host(host: str) -> None:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
        if not addresses:
            raise RuntimeError("Web posture target did not resolve")
        for value in addresses:
            if not ipaddress.ip_address(value).is_global:
                raise RuntimeError("Web posture target resolves to a non-public address")

    @staticmethod
    def _remaining_timeout(context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 10.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, min(15.0, (deadline - datetime.now(UTC)).total_seconds()))

    @staticmethod
    def _certificate(host: str, timeout: float) -> dict:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((host, 443), timeout=timeout) as raw_socket:
            with ssl_context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
        names = sorted(
            value for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"
        )
        not_after = certificate.get("notAfter")
        expires_at = (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC).isoformat()
            if not_after
            else None
        )
        issuer = {key: value for group in certificate.get("issuer", []) for key, value in group}
        return {"expires_at": expires_at, "issuer": issuer, "dns_names": names[:200]}

    @staticmethod
    def _security_headers(headers: httpx.Headers) -> dict:
        names = (
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        )
        return {name: headers.get(name) for name in names}

    @staticmethod
    def _cookie_posture(values: list[str]) -> list[dict]:
        results = []
        for value in values[:50]:
            name = value.split("=", 1)[0].strip()[:100]
            lower = value.lower()
            results.append(
                {
                    "name": name,
                    "secure": "; secure" in lower,
                    "http_only": "; httponly" in lower,
                    "same_site": "samesite=" in lower,
                }
            )
        return results

    def normalize(self, context: ProviderContext, observations: dict) -> ProviderResult:
        db, job = context.db, context.job
        host = observations["host"]
        root = self._entity(db, job.investigation_id, "domain", host, 100)
        posture = self._entity(
            db,
            job.investigation_id,
            "web_posture",
            f"web_posture:{host}",
            95,
            observations,
        )
        relationship = self._relationship(
            db, job.investigation_id, root.id, "HAS_WEB_POSTURE", posture.id, 95
        )
        findings = self._finding_candidates(observations)
        fingerprint = hashlib.sha256(
            json.dumps(observations, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        db.flush()
        return ProviderResult(
            result_count=2,
            entity_ids=(root.id, posture.id),
            relationship_ids=(relationship.id,),
            metadata={
                "synthetic": False,
                "target": host,
                "finding_candidates": findings,
            },
            response_fingerprint=fingerprint,
            redacted_payload=observations,
        )

    @staticmethod
    def _finding_candidates(observations: dict) -> list[dict]:
        host = observations["host"]
        candidates = []
        location = str(observations["http"].get("location") or "")
        if not location.lower().startswith("https://"):
            candidates.append(
                {
                    "rule_id": "web.http_without_https_redirect",
                    "title": "HTTP does not redirect to HTTPS",
                    "description": (
                        "The HTTP endpoint did not return an HTTPS redirect. "
                        "Confirm whether plaintext access is intentional."
                    ),
                    "severity": "medium",
                    "confidence": 90,
                    "asset_value": host,
                    "entity_value": f"web_posture:{host}",
                }
            )
        headers = observations["https"]["headers"]
        rules = (
            ("strict-transport-security", "web.missing_hsts", "Missing HSTS header", "medium"),
            (
                "content-security-policy",
                "web.missing_csp",
                "Missing Content Security Policy",
                "low",
            ),
            (
                "x-content-type-options",
                "web.missing_nosniff",
                "Missing MIME-sniffing protection",
                "low",
            ),
        )
        for header, rule_id, title, severity in rules:
            if not headers.get(header):
                candidates.append(
                    {
                        "rule_id": rule_id,
                        "title": title,
                        "description": f"The HTTPS response did not include the {header} header.",
                        "severity": severity,
                        "confidence": 95,
                        "asset_value": host,
                        "entity_value": f"web_posture:{host}",
                    }
                )
        expires_at = observations["certificate"].get("expires_at")
        if expires_at:
            remaining = datetime.fromisoformat(expires_at) - datetime.now(UTC)
            if remaining.days <= 30:
                candidates.append(
                    {
                        "rule_id": "tls.certificate_expiring",
                        "title": "TLS certificate expires soon",
                        "description": f"The certificate expires in {remaining.days} days.",
                        "severity": "high" if remaining.days <= 7 else "medium",
                        "confidence": 100,
                        "asset_value": host,
                        "entity_value": f"web_posture:{host}",
                    }
                )
        return candidates

    def _entity(
        self,
        db,
        investigation_id: str,
        entity_type: str,
        value: str,
        confidence: int,
        attributes: dict | None = None,
    ):
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
