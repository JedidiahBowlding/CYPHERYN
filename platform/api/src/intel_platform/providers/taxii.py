from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from sqlalchemy import select

from ..models import Entity, Investigation
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult
from ..stix_ingest import import_stix_bundle

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


class TaxiiProvider:
    name = "taxii"
    version = "TAXII 2.1"
    available = True
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address", "url"}),
        passive_only=True,
        requires_credentials=True,
    )

    @staticmethod
    def _collection_url(value: str) -> str:
        parsed = urlsplit(value.strip())
        if not parsed.hostname or parsed.username or parsed.password:
            raise RuntimeError("TAXII collection URL must not contain embedded credentials")
        loopback_host = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback_host):
            raise RuntimeError("TAXII collection URL must use HTTPS (HTTP is loopback-only)")
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)
            }
        except (OSError, ValueError) as exc:
            raise RuntimeError("TAXII collection hostname could not be resolved") from exc
        if not addresses or (
            not loopback_host and any(not address.is_global for address in addresses)
        ):
            raise RuntimeError("TAXII collection must resolve only to public addresses")
        if loopback_host and any(not address.is_loopback for address in addresses):
            raise RuntimeError("Local TAXII hostname must resolve only to loopback addresses")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))

    @staticmethod
    def _next_url(url: str, token: str) -> str:
        parsed = urlsplit(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query["next"] = token
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))

    def collect(self, context: ProviderContext) -> ProviderResult:
        collection_url = self._collection_url(str(context.settings.get("collection_url") or ""))
        token = str(
            context.credentials.get("token") or context.credentials.get("api_key") or ""
        ).strip()
        username = str(context.credentials.get("username") or "").strip()
        password = str(context.credentials.get("password") or "")
        if not token and not (username and password):
            raise RuntimeError("TAXII bearer token or username/password is required")
        headers = {"Accept": TAXII_MEDIA_TYPE, "User-Agent": "CYPHERYN-TAXII/1.0"}
        auth = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            auth = httpx.BasicAuth(username, password)

        objects: list[dict] = []
        page_url = collection_url
        pages = 0
        timeout = 20.0
        if context.deadline_at:
            deadline = context.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            timeout = max(1.0, min((deadline - datetime.now(UTC)).total_seconds(), 60.0))
        with httpx.Client(
            headers=headers, auth=auth, timeout=timeout, follow_redirects=False
        ) as client:
            while page_url and pages < 20 and len(objects) < 5000:
                response = client.get(page_url)
                if response.status_code != 200:
                    raise RuntimeError(f"TAXII server returned HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "").lower()
                if "application/taxii+json" not in content_type:
                    raise RuntimeError("TAXII server returned an unexpected content type")
                envelope = response.json()
                page_objects = envelope.get("objects") or []
                if not isinstance(page_objects, list):
                    raise RuntimeError("TAXII envelope has no valid objects array")
                objects.extend(item for item in page_objects if isinstance(item, dict))
                pages += 1
                next_token = str(envelope.get("next") or "").strip()
                page_url = (
                    self._next_url(collection_url, next_token)
                    if envelope.get("more") and next_token
                    else ""
                )

        investigation = context.db.get(Investigation, context.job.investigation_id)
        if investigation is None:
            raise RuntimeError("Investigation no longer exists")
        summary = import_stix_bundle(
            context.db,
            investigation,
            {"type": "bundle", "objects": objects[:5000]},
            source="taxii",
            default_ttl_days=int(context.settings.get("default_ttl_days", 90)),
        )
        stix_ids = [str(item.get("id")) for item in objects if item.get("id")][:5000]
        entity_ids = tuple(
            context.db.scalars(
                select(Entity.id).where(
                    Entity.investigation_id == investigation.id,
                    Entity.canonical_value.in_(stix_ids),
                )
            )
        )
        redacted = {
            "collection": collection_url,
            "pages": pages,
            "object_count": len(objects),
            "object_ids": stix_ids,
            "summary": summary,
        }
        encoded = json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=len(objects),
            entity_ids=entity_ids,
            metadata={"stix_import": summary, "pages": pages},
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload=redacted,
        )
