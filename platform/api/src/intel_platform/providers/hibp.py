from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

import httpx
from sqlalchemy import select

from ..models import Entity
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

API = "https://haveibeenpwned.com/api/v3"


class HibpProvider:
    name = "hibp"
    version = "API v3"
    available = True
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "email_address"}),
        passive_only=True,
        requires_credentials=True,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        key = str(context.credentials.get("api_key") or "").strip()
        if len(key) != 32:
            raise RuntimeError("HIBP API key must be a 32-character subscription key")
        headers = {
            "hibp-api-key": key,
            "user-agent": "CYPHERYN-Defensive-Identity/1.0",
            "accept": "application/json",
        }
        with httpx.Client(headers=headers, timeout=20, follow_redirects=False) as client:
            subscribed = client.get(f"{API}/subscribedDomains")
            if subscribed.status_code != 200:
                raise RuntimeError(
                    f"HIBP subscription verification returned HTTP {subscribed.status_code}"
                )
            verified = {
                str(item.get("DomainName") or "").lower()
                for item in subscribed.json()
                if isinstance(item, dict)
            }
            target = context.target.canonical_value.lower()
            domain = target.rsplit("@", 1)[-1] if "@" in target else target
            if domain not in verified:
                raise RuntimeError("HIBP search requires a domain verified on this subscription")
            if context.target.target_type.value == "email_address":
                breaches = self._email_search(client, target)
                exposed_accounts = 1 if breaches else 0
            else:
                response = client.get(f"{API}/breachedDomain/{quote(domain, safe='')}")
                if response.status_code == 404:
                    domain_results = {}
                elif response.status_code == 200:
                    domain_results = response.json()
                else:
                    raise RuntimeError(f"HIBP domain search returned HTTP {response.status_code}")
                breaches = sorted(
                    {
                        str(name)
                        for names in domain_results.values()
                        if isinstance(names, list)
                        for name in names
                    }
                )
                exposed_accounts = len(domain_results)
        redacted = {
            "query_type": context.target.target_type.value,
            "verified_domain": domain,
            "exposed_account_count": exposed_accounts,
            "breach_count": len(breaches),
            "breaches": breaches[:500],
            "plaintext_passwords_stored": False,
            "breach_contents_stored": False,
        }
        entity = self._entity(context, target, redacted)
        fingerprint = hashlib.sha256(
            json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        return ProviderResult(
            result_count=len(breaches),
            entity_ids=(entity.id,),
            metadata={"breach_count": len(breaches), "exposed_account_count": exposed_accounts},
            response_fingerprint=fingerprint,
            redacted_payload=redacted,
        )

    @staticmethod
    def _email_search(client: httpx.Client, email: str) -> list[str]:
        digest = hashlib.sha1(email.encode(), usedforsecurity=False).hexdigest().upper()
        response = client.get(f"{API}/breachedaccount/range/{digest[:6]}")
        if response.status_code != 200:
            raise RuntimeError(f"HIBP private email search returned HTTP {response.status_code}")
        suffix = digest[6:]
        for item in response.json():
            if str(item.get("hashSuffix") or "").upper() == suffix:
                return sorted({str(name) for name in item.get("websites") or []})
        return []

    def _entity(self, context: ProviderContext, target: str, attributes: dict) -> Entity:
        value = hashlib.sha256(target.encode()).hexdigest()
        entity = context.db.scalar(
            select(Entity).where(
                Entity.investigation_id == context.job.investigation_id,
                Entity.entity_type == "breach_exposure",
                Entity.canonical_value == value,
            )
        )
        safe_attributes = {**attributes, "identifier_sha256": value, "review_status": "unreviewed"}
        if entity is None:
            entity = Entity(
                investigation_id=context.job.investigation_id,
                entity_type="breach_exposure",
                canonical_value=value,
                confidence=100,
                provider=self.name,
                attributes=safe_attributes,
            )
            context.db.add(entity)
            context.db.flush()
        else:
            entity.attributes = safe_attributes
        return entity
