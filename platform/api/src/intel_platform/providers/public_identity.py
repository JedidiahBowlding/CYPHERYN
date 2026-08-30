import hashlib
import json
import re
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

API_ROOT = "https://api.github.com"
MAX_CANDIDATES = 5


class PublicIdentityProvider:
    """Passive public-profile lookup with deliberately conservative identity claims."""

    name = "public_identity"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"person", "username", "organization"}),
        passive_only=True,
        requires_credentials=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        timeout = self._remaining_timeout(context)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "CYPHERYN-Defensive-OSINT/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        target_type = context.target.target_type.value
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=False) as client:
            if target_type == "username":
                response = client.get(
                    f"{API_ROOT}/users/{quote(context.target.canonical_value, safe='')}"
                )
                if response.status_code == 404:
                    profiles = []
                else:
                    response.raise_for_status()
                    profiles = [self._profile(response.json())]
            else:
                qualifier = " type:org" if target_type == "organization" else " type:user"
                response = client.get(
                    f"{API_ROOT}/search/users",
                    params={
                        "q": f"{context.target.canonical_value} in:fullname{qualifier}",
                        "per_page": MAX_CANDIDATES,
                    },
                )
                response.raise_for_status()
                items = response.json().get("items", [])[:MAX_CANDIDATES]
                profiles = []
                for item in items:
                    detail = client.get(f"{API_ROOT}/users/{quote(str(item['login']), safe='')}")
                    detail.raise_for_status()
                    profiles.append(self._profile(detail.json()))
        return self.normalize(context, profiles)

    @staticmethod
    def _remaining_timeout(context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 15.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, min(20.0, (deadline - datetime.now(UTC)).total_seconds()))

    @staticmethod
    def _profile(payload: dict) -> dict:
        return {
            "source": "github",
            "login": str(payload.get("login", ""))[:100],
            "display_name": str(payload.get("name") or "")[:200] or None,
            "account_type": str(payload.get("type", ""))[:50],
            "profile_url": str(payload.get("html_url", ""))[:500],
            "company": str(payload.get("company") or "")[:200] or None,
            "location": str(payload.get("location") or "")[:200] or None,
            "bio": str(payload.get("bio") or "")[:500] or None,
            "public_repositories": int(payload.get("public_repos") or 0),
            "followers": int(payload.get("followers") or 0),
            "created_at": payload.get("created_at"),
        }

    @classmethod
    def confidence_for(cls, target_type: str, query: str, profile: dict) -> int:
        query_key = cls._key(query)
        login_key = cls._key(str(profile.get("login") or ""))
        name_key = cls._key(str(profile.get("display_name") or ""))
        if target_type == "username":
            return 98 if query_key == login_key else 55
        if query_key and query_key == name_key:
            return 78
        query_tokens, name_tokens = set(query_key.split()), set(name_key.split())
        overlap = len(query_tokens & name_tokens) / max(1, len(query_tokens | name_tokens))
        return max(35, min(70, round(35 + overlap * 35)))

    @staticmethod
    def _key(value: str) -> str:
        return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))

    def normalize(self, context: ProviderContext, profiles: list[dict]) -> ProviderResult:
        db, job, target = context.db, context.job, context.target
        root = self._entity(
            db,
            job.investigation_id,
            target.target_type.value,
            target.canonical_value,
            100,
            {"classification": "USER_SUPPLIED", "synthetic": False},
        )
        entities = [root]
        relationships = []
        redacted_profiles = []
        for profile in profiles[:MAX_CANDIDATES]:
            if not profile.get("login"):
                continue
            confidence = self.confidence_for(
                target.target_type.value, target.canonical_value, profile
            )
            attributes = {
                **profile,
                "classification": "CANDIDATE_MATCH",
                "synthetic": False,
                "match_confidence": confidence,
                "match_basis": (
                    "exact public username"
                    if target.target_type.value == "username"
                    else "public profile name"
                ),
                "disclaimer": (
                    "Candidate only; corroboration is required before identity attribution."
                ),
            }
            candidate = self._entity(
                db,
                job.investigation_id,
                "identity_profile",
                f"github:{profile['login']}",
                confidence,
                attributes,
            )
            relationship = self._relationship(
                db, job.investigation_id, root.id, candidate.id, confidence
            )
            entities.append(candidate)
            relationships.append(relationship)
            redacted_profiles.append({**profile, "match_confidence": confidence})
        redacted = {
            "query": target.canonical_value,
            "query_type": target.target_type.value,
            "candidate_count": len(redacted_profiles),
            "candidates": redacted_profiles,
            "claim_class": "CANDIDATE_MATCH",
        }
        fingerprint = hashlib.sha256(
            json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        db.flush()
        return ProviderResult(
            result_count=len(entities),
            entity_ids=tuple(item.id for item in entities),
            relationship_ids=tuple(item.id for item in relationships),
            metadata={"synthetic": False, "candidate_count": len(redacted_profiles)},
            response_fingerprint=fingerprint,
            redacted_payload=redacted,
        )

    def _entity(self, db, investigation_id, entity_type, value, confidence, attributes):
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
                attributes=attributes,
            )
            db.add(entity)
            db.flush()
        else:
            entity.confidence = confidence
            entity.attributes = attributes
        return entity

    def _relationship(self, db, investigation_id, subject_id, object_id, confidence):
        relationship = db.scalar(
            select(Relationship).where(
                Relationship.investigation_id == investigation_id,
                Relationship.subject_entity_id == subject_id,
                Relationship.predicate == "CANDIDATE_MATCH",
                Relationship.object_entity_id == object_id,
                Relationship.provider == self.name,
            )
        )
        if relationship is None:
            relationship = Relationship(
                investigation_id=investigation_id,
                subject_entity_id=subject_id,
                predicate="CANDIDATE_MATCH",
                object_entity_id=object_id,
                claim_class="CANDIDATE_MATCH",
                confidence=confidence,
                provider=self.name,
            )
            db.add(relationship)
        else:
            relationship.confidence = confidence
        return relationship
