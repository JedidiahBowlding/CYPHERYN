from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult

MAIGRET = Path(__file__).resolve().parents[4] / "tools" / "maigret-venv" / "bin" / "maigret"


class MaigretProvider:
    name = "maigret"
    version = "0.6.5"
    available = MAIGRET.exists()
    capabilities = ProviderCapabilities(
        target_types=frozenset({"username"}), passive_only=True, requires_credentials=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        if not self.available:
            raise RuntimeError("Maigret is not installed")
        minimum = max(50, min(int(context.settings.get("minimum_confidence", 70)), 95))
        top_sites = max(10, min(int(context.settings.get("top_sites", 50)), 500))
        timeout = 20
        if context.deadline_at:
            deadline = context.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            timeout = max(5, min(int((deadline - datetime.now(UTC)).total_seconds()), 180))
        with tempfile.TemporaryDirectory(prefix="signaltrace-maigret-") as directory:
            command = [
                str(MAIGRET),
                context.target.canonical_value,
                "--top-sites",
                str(top_sites),
                "--timeout",
                "5",
                "--no-recursion",
                "--no-extracting",
                "--no-progressbar",
                "--no-color",
                "--no-autoupdate",
                "-J",
                "simple",
            ]
            try:
                subprocess.run(  # noqa: S603
                    command,
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Maigret lookup timed out") from exc
            reports = list((Path(directory) / "reports").glob("*_simple.json"))
            if not reports:
                raise RuntimeError("Maigret produced no structured report")
            payload = json.loads(reports[0].read_text())

        root = self._entity(
            context,
            "username",
            context.target.canonical_value,
            100,
            {"classification": "USER_SUPPLIED", "review_status": "unreviewed"},
        )
        entities, relationships, candidates = [root], [], []
        for site_name, result in payload.items():
            status = result.get("status") if isinstance(result, dict) else {}
            if not isinstance(status, dict) or status.get("status") != "Claimed":
                continue
            rank = int(result.get("rank") or 999999)
            confidence = 85 if rank <= 100 else 78 if rank <= 1000 else 70
            if result.get("is_similar"):
                confidence -= 20
            if confidence < minimum:
                continue
            url = str(status.get("url") or result.get("url_user") or "")[:1000]
            candidate = self._entity(
                context,
                "identity_profile",
                f"maigret:{site_name}:{context.target.canonical_value}",
                confidence,
                {
                    "source": "maigret",
                    "site": str(site_name)[:150],
                    "profile_url": url,
                    "match_confidence": confidence,
                    "classification": "CANDIDATE_MATCH",
                    "review_status": "unreviewed",
                    "disclaimer": "Candidate only; corroboration is required before attribution.",
                },
            )
            relationship = self._relationship(context, root.id, candidate.id, confidence)
            entities.append(candidate)
            relationships.append(relationship)
            candidates.append({"site": str(site_name)[:150], "url": url, "confidence": confidence})
        redacted = {
            "username": context.target.canonical_value,
            "minimum_confidence": minimum,
            "sites_checked": top_sites,
            "candidate_count": len(candidates),
            "candidates": candidates[:500],
        }
        context.db.flush()
        fingerprint = hashlib.sha256(
            json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        return ProviderResult(
            result_count=len(candidates),
            entity_ids=tuple(entity.id for entity in entities),
            relationship_ids=tuple(item.id for item in relationships),
            metadata={"candidate_count": len(candidates), "minimum_confidence": minimum},
            response_fingerprint=fingerprint,
            redacted_payload=redacted,
        )

    def _entity(self, context, kind, value, confidence, attributes):
        entity = context.db.scalar(
            select(Entity).where(
                Entity.investigation_id == context.job.investigation_id,
                Entity.entity_type == kind,
                Entity.canonical_value == value,
            )
        )
        if entity is None:
            entity = Entity(
                investigation_id=context.job.investigation_id,
                entity_type=kind,
                canonical_value=value,
                confidence=confidence,
                provider=self.name,
                attributes=attributes,
            )
            context.db.add(entity)
            context.db.flush()
        else:
            entity.confidence = confidence
            entity.attributes = attributes
        return entity

    def _relationship(self, context, subject_id, object_id, confidence):
        relationship = context.db.scalar(
            select(Relationship).where(
                Relationship.investigation_id == context.job.investigation_id,
                Relationship.subject_entity_id == subject_id,
                Relationship.predicate == "CANDIDATE_MATCH",
                Relationship.object_entity_id == object_id,
                Relationship.provider == self.name,
            )
        )
        if relationship is None:
            relationship = Relationship(
                investigation_id=context.job.investigation_id,
                subject_entity_id=subject_id,
                predicate="CANDIDATE_MATCH",
                object_entity_id=object_id,
                claim_class="CANDIDATE_MATCH",
                confidence=confidence,
                provider=self.name,
            )
            context.db.add(relationship)
        return relationship
