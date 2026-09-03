from datetime import UTC, datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .models import Entity, EvidenceChange, Finding, Investigation, Relationship

SEVERITY_WEIGHT = {"critical": 35, "high": 25, "medium": 15, "low": 5, "info": 1}


def finding_risk_domain(finding: Finding) -> str:
    """Classify risk without conflating third-party brand abuse with host compromise."""
    if finding.rule_id.startswith("domain.registered_lookalike"):
        return "brand"
    return "host"


def is_risk_finding(finding: Finding) -> bool:
    """Exclude legacy advisories and scanner diagnostics from vulnerability scoring."""
    rule = finding.rule_id.lower()
    return rule not in {"email.missing_bimi", "nikto.fail"} and not (
        rule.startswith("testssl.")
        and rule.rsplit(".", 1)[-1] in {"scanproblem", "engineproblem"}
    )


def build_analysis(db: Session, investigation: Investigation) -> dict:
    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.investigation_id == investigation.id,
                or_(
                    Finding.status.in_(["open", "acknowledged"]),
                    and_(
                        Finding.status == "risk_accepted",
                        Finding.exception_expires_at <= datetime.now(UTC),
                    ),
                ),
            )
        )
    )
    entities = list(db.scalars(select(Entity).where(Entity.investigation_id == investigation.id)))
    relationships = list(
        db.scalars(select(Relationship).where(Relationship.investigation_id == investigation.id))
    )
    changes = list(
        db.scalars(
            select(EvidenceChange).where(
                EvidenceChange.investigation_id == investigation.id,
                EvidenceChange.acknowledged_at.is_(None),
            )
        )
    )
    findings = [item for item in findings if is_risk_finding(item)]
    host_findings = [item for item in findings if finding_risk_domain(item) == "host"]
    brand_findings = [item for item in findings if finding_risk_domain(item) == "brand"]
    score = sum(SEVERITY_WEIGHT.get(item.severity.lower(), 3) for item in host_findings)
    score += min(15, len(changes) * 3)
    malicious_records = []
    public_services = []
    for entity in entities:
        attributes = entity.attributes or {}
        if entity.entity_type == "intelligence_record" and (
            int((attributes.get("analysis_stats") or {}).get("malicious", 0)) > 0
            or int(attributes.get("pulse_count", 0)) > 0
            or int(attributes.get("match_count", 0)) > 0
        ):
            malicious_records.append(entity)
        if entity.entity_type == "network_service":
            public_services.append(entity)
    score += min(25, len(malicious_records) * 10)
    score = min(100, score)
    brand_score = min(
        100,
        sum(SEVERITY_WEIGHT.get(item.severity.lower(), 3) for item in brand_findings),
    )
    brand_level = (
        "critical"
        if brand_score >= 80
        else "high"
        if brand_score >= 60
        else "medium"
        if brand_score >= 30
        else "low"
    )
    level = (
        "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    )

    claims = []
    for finding in findings:
        claims.append(
            {
                "classification": "OBSERVED_FACT",
                "statement": f"{finding.title} affects {finding.asset_value}.",
                "confidence": finding.confidence,
                "evidence": {"finding_id": finding.id, "source_id": finding.source_id},
            }
        )
    for entity in malicious_records:
        claims.append(
            {
                "classification": "OBSERVED_FACT",
                "statement": (
                    f"{entity.provider} reported threat-intelligence activity for "
                    f"{entity.canonical_value}."
                ),
                "confidence": entity.confidence,
                "evidence": {"entity_id": entity.id, "provider": entity.provider},
            }
        )
    correlations = []
    if public_services and malicious_records:
        correlations.append(
            {
                "classification": "DERIVED_ANALYSIS",
                "statement": (
                    "The investigation contains both public service exposure and "
                    "threat-intelligence observations."
                ),
                "confidence": 70,
                "evidence": {
                    "service_entity_ids": [item.id for item in public_services[:20]],
                    "intelligence_entity_ids": [item.id for item in malicious_records[:20]],
                },
                "limitation": "Co-occurrence does not establish causation or compromise.",
            }
        )
    recommendations = []
    for finding in sorted(
        findings, key=lambda item: SEVERITY_WEIGHT.get(item.severity.lower(), 0), reverse=True
    ):
        recommendations.append(
            {
                "priority": finding.severity.lower(),
                "action": f"Review and remediate: {finding.title}",
                "asset": finding.asset_value,
                "evidence": {"finding_id": finding.id},
            }
        )
    if changes:
        recommendations.append(
            {
                "priority": "medium",
                "action": (
                    "Review unacknowledged evidence changes and confirm whether they are expected."
                ),
                "asset": "investigation",
                "evidence": {"change_ids": [item.id for item in changes[:50]]},
            }
        )
    summary = (
        f"Host-compromise risk is {level} ({score}/100); external brand risk is "
        f"{brand_level} ({brand_score}/100). Analysis is based on {len(findings)} active findings, "
        f"{len(entities)} entities, {len(relationships)} relationships, and "
        f"{len(changes)} unacknowledged changes."
    )
    return {
        "risk_score": score,
        "risk_level": level,
        "title": f"{investigation.name} risk assessment",
        "executive_summary": summary,
        "claims": claims[:100],
        "correlations": correlations,
        "recommendations": recommendations[:50],
        "metrics": {
            "active_findings": len(findings),
            "host_findings": len(host_findings),
            "brand_findings": len(brand_findings),
            "brand_risk_score": brand_score,
            "brand_risk_level": brand_level,
            "entities": len(entities),
            "relationships": len(relationships),
            "unacknowledged_changes": len(changes),
            "public_services": len(public_services),
            "threat_records": len(malicious_records),
        },
    }
