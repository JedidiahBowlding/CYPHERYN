from __future__ import annotations

import enum


class PublicSecurityDecision(enum.StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    QUARANTINE = "QUARANTINE"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"


class PolicyMode(enum.StrEnum):
    SHADOW = "SHADOW"
    ENFORCE = "ENFORCE"


class AgentStatus(enum.StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    QUARANTINED = "QUARANTINED"


class ClientStatus(enum.StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class GrantStatus(enum.StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class DestinationTrust(enum.StrEnum):
    TRUSTED = "TRUSTED"
    APPROVED = "APPROVED"
    UNKNOWN = "UNKNOWN"
    RESTRICTED = "RESTRICTED"
    BLOCKED = "BLOCKED"


class DataClassification(enum.StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PERSONAL = "PERSONAL"
    FINANCIAL = "FINANCIAL"
    AUTHENTICATION_SECRET = "AUTHENTICATION_SECRET"  # noqa: S105 - classification label
    SYSTEM_SECRET = "SYSTEM_SECRET"  # noqa: S105 - classification label
    HIGHLY_RESTRICTED = "HIGHLY_RESTRICTED"


CLASSIFICATION_ALIASES = {
    "public": DataClassification.PUBLIC,
    "internal": DataClassification.INTERNAL,
    "internal_infrastructure": DataClassification.INTERNAL,
    "organization_sensitive": DataClassification.CONFIDENTIAL,
    "confidential": DataClassification.CONFIDENTIAL,
    "personal": DataClassification.PERSONAL,
    "personal_information": DataClassification.PERSONAL,
    "financial": DataClassification.FINANCIAL,
    "financial_data": DataClassification.FINANCIAL,
    "secret": DataClassification.AUTHENTICATION_SECRET,
    "authentication_secret": DataClassification.AUTHENTICATION_SECRET,
    "system_secret": DataClassification.SYSTEM_SECRET,
    "highly_restricted": DataClassification.HIGHLY_RESTRICTED,
    "uninspectable": DataClassification.HIGHLY_RESTRICTED,
}


DEFAULT_CAPABILITIES = (
    "web.read",
    "web.write",
    "email.read",
    "email.send",
    "calendar.read",
    "calendar.write",
    "commerce.search",
    "commerce.purchase",
    "filesystem.read",
    "filesystem.write",
    "database.read",
    "database.write",
    "network.external",
    "code.execute",
    "mcp.invoke",
    "agent.delegate",
    "agent.communicate",
)


def normalize_classifications(values: list[str]) -> list[str]:
    normalized: set[str] = set()
    for value in values:
        classification = CLASSIFICATION_ALIASES.get(str(value).strip().lower())
        if classification is None:
            raise ValueError(f"Unknown data classification: {value}")
        normalized.add(classification.value)
    return sorted(normalized)


def public_decision(value: str) -> str:
    """Map the historical internal BLOCK value to the public DENY contract."""
    return PublicSecurityDecision.DENY.value if value == "BLOCK" else value


def internal_decision(value: str) -> str:
    """Keep existing records and database enums compatible with generic decisions."""
    return "BLOCK" if value == PublicSecurityDecision.DENY.value else value
