from __future__ import annotations

import enum
from datetime import UTC, datetime, timedelta


class ProviderTier(enum.StrEnum):
    SUPPORTED = "supported"
    EXPERIMENTAL = "experimental"
    ADAPTER_ONLY = "adapter_only"
    INHERITED = "inherited"


SUPPORTED_CONTRACT_PROVIDERS = frozenset(
    {"virustotal", "shodan", "alienvault_otx", "censys", "abuse_ch"}
)
INHERITED_PROVIDERS = frozenset({"spiderfoot"})
ADAPTER_ONLY_PROVIDERS = frozenset(
    {
        "masscan",
        "nmap",
        "naabu",
        "nuclei",
        "nikto",
        "zap_active",
        "zap_passive",
        "testssl",
        "katana",
        "katana_authenticated",
        "openvas",
    }
)

VERIFICATION_AGING_AFTER = timedelta(days=7)
VERIFICATION_STALE_AFTER = timedelta(days=30)


def provider_tier(name: str) -> ProviderTier:
    if name in SUPPORTED_CONTRACT_PROVIDERS:
        return ProviderTier.SUPPORTED
    if name in INHERITED_PROVIDERS:
        return ProviderTier.INHERITED
    if name in ADAPTER_ONLY_PROVIDERS:
        return ProviderTier.ADAPTER_ONLY
    return ProviderTier.EXPERIMENTAL


def contract_tested(name: str) -> bool:
    return name in SUPPORTED_CONTRACT_PROVIDERS


def verification_freshness(
    last_verified_at: datetime | None, *, now: datetime | None = None
) -> str:
    if last_verified_at is None:
        return "never_verified"
    current = now or datetime.now(UTC)
    value = last_verified_at if last_verified_at.tzinfo else last_verified_at.replace(tzinfo=UTC)
    age = current - value
    if age >= VERIFICATION_STALE_AFTER:
        return "verification_stale"
    if age >= VERIFICATION_AGING_AFTER:
        return "verification_aging"
    return "live_verified"
