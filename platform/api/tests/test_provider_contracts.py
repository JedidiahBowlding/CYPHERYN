from types import SimpleNamespace

import httpx
import pytest

from intel_platform.provider_contract import ProviderContext
from intel_platform.providers.threat_intel import (
    AbuseChProvider,
    AlienVaultOtxProvider,
    CensysProvider,
    ShodanProvider,
    VirusTotalProvider,
)


def context(
    target_type: str = "domain",
    value: str = "example.test",
    credentials: dict | None = None,
) -> ProviderContext:
    return ProviderContext(
        db=SimpleNamespace(),
        job=SimpleNamespace(investigation_id="investigation", provider="test"),
        target=SimpleNamespace(
            target_type=SimpleNamespace(value=target_type), canonical_value=value
        ),
        credentials=credentials or {},
    )


@pytest.mark.parametrize(
    ("provider", "target_type", "value", "credentials"),
    [
        (VirusTotalProvider(), "domain", "example.test", {"api_key": "secret"}),
        (ShodanProvider(), "ip_address", "203.0.113.10", {"api_key": "secret"}),
        (AlienVaultOtxProvider(), "domain", "example.test", {"api_key": "secret"}),
        (
            CensysProvider(),
            "ip_address",
            "203.0.113.10",
            {"personal_access_token": "secret"},
        ),
        (AbuseChProvider(), "domain", "example.test", {"auth_key": "secret"}),
    ],
)
def test_priority_provider_requests_keep_credentials_out_of_urls(
    provider, target_type: str, value: str, credentials: dict
) -> None:
    request = provider.build_request(context(target_type, value, credentials))
    assert request["url"].startswith("https://")
    assert "secret" not in request["url"]


@pytest.mark.parametrize(
    ("provider", "target_type"),
    [
        (VirusTotalProvider(), "domain"),
        (ShodanProvider(), "ip_address"),
        (AlienVaultOtxProvider(), "domain"),
        (CensysProvider(), "ip_address"),
        (AbuseChProvider(), "domain"),
    ],
)
def test_priority_providers_reject_missing_credentials(provider, target_type: str) -> None:
    with pytest.raises(RuntimeError, match="credential|token"):
        provider.build_request(context(target_type=target_type))


def test_priority_provider_normalizers_extract_security_signal() -> None:
    vt, _ = VirusTotalProvider().extract_intelligence(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}
    )
    otx, otx_associations = AlienVaultOtxProvider().extract_intelligence(
        {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {"id": "pulse-1", "name": "Example", "malware_families": ["TestRat"]}
                ],
            }
        }
    )
    censys, censys_associations = CensysProvider().extract_intelligence(
        {
            "result": {
                "resource": {
                    "ip": "203.0.113.10",
                    "services": [{"port": 22, "transport_protocol": "tcp", "protocol": "ssh"}],
                }
            }
        }
    )
    abuse, abuse_associations = AbuseChProvider().extract_intelligence(
        {
            "data": [
                {
                    "id": "42",
                    "ioc": "example.test",
                    "malware_printable": "TestRat",
                    "confidence_level": 90,
                }
            ]
        }
    )
    assert vt["verdict"] == "malicious_detections"
    assert otx["pulse_count"] == 1 and len(otx_associations) == 2
    assert censys["service_count"] == 1 and censys_associations[0]["value"].endswith(":22/tcp")
    assert abuse["match_count"] == 1 and abuse_associations[0]["confidence"] == 90


@pytest.mark.parametrize("status_code", [401, 403, 429])
def test_provider_http_failures_are_not_treated_as_results(
    monkeypatch: pytest.MonkeyPatch, status_code: int
) -> None:
    original = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, request=request, json={"error": "rejected"})

    monkeypatch.setattr(
        "intel_platform.providers.threat_intel.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    with pytest.raises(httpx.HTTPStatusError):
        VirusTotalProvider().collect(context(credentials={"api_key": "redacted"}))


def test_provider_rejects_malformed_response(monkeypatch: pytest.MonkeyPatch) -> None:
    original = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, json=["not", "an", "object"])

    monkeypatch.setattr(
        "intel_platform.providers.threat_intel.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    with pytest.raises(RuntimeError, match="JSON object"):
        VirusTotalProvider().collect(context(credentials={"api_key": "redacted"}))


def test_provider_timeout_is_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    original = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    monkeypatch.setattr(
        "intel_platform.providers.threat_intel.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    with pytest.raises(httpx.ReadTimeout):
        VirusTotalProvider().collect(context(credentials={"api_key": "redacted"}))
