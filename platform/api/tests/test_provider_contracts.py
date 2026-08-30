from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from intel_platform.provider_certification import SUPPORTED_CONTRACT_PROVIDERS
from intel_platform.provider_contract import (
    ProviderCancelledError,
    ProviderContext,
    ProviderHttpError,
)
from intel_platform.providers.threat_intel import (
    AbuseChProvider,
    AlienVaultOtxProvider,
    CensysProvider,
    ShodanProvider,
    ThreatIntelProvider,
    VirusTotalProvider,
)
from intel_platform.security_controls import redact_payload


@dataclass(frozen=True)
class ContractCase:
    provider: ThreatIntelProvider
    target_type: str
    value: str
    credentials: dict
    payload: dict
    malformed_payload: dict
    expected_kind: str
    expected_predicate: str | None


CASES = (
    ContractCase(
        VirusTotalProvider(),
        "domain",
        "example.test",
        {"api_key": "vt-contract-secret"},
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 3, "harmless": 12},
                    "categories": {"engine": "phishing"},
                }
            }
        },
        {"data": []},
        "virustotal_verdict",
        None,
    ),
    ContractCase(
        ShodanProvider(),
        "ip_address",
        "203.0.113.10",
        {"api_key": "shodan-contract-secret"},
        {
            "ip_str": "203.0.113.10",
            "ports": [443, 22],
            "vulns": ["CVE-2025-0001"],
            "org": "Example Network",
            "asn": "AS64500",
        },
        {"ports": "443"},
        "shodan_host_summary",
        "MAY_BE_AFFECTED_BY",
    ),
    ContractCase(
        AlienVaultOtxProvider(),
        "domain",
        "example.test",
        {"api_key": "otx-contract-secret"},
        {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {
                        "id": "pulse-1",
                        "name": "Contract pulse",
                        "malware_families": ["TestRat"],
                    }
                ],
            }
        },
        {"pulse_info": []},
        "otx_pulse_summary",
        "ASSOCIATED_WITH_MALWARE",
    ),
    ContractCase(
        CensysProvider(),
        "ip_address",
        "203.0.113.10",
        {"personal_access_token": "censys-contract-secret"},
        {
            "result": {
                "resource": {
                    "ip": "203.0.113.10",
                    "services": [
                        {"port": 22, "transport_protocol": "tcp", "protocol": "ssh"}
                    ],
                }
            }
        },
        {"result": {"resource": []}},
        "censys_host_summary",
        "EXPOSES_SERVICE",
    ),
    ContractCase(
        AbuseChProvider(),
        "domain",
        "example.test",
        {"auth_key": "abuse-contract-secret"},
        {
            "query_status": "ok",
            "data": [
                {
                    "id": "42",
                    "ioc": "example.test",
                    "malware_printable": "TestRat",
                    "confidence_level": 90,
                }
            ],
        },
        {"query_status": "ok", "data": {}},
        "threatfox_summary",
        "MATCHED_THREAT_RECORD",
    ),
)


class FakeDb:
    def __init__(self) -> None:
        self.items = []

    def scalar(self, _query):
        return None

    def add(self, item) -> None:
        if item.id is None:
            item.id = str(uuid4())
        self.items.append(item)

    def flush(self) -> None:
        return None


def context(case: ContractCase, *, cancelled: bool = False) -> ProviderContext:
    return ProviderContext(
        db=FakeDb(),
        job=SimpleNamespace(
            investigation_id="investigation",
            provider=case.provider.name,
            cancellation_requested_at=datetime.now(UTC) if cancelled else None,
        ),
        target=SimpleNamespace(
            target_type=SimpleNamespace(value=case.target_type), canonical_value=case.value
        ),
        credentials=case.credentials,
        deadline_at=datetime.now(UTC) + timedelta(seconds=10),
    )


def install_transport(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    original = httpx.Client
    monkeypatch.setattr(
        "intel_platform.providers.threat_intel.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )


def collect_response(monkeypatch: pytest.MonkeyPatch, case: ContractCase, response_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return response_factory(request)

    install_transport(monkeypatch, handler)
    return case.provider.collect(context(case))


def test_certification_matrix_exactly_covers_every_supported_provider() -> None:
    names = {case.provider.name for case in CASES}
    assert names == SUPPORTED_CONTRACT_PROVIDERS
    assert len(names) == len(CASES)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_request_contract(case: ContractCase) -> None:
    request = case.provider.build_request(context(case))
    serialized = repr(request)
    secret = next(iter(case.credentials.values()))
    assert request["url"].startswith("https://")
    assert case.value in serialized
    assert secret in serialized
    assert secret not in request["url"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_rejects_missing_credentials(case: ContractCase) -> None:
    current = context(case)
    missing = ProviderContext(
        db=current.db,
        job=current.job,
        target=current.target,
        credentials={},
        deadline_at=current.deadline_at,
    )
    with pytest.raises(RuntimeError, match="credential|token"):
        case.provider.build_request(missing)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
@pytest.mark.parametrize("status_code", (401, 403, 429))
def test_supported_provider_rejects_auth_and_throttle_failures(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase, status_code: int
) -> None:
    with pytest.raises(ProviderHttpError) as caught:
        collect_response(
            monkeypatch,
            case,
            lambda request: httpx.Response(
                status_code, request=request, json={"error": "provider rejected request"}
            ),
        )
    assert caught.value.status_code == status_code
    assert next(iter(case.credentials.values())) not in str(caught.value)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_rejects_non_json_response(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    with pytest.raises(RuntimeError, match="not valid JSON"):
        collect_response(
            monkeypatch,
            case,
            lambda request: httpx.Response(200, request=request, content=b"not-json"),
        )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_rejects_malformed_schema(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    with pytest.raises(RuntimeError, match="schema is invalid"):
        collect_response(
            monkeypatch,
            case,
            lambda request: httpx.Response(200, request=request, json=case.malformed_payload),
        )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_propagates_transport_timeout(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(httpx.ReadTimeout):
        collect_response(monkeypatch, case, timeout)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_honors_cancellation_before_network_io(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    monkeypatch.setattr(
        "intel_platform.providers.threat_intel.httpx.Client",
        lambda **_kwargs: pytest.fail("cancelled collection must not create a client"),
    )
    with pytest.raises(ProviderCancelledError, match="cancelled"):
        case.provider.collect(context(case, cancelled=True))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_honors_cancellation_during_streaming(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    current = context(case)

    class CancellingStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"partial":'
            current.job.cancellation_requested_at = datetime.now(UTC)
            yield b"true}"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, stream=CancellingStream())

    install_transport(monkeypatch, handler)
    with pytest.raises(ProviderCancelledError, match="cancelled"):
        case.provider.collect(current)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_rejects_expired_deadline_before_network_io(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    current = context(case)
    expired = ProviderContext(
        db=current.db,
        job=current.job,
        target=current.target,
        credentials=current.credentials,
        deadline_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    monkeypatch.setattr(
        "intel_platform.providers.threat_intel.httpx.Client",
        lambda **_kwargs: pytest.fail("expired collection must not create a client"),
    )
    with pytest.raises(TimeoutError, match="deadline expired"):
        case.provider.collect(expired)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.provider.name)
def test_supported_provider_success_normalizes_redacts_and_preserves_provenance(
    monkeypatch: pytest.MonkeyPatch, case: ContractCase
) -> None:
    result = collect_response(
        monkeypatch,
        case,
        lambda request: httpx.Response(200, request=request, json=case.payload),
    )
    secret = next(iter(case.credentials.values()))
    secured = redact_payload(result.redacted_payload)
    summary = secured["summary"]

    assert summary["kind"] == case.expected_kind
    assert secured["provider"] == case.provider.name
    assert secured["target_type"] == case.target_type
    assert secured["target"] == case.value
    assert result.metadata["synthetic"] is False
    assert result.metadata["target"] == case.value
    assert result.result_count >= 2
    assert len(result.response_fingerprint or "") == 64
    assert secret not in repr(secured)
    if case.expected_predicate:
        assert case.expected_predicate in {
            association["predicate"] for association in secured["associations"]
        }
