import shutil
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from intel_platform.auth import Principal, get_principal
from intel_platform.local_ai import (
    LocalNarrativeError,
    correct_unambiguous_indicators,
    generate_local_narrative,
    strip_unsupported_security_sentences,
    validate_narrative,
)
from intel_platform.main import app
from intel_platform.models import (
    AnalysisSnapshot,
    Entity,
    Finding,
    ProviderConfiguration,
    ProviderRuntimeState,
)
from intel_platform.provider_contract import ProviderResult, registry
from intel_platform.provider_secrets import decrypt_credentials, encrypt_credentials
from intel_platform.providers.certificate_transparency import CertificateTransparencyProvider
from intel_platform.providers.public_identity import PublicIdentityProvider
from intel_platform.providers.rdap import RdapProvider
from intel_platform.providers.threat_intel import (
    AbuseChProvider,
    AlienVaultOtxProvider,
    CensysProvider,
    VirusTotalProvider,
)
from intel_platform.worker import compare_redacted_payloads, enqueue_due_schedules, process_one


def create_org(client: TestClient, name: str = "Example Security") -> dict:
    response = client.post("/api/v1/organizations", json={"name": name})
    assert response.status_code == 201
    return response.json()


def test_health(client: TestClient) -> None:
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_organization_is_tenant_scoped(client: TestClient) -> None:
    organization = create_org(client)
    assert [item["id"] for item in client.get("/api/v1/organizations").json()] == [
        organization["id"]
    ]

    app.dependency_overrides[get_principal] = lambda: Principal(subject="outsider")
    assert client.post(
        "/api/v1/legal/acceptance",
        json={
            "accepted": True,
            "terms_version": "1.0",
            "responsible_use_version": "1.0",
        },
    ).status_code == 200
    assert client.get("/api/v1/organizations").json() == []
    hidden = client.get(f"/api/v1/organizations/{organization['id']}/investigations")
    assert hidden.status_code == 404


def test_authorized_target_is_canonicalized_and_deduplicated(client: TestClient) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "External attack surface", "description": "Authorized assets"},
    ).json()
    now = datetime.now(UTC)
    authorization_response = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Written authorization held by security team",
            "passive_allowed": True,
            "active_allowed": False,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=30)).isoformat(),
        },
    )
    assert authorization_response.status_code == 201
    authorization = authorization_response.json()

    target_response = client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "EXAMPLE.COM.",
            "include_descendants": True,
        },
    )
    assert target_response.status_code == 201
    assert target_response.json()["canonical_value"] == "example.com"

    duplicate = client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.com",
        },
    )
    assert duplicate.status_code == 409


def test_expired_authorization_rejects_target(client: TestClient) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Expired scope"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Historical authorization only",
            "passive_allowed": True,
            "valid_from": (now - timedelta(days=2)).isoformat(),
            "valid_until": (now - timedelta(days=1)).isoformat(),
        },
    ).json()
    response = client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.com",
        },
    )
    assert response.status_code == 422


def test_safe_mock_collection_builds_evidence_graph(client: TestClient) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Mock collector contract"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Authorized integration test scope",
            "passive_allowed": True,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    ).json()
    target = client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.com",
        },
    ).json()

    job = client.post(f"/api/v1/investigations/{investigation['id']}/collect")
    assert job.status_code == 202
    assert job.json()["status"] == "queued"
    assert job.json()["attempt"] == 0

    completed = process_one("test-worker", client.app.state.testing_session)
    assert completed is not None
    assert completed.status.value == "completed"
    assert completed.result_count == 4
    assert completed.attempt == 1

    listed_investigations = client.get(
        f"/api/v1/organizations/{organization['id']}/investigations"
    ).json()
    assert listed_investigations[0]["id"] == investigation["id"]
    assert listed_investigations[0]["last_scanned_at"] is not None

    workspace = client.get(f"/api/v1/investigations/{investigation['id']}/workspace")
    assert workspace.status_code == 200
    assert len(workspace.json()["entities"]) == 4
    assert len(workspace.json()["relationships"]) == 3
    assert {item["claim_class"] for item in workspace.json()["relationships"]} == {"OBSERVED_FACT"}
    assert [event["event_type"] for event in reversed(workspace.json()["job_events"])] == [
        "queued",
        "claimed",
        "completed",
    ]
    assert len(workspace.json()["evidence_sources"]) == 1
    assert len(workspace.json()["claim_observations"]) == 7
    source = workspace.json()["evidence_sources"][0]
    assert source["authorization_id"] == authorization["id"]
    assert len(source["raw_response_hash"]) == 64
    assert len(source["integrity_hash"]) == 64
    assert source["previous_integrity_hash"] is None
    assert source["redaction_policy"] == "central-default-v2"
    assert source["provider_version"]
    assert source["ruleset_version"]
    monitor = client.post(
        f"/api/v1/investigations/{investigation['id']}/monitors",
        json={"target_id": target["id"], "provider": "safe_mock", "interval_minutes": 5},
    )
    assert monitor.status_code == 201
    assert enqueue_due_schedules(client.app.state.testing_session) == 1
    scheduled = process_one("test-worker", client.app.state.testing_session)
    assert scheduled is not None and scheduled.status.value == "completed"
    monitored_workspace = client.get(
        f"/api/v1/investigations/{investigation['id']}/workspace"
    ).json()
    assert len(monitored_workspace["monitor_schedules"]) == 1
    assert monitored_workspace["monitor_schedules"][0]["last_job_id"] == scheduled.id
    assert monitored_workspace["evidence_changes"] == []
    analysis = client.post(f"/api/v1/investigations/{investigation['id']}/analysis")
    assert analysis.status_code == 201
    assert analysis.json()["risk_level"] == "low"
    assert analysis.json()["metrics"]["entities"] == 4
    analyzed_workspace = client.get(
        f"/api/v1/investigations/{investigation['id']}/workspace"
    ).json()
    # Scheduled monitoring produces a fresh analysis automatically; the explicit
    # request above creates a second retained snapshot.
    assert len(analyzed_workspace["analysis_snapshots"]) == 2
    report = client.get(f"/api/v1/investigations/{investigation['id']}/reports/pdf?style=technical")
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert report.content.startswith(b"%PDF-")


def test_redacted_evidence_comparison_is_bounded_and_field_based() -> None:
    change = compare_redacted_payloads(
        {"records": {"A": ["192.0.2.1"]}, "status": "ok"},
        {"records": {"A": ["192.0.2.2"]}, "status": "ok", "new": True},
    )
    assert change["changed_field_count"] == 2
    assert {item["field"] for item in change["changed_fields"]} == {"new", "records"}


def test_stix_import_correlates_active_indicators_and_suppresses_expired(
    client: TestClient,
) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "STIX correlation"},
    ).json()
    with client.app.state.testing_session() as session:
        session.add(
            Entity(
                investigation_id=investigation["id"],
                entity_type="domain",
                canonical_value="example.com",
                confidence=100,
                provider="test",
                attributes={},
            )
        )
        session.commit()
    now = datetime.now(UTC)
    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--11111111-1111-4111-8111-111111111111",
                "name": "Active domain indicator",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'example.com']",
                "valid_from": (now - timedelta(days=1)).isoformat(),
                "valid_until": (now + timedelta(days=1)).isoformat(),
                "confidence": 85,
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "name": "Expired domain indicator",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'example.com']",
                "valid_from": (now - timedelta(days=10)).isoformat(),
                "valid_until": (now - timedelta(days=2)).isoformat(),
                "confidence": 90,
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--33333333-3333-4333-8333-333333333333",
                "name": "Example malware",
                "is_family": True,
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--44444444-4444-4444-8444-444444444444",
                "relationship_type": "indicates",
                "source_ref": "indicator--11111111-1111-4111-8111-111111111111",
                "target_ref": "malware--33333333-3333-4333-8333-333333333333",
            },
        ],
    }
    response = client.post(
        f"/api/v1/investigations/{investigation['id']}/stix/import",
        json={"bundle": bundle, "source": "test-feed", "default_ttl_days": 90},
    )
    assert response.status_code == 200
    assert response.json()["active_indicators"] == 1
    assert response.json()["expired_indicators"] == 1
    assert response.json()["correlations"] == 1
    active = client.get(f"/api/v1/organizations/{organization['id']}/threat-intelligence").json()
    assert {item["name"] for item in active} == {
        "Active domain indicator",
        "Example malware",
    }


def test_redacted_evidence_comparison_ignores_provider_timestamps() -> None:
    change = compare_redacted_payloads(
        {
            "services": [{"port": 443, "scan_time": "2026-01-01T00:00:00Z"}],
            "events": [
                {"action": "registration", "date": "2025-01-01T00:00:00Z"},
                {"action": "last update of RDAP database", "date": "2026-01-01T00:00:00Z"},
            ],
        },
        {
            "services": [{"port": 443, "scan_time": "2026-01-02T00:00:00Z"}],
            "events": [
                {"action": "registration", "date": "2025-01-01T00:00:00Z"},
                {"action": "last update of RDAP database", "date": "2026-01-02T00:00:00Z"},
            ],
        },
    )
    assert change["changed_field_count"] == 0


def test_finding_verification_requires_two_clean_observations(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Finding verification"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Authorized finding verification test",
            "passive_allowed": True,
            "active_allowed": True,
            "active_scope_confirmed": True,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    ).json()
    client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "verify.example",
        },
    ).json()
    seed_job = client.post(f"/api/v1/investigations/{investigation['id']}/collect").json()
    assert process_one("seed-worker", client.app.state.testing_session).id == seed_job["id"]
    workspace = client.get(f"/api/v1/investigations/{investigation['id']}/workspace").json()
    with client.app.state.testing_session() as db:
        finding = Finding(
            investigation_id=investigation["id"],
            source_id=workspace["evidence_sources"][0]["id"],
            rule_id="TEST_EXPOSURE",
            title="Test exposure",
            description="Verification lifecycle test",
            severity="medium",
            confidence=90,
            asset_value="8.8.8.8:443/tcp",
            provider="safe_mock",
        )
        db.add(finding)
        db.commit()
        finding_id = finding.id
    direct = registry.get("direct_verifier")
    monkeypatch.setattr(
        direct,
        "collect",
        lambda context: ProviderResult(
            result_count=1,
            metadata={
                "direct_verification": {
                    "observed_at": datetime.now(UTC).isoformat(),
                    "services": [
                        {
                            "address": "8.8.8.8",
                            "port": 443,
                            "protocol": "tcp",
                            "state": "refused",
                        }
                    ],
                }
            },
        ),
    )
    first = client.post(f"/api/v1/findings/{finding_id}/verify")
    assert first.status_code == 202
    assert process_one("verify-worker-1", client.app.state.testing_session) is not None
    listed = client.get(f"/api/v1/organizations/{organization['id']}/findings").json()[0]
    assert listed["status"] == "verifying"
    assert listed["clean_observations"] == 1
    second = client.post(f"/api/v1/findings/{finding_id}/verify")
    assert second.status_code == 202
    assert process_one("verify-worker-2", client.app.state.testing_session) is not None
    listed = client.get(f"/api/v1/organizations/{organization['id']}/findings").json()[0]
    assert listed["status"] == "resolved"
    assert listed["clean_observations"] == 2


def test_local_ai_generates_executive_and_technical_sections_separately(monkeypatch) -> None:
    requests = []

    class Response:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"response": __import__("json").dumps(self.payload)}

    responses = iter(
        [
            Response({"executive_summary": "One observed service requires review."}),
            Response(
                {
                    "technical_summary": "The service was observed at 8.8.8.8:443/tcp.",
                    "key_points": [{"text": "Review the service.", "claim_refs": [0]}],
                }
            ),
        ]
    )

    def fake_post(endpoint, *, json, timeout):
        requests.append((endpoint, json, timeout))
        return next(responses)

    monkeypatch.setattr("intel_platform.local_ai.httpx.post", fake_post)
    snapshot = AnalysisSnapshot(
        investigation_id="investigation",
        generated_by_id="user",
        risk_score=25,
        risk_level="low",
        title="Assessment",
        executive_summary="Deterministic summary",
        claims=[{"statement": "A service was observed at 8.8.8.8:443/tcp."}],
        correlations=[],
        recommendations=["Review the service."],
        metrics={"claim_count": 1},
    )

    narrative = generate_local_narrative(snapshot, "http://ollama:11434/", "small", 30)

    assert narrative["executive_summary"] == "One observed service requires review."
    assert narrative["technical_summary"].endswith("8.8.8.8:443/tcp.")
    assert narrative["key_points"] == [{"text": "Review the service.", "claim_refs": [0]}]
    assert len(requests) == 2
    assert requests[0][0] == "http://ollama:11434/api/generate"
    assert "executive_summary" in requests[0][1]["format"]["required"]
    assert "technical_summary" in requests[1][1]["format"]["required"]
    assert requests[0][1]["options"]["num_predict"] < requests[1][1]["options"]["num_predict"]


def test_local_ai_narrative_discards_unsupported_claim_references() -> None:
    narrative = validate_narrative(
        {
            "executive_summary": "One supported issue requires review.",
            "technical_summary": "The assessment contains one observed claim.",
            "key_points": [
                {"text": "Supported", "claim_refs": [0]},
                {"text": "Unsupported", "claim_refs": [99]},
            ],
        },
        claim_count=1,
    )
    assert narrative["key_points"] == [{"text": "Supported", "claim_refs": [0]}]
    with pytest.raises(LocalNarrativeError, match="unsupported security claims"):
        validate_narrative(
            {
                "executive_summary": "A breach may have occurred.",
                "technical_summary": "One service was observed.",
                "key_points": [],
            },
            claim_count=1,
            supported_claims=[{"statement": "An unexpected service was observed."}],
        )
    with pytest.raises(LocalNarrativeError, match="unsupported indicators"):
        validate_narrative(
            {
                "executive_summary": "The service was observed at 104.175.131.81:500/udp.",
                "technical_summary": "Review 104.175.131.81.",
                "key_points": [],
            },
            claim_count=1,
            supported_claims=[{"statement": "The service affects 104.131.175.81:500/udp."}],
        )
    cleaned = strip_unsupported_security_sentences(
        {
            "executive_summary": "A service was observed. A breach may have occurred.",
            "technical_summary": "Review the service. No compromise was confirmed.",
            "key_points": [
                {"text": "Review the observed service.", "claim_refs": [0]},
                {"text": "A malicious actor may exist.", "claim_refs": [0]},
            ],
        },
        [{"statement": "An unexpected service was observed."}],
    )
    assert cleaned["executive_summary"] == "A service was observed."
    assert cleaned["technical_summary"] == "Review the service."
    assert len(cleaned["key_points"]) == 1
    corrected = correct_unambiguous_indicators(
        {
            "executive_summary": "Observed at 104.175.131.81.",
            "technical_summary": "Review 104.175.131.81:500/udp.",
            "key_points": [],
        },
        [{"statement": "The service affects 104.131.175.81:500/udp."}],
    )
    assert "104.131.175.81" in corrected["executive_summary"]


def test_queued_job_can_be_cancelled(client: TestClient) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Cancellation contract"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Authorized cancellation test scope",
            "passive_allowed": True,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    ).json()
    client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.net",
        },
    )
    queued = client.post(f"/api/v1/investigations/{investigation['id']}/collect").json()
    cancelled = client.post(f"/api/v1/jobs/{queued['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["cancellation_requested_at"] is not None
    assert process_one("test-worker", client.app.state.testing_session) is None


def test_provider_contract_and_secret_envelope(client: TestClient) -> None:
    providers = client.get("/api/v1/providers")
    assert providers.status_code == 200
    descriptors = {item["name"]: item for item in providers.json()}
    assert set(descriptors) == {
        "certificate_transparency",
        "checkov",
        "domain_security",
        "gitleaks",
        "grype",
        "dns_discovery",
        "direct_verifier",
        "subfinder",
        "projectdiscovery_httpx",
        "naabu",
        "nmap",
        "rustscan",
        "masscan",
        "katana",
        "katana_authenticated",
        "nikto",
        "zap_passive",
        "zap_active",
        "nuclei",
        "dnstwist",
        "trufflehog",
        "semgrep",
        "osv_scanner",
        "syft",
        "trivy",
        "testssl",
        "safe_mock",
        "local_observer",
        "openvas",
        "taxii",
        "rdap",
        "virustotal",
        "shodan",
        "greynoise",
        "alienvault_otx",
        "abuseipdb",
        "censys",
        "urlhaus",
        "abuse_ch",
        "web_posture",
        "public_identity",
        "maigret",
        "hibp",
    }
    assert descriptors["rdap"]["requires_credentials"] is False
    assert descriptors["virustotal"]["requires_credentials"] is True
    assert descriptors["shodan"]["target_types"] == ["ip_address"]
    assert descriptors["local_observer"]["passive_only"] is False
    subfinder_installed = shutil.which("subfinder") is not None
    assert descriptors["subfinder"]["available"] is subfinder_installed
    if subfinder_installed:
        assert descriptors["subfinder"]["version"] != "not installed"
    else:
        assert descriptors["subfinder"]["version"] == "not installed"
    assert descriptors["nuclei"]["passive_only"] is False
    assert descriptors["public_identity"]["target_types"] == [
        "organization",
        "person",
        "username",
    ]
    key = Fernet.generate_key().decode()
    ciphertext = encrypt_credentials({"api_key": "not-plaintext"}, key)
    assert "not-plaintext" not in ciphertext
    assert decrypt_credentials(ciphertext, key) == {"api_key": "not-plaintext"}
    assert (
        RdapProvider.select_domain_service(
            {"services": [[["com"], ["https://rdap.example.test/"]]]},
            "sub.example.com",
        )
        == "https://rdap.example.test/"
    )


def test_authorized_hash_analysis_is_persisted(client: TestClient) -> None:
    organization = create_org(client)
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Authorized malware analysis"},
    ).json()
    endpoint = f"/api/v1/investigations/{investigation['id']}/malware/hashes"
    rejected = client.post(
        endpoint,
        json={"sha256": "a" * 64, "filename": "sample.bin", "authorization_confirmed": False},
    )
    assert rejected.status_code == 422
    created = client.post(
        endpoint,
        json={"sha256": "a" * 64, "filename": "sample.bin", "authorization_confirmed": True},
    )
    assert created.status_code == 201
    assert created.json()["analysis_type"] == "hash"
    assert created.json()["verdict"] == "unknown"
    listed = client.get(f"/api/v1/investigations/{investigation['id']}/malware/samples")
    assert [item["id"] for item in listed.json()] == [created.json()["id"]]


def test_zap_active_requires_per_run_approval(client: TestClient) -> None:
    organization = create_org(client, "ZAP approval")
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Approved web target"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Owner-authorized web assessment",
            "passive_allowed": True,
            "active_allowed": True,
            "active_scope_confirmed": True,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    ).json()
    target = client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.com",
        },
    ).json()
    rejected = client.post(
        f"/api/v1/investigations/{investigation['id']}/collect",
        json={"provider": "zap_active", "target_id": target["id"]},
    )
    assert rejected.status_code == 422
    approved = client.post(
        f"/api/v1/investigations/{investigation['id']}/collect",
        json={
            "provider": "zap_active",
            "target_id": target["id"],
            "active_attack_approved": True,
        },
    )
    assert approved.status_code == 202
    assert approved.json()["profile"] == "active_attack"


def test_threat_provider_intelligence_extraction() -> None:
    vt, _ = VirusTotalProvider().extract_intelligence(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60},
                    "reputation": -4,
                }
            }
        }
    )
    assert vt["verdict"] == "malicious_detections"
    assert vt["analysis_stats"]["malicious"] == 2

    otx, otx_associations = AlienVaultOtxProvider().extract_intelligence(
        {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {
                        "id": "pulse-1",
                        "name": "Observed campaign",
                        "malware_families": [{"display_name": "ExampleMalware"}],
                    }
                ],
            }
        }
    )
    assert otx["pulse_count"] == 1
    assert any(item["entity_type"] == "otx_pulse" for item in otx_associations)
    assert "ExampleMalware" in otx["malware_families"]

    threatfox, threat_associations = AbuseChProvider().extract_intelligence(
        {
            "query_status": "ok",
            "data": [
                {
                    "id": "12",
                    "ioc": "bad.example",
                    "threat_type": "botnet_cc",
                    "malware_printable": "ExampleBot",
                    "confidence_level": 90,
                }
            ],
        }
    )
    assert threatfox["match_count"] == 1
    assert any(item["entity_type"] == "threatfox_record" for item in threat_associations)

    censys, censys_associations = CensysProvider().extract_intelligence(
        {
            "result": {
                "resource": {
                    "ip": "203.0.113.9",
                    "service_count": 2,
                    "services": [
                        {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp"},
                        {"port": 500, "protocol": "IKE", "transport_protocol": "udp"},
                    ],
                    "autonomous_system": {"asn": 64500, "name": "Example ASN"},
                }
            }
        }
    )
    assert censys["service_count"] == 2
    assert (
        len([item for item in censys_associations if item["entity_type"] == "network_service"]) == 2
    )
    assert censys["_finding_candidates"][0]["asset_value"] == "203.0.113.9:500/udp"


def test_public_identity_confidence_distinguishes_candidates_from_exact_usernames() -> None:
    profile = {"login": "octocat", "display_name": "The Octocat"}
    assert PublicIdentityProvider.confidence_for("username", "octocat", profile) == 98
    assert PublicIdentityProvider.confidence_for("person", "The Octocat", profile) == 78
    assert PublicIdentityProvider.confidence_for("person", "Different Person", profile) < 60


def test_certificate_names_are_constrained_to_authorized_descendants() -> None:
    names = CertificateTransparencyProvider.extract_scoped_names(
        [{"name_value": "*.api.example.com\nexample.com\nevil-example.com\nother.test"}],
        "example.com",
    )
    assert names == {"api.example.com"}


def test_provider_kill_switch_blocks_collection(client: TestClient) -> None:
    organization = create_org(client)
    configuration = client.put(
        f"/api/v1/organizations/{organization['id']}/providers/safe_mock",
        json={
            "enabled": True,
            "settings": {
                "kill_switch": True,
                "jobs_per_hour": 60,
                "timeout_seconds": 20,
                "failure_threshold": 3,
                "cooldown_seconds": 300,
            },
        },
    )
    assert configuration.status_code == 200
    investigation = client.post(
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": "Kill switch contract"},
    ).json()
    now = datetime.now(UTC)
    authorization = client.post(
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Authorized safety control test",
            "passive_allowed": True,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
    ).json()
    client.post(
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.org",
        },
    )
    blocked = client.post(f"/api/v1/investigations/{investigation['id']}/collect")
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "Provider kill switch is active"
    runtime = client.get(f"/api/v1/organizations/{organization['id']}/providers/safe_mock/runtime")
    assert runtime.status_code == 200
    assert runtime.json()["kill_switch"] is True
    assert runtime.json()["consecutive_failures"] == 0


def test_replacing_provider_credentials_resets_stale_runtime_state(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    organization = create_org(client)
    key = Fernet.generate_key().decode()
    monkeypatch.setattr("intel_platform.main.settings.provider_encryption_key", key)
    with client.app.state.testing_session() as db:
        db.add(
            ProviderRuntimeState(
                organization_id=organization["id"],
                provider="abuseipdb",
                consecutive_failures=4,
                circuit_open_until=datetime.now(UTC) + timedelta(minutes=5),
                last_error="abuseipdb returned HTTP 401",
            )
        )
        db.commit()

    response = client.put(
        f"/api/v1/organizations/{organization['id']}/providers/abuseipdb",
        json={"enabled": True, "credentials": {"api_key": "replacement-key"}},
    )

    assert response.status_code == 200
    with client.app.state.testing_session() as db:
        configuration = (
            db.query(ProviderConfiguration)
            .filter_by(organization_id=organization["id"], provider="abuseipdb")
            .one()
        )
        runtime = (
            db.query(ProviderRuntimeState)
            .filter_by(organization_id=organization["id"], provider="abuseipdb")
            .one()
        )
        assert decrypt_credentials(configuration.encrypted_credentials, key) == {
            "api_key": "replacement-key"
        }
        assert runtime.consecutive_failures == 0
        assert runtime.circuit_open_until is None
        assert runtime.last_error is None


def test_provider_assurance_uses_progressive_verification_states(client: TestClient) -> None:
    organization = create_org(client)
    response = client.get(f"/api/v1/organizations/{organization['id']}/platform-assurance")
    assert response.status_code == 200
    providers = {item["provider"]: item for item in response.json()["providers"]}
    safe_mock = providers["safe_mock"]
    assert safe_mock["supported"] is False
    assert safe_mock["tier"] == "experimental"
    assert safe_mock["contract_tested"] is False
    assert safe_mock["installed"] is True
    assert safe_mock["configured"] is True
    assert safe_mock["healthy"] is True
    assert safe_mock["live_verified"] is False
    assert safe_mock["status"] == "healthy"
    assert {name for name, item in providers.items() if item["supported"]} == {
        "virustotal",
        "shodan",
        "alienvault_otx",
        "censys",
        "abuse_ch",
    }
    assert all(
        item["status"]
        in {
            "supported",
            "experimental",
            "adapter_only",
            "inherited",
            "installed",
            "configured",
            "healthy",
            "live_verified",
        }
        for item in providers.values()
    )
    integrity = client.get(f"/api/v1/organizations/{organization['id']}/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert integrity.json()["audit_sealed"] >= 1
