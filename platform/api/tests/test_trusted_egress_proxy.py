from __future__ import annotations

import base64
import ssl
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from intel_platform.auth import WorkloadPrincipal, get_workload_principal
from intel_platform.config import Settings
from intel_platform.destination_security import CanonicalDestination
from intel_platform.egress_proxy import (
    PinnedHttpsTransport,
    ProxyRequest,
    ProxySecurityError,
    TransportResult,
    app,
    execute_proxy_request,
)
from intel_platform.main import app as control_plane_app


class FakeControlPlane:
    def __init__(self, *, valid=True, reasons=None):
        self.valid = valid
        self.reasons = reasons or []
        self.started = []
        self.validations = []
        self.finished = []

    def start_receipt(self, decision_id, payload):
        self.started.append((decision_id, payload))
        return "receipt-1"

    def validate(self, decision_id, payload):
        self.validations.append((decision_id, payload))
        return {"valid": self.valid, "reason_codes": self.reasons}

    def finish_receipt(self, receipt_id, payload):
        self.finished.append((receipt_id, payload))


class FakeTransport:
    def __init__(self, responses=None, error=None):
        self.responses = list(
            responses or [TransportResult(200, {"content-type": "text/plain"}, b"ok", 0)]
        )
        self.error = error
        self.calls = []

    def request(self, canonical, pinned_address, method, url, headers, body):
        self.calls.append((canonical, pinned_address, method, url, headers, body))
        if self.error:
            raise self.error
        return self.responses.pop(0)


def settings(**changes):
    return Settings(
        trusted_egress_proxy_enabled=True,
        allow_dev_identity=True,
        **changes,
    )


def request(**changes):
    payload = {
        "decision_id": "00000000-0000-0000-0000-000000000001",
        "action": "fetch",
        "capability": "web.read",
        "url": "https://8.8.8.8/resource",
        "method": "GET",
        "environment": "production",
        "resource_scope": {"method": "GET"},
        "headers": {"Accept": "application/json"},
        "correlation_id": "correlation-0001",
    }
    payload.update(changes)
    return ProxyRequest.model_validate(payload)


def execute(payload=None, *, cp=None, transport=None, configured=None):
    return execute_proxy_request(
        payload or request(),
        "Bearer signed-workload-token",
        configured or settings(),
        control_plane=cp or FakeControlPlane(),
        transport=transport or FakeTransport(),
    )


def test_proxy_route_requires_workload_bearer():
    response = TestClient(app).post("/v1/proxy", json=request().model_dump())
    assert response.status_code == 401


def test_feature_flag_fails_closed():
    with pytest.raises(ProxySecurityError, match="TRUSTED_PROXY_DISABLED"):
        execute(configured=Settings(trusted_egress_proxy_enabled=False))


@pytest.mark.parametrize(
    ("method", "capability"),
    [("POST", "web.read"), ("GET", "web.write"), ("DELETE", "web.read")],
)
def test_method_capability_mapping_is_enforced(method, capability):
    with pytest.raises(ProxySecurityError, match="METHOD_CAPABILITY_MISMATCH"):
        execute(request(method=method, capability=capability, resource_scope={"method": method}))


def test_valid_request_consumes_authority_immediately_before_socket():
    order = []

    class OrderedControlPlane(FakeControlPlane):
        def validate(self, decision_id, payload):
            order.append("validate")
            assert payload["consume"] is True
            return super().validate(decision_id, payload)

    class OrderedTransport(FakeTransport):
        def request(self, *args):
            order.append("socket")
            return super().request(*args)

    cp, transport = OrderedControlPlane(), OrderedTransport()
    result = execute(cp=cp, transport=transport)
    assert result["outcome"] == "ALLOWED_AND_EXECUTED"
    assert order == ["validate", "socket"]
    assert cp.finished[0][1]["outcome"] == "ALLOWED_AND_EXECUTED"


def test_final_validation_denial_never_opens_socket():
    cp = FakeControlPlane(valid=False, reasons=["AGENT_AUTHORITY_CHANGED"])
    transport = FakeTransport()
    with pytest.raises(ProxySecurityError, match="AGENT_AUTHORITY_CHANGED"):
        execute(cp=cp, transport=transport)
    assert transport.calls == []
    assert cp.finished[0][1]["outcome"] == "DENIED"


def test_consumed_authority_has_distinct_outcome_and_no_socket():
    cp = FakeControlPlane(valid=False, reasons=["AUTHORIZATION_EXHAUSTED"])
    transport = FakeTransport()
    with pytest.raises(ProxySecurityError) as error:
        execute(cp=cp, transport=transport)
    assert error.value.outcome == "AUTHORITY_CONSUMED"
    assert not transport.calls


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer should-not-leak"},
        {"Cookie": "session=private"},
        {"X-Cypheryn-Proxy-Secret": "private"},
        {"X-Note": "api_key=abcdefghijklmnop"},
    ],
)
def test_sensitive_headers_are_quarantined_before_network(headers):
    with pytest.raises(ProxySecurityError) as error:
        execute(request(headers=headers))
    assert error.value.outcome == "QUARANTINED"


def test_secret_body_is_quarantined_before_network():
    body = base64.b64encode(b"api_key=abcdefghijklmnop").decode()
    with pytest.raises(ProxySecurityError) as error:
        execute(request(body_base64=body))
    assert error.value.outcome == "QUARANTINED"


def test_request_body_size_is_bounded():
    body = base64.b64encode(b"x" * 2048).decode()
    with pytest.raises(ProxySecurityError, match="REQUEST_BODY_TOO_LARGE"):
        execute(
            request(body_base64=body),
            configured=settings(trusted_egress_proxy_max_request_bytes=1024),
        )


def test_cross_origin_redirect_requires_new_authorization():
    transport = FakeTransport(
        [TransportResult(302, {"location": "https://example.com/next"}, b"", 0)]
    )
    with pytest.raises(ProxySecurityError) as error:
        execute(transport=transport)
    assert error.value.outcome == "REDIRECT_REQUIRES_REAUTHORIZATION"
    assert len(transport.calls) == 1


def test_same_origin_redirect_uses_same_pinned_address():
    transport = FakeTransport(
        [
            TransportResult(302, {"location": "/next"}, b"", 0),
            TransportResult(200, {}, b"done", 0),
        ]
    )
    result = execute(transport=transport)
    assert result["redirect_count"] == 1
    assert [call[1] for call in transport.calls] == ["8.8.8.8", "8.8.8.8"]


def test_redirect_loop_is_bounded():
    transport = FakeTransport(
        [TransportResult(302, {"location": "/resource"}, b"", 0)]
    )
    with pytest.raises(ProxySecurityError, match="REDIRECT_LIMIT_OR_LOOP"):
        execute(transport=transport)


@pytest.mark.parametrize("url", ["https://127.0.0.1", "https://169.254.169.254"])
def test_unsafe_destinations_never_create_receipt_or_socket(url):
    cp, transport = FakeControlPlane(), FakeTransport()
    with pytest.raises(ProxySecurityError) as error:
        execute(request(url=url), cp=cp, transport=transport)
    assert error.value.outcome == "UNSAFE_DESTINATION"
    assert not cp.started and not transport.calls


def test_timeout_is_recorded_without_response_data():
    cp = FakeControlPlane()
    with pytest.raises(ProxySecurityError) as error:
        execute(cp=cp, transport=FakeTransport(error=TimeoutError()))
    assert error.value.outcome == "TIMEOUT"
    assert cp.finished[0][1]["bytes_received"] == 0


def test_response_excludes_authentication_headers():
    transport = FakeTransport(
        [
            TransportResult(
                200,
                {
                    "set-cookie": "secret",
                    "www-authenticate": "private",
                    "content-type": "text/plain",
                },
                b"ok",
                0,
            )
        ]
    )
    result = execute(transport=transport)
    assert result["headers"] == {"content-type": "text/plain"}


def test_pinned_transport_preserves_hostname_for_sni_and_certificate_validation(monkeypatch):
    observed = {}

    class Raw:
        def close(self):
            pass

    class TLS:
        def settimeout(self, value):
            observed["timeout"] = value

        def sendall(self, value):
            observed["wire"] = value

        def close(self):
            pass

    class Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, raw, *, server_hostname):
            observed["server_hostname"] = server_hostname
            return TLS()

    class Incoming:
        status = 200

        def __init__(self, tls):
            pass

        def begin(self):
            pass

        def getheaders(self):
            return [("Content-Type", "text/plain")]

        def read(self, limit):
            return b"ok"

    monkeypatch.setattr(
        "intel_platform.egress_proxy.socket.create_connection", lambda *args, **kwargs: Raw()
    )
    monkeypatch.setattr(
        "intel_platform.egress_proxy.ssl.create_default_context", lambda: Context()
    )
    monkeypatch.setattr("intel_platform.egress_proxy.http.client.HTTPResponse", Incoming)
    canonical = CanonicalDestination(
        "https://example.com", "example.com", 443, "https", ("8.8.8.8",)
    )
    PinnedHttpsTransport(settings()).request(
        canonical, "8.8.8.8", "GET", "https://example.com/path", {}, b""
    )
    assert observed["server_hostname"] == "example.com"
    assert b"Host: example.com\r\n" in observed["wire"]


def test_tls_hostname_failure_is_not_downgraded(monkeypatch):
    class Raw:
        def close(self):
            pass

    class WrongHostname:
        def wrap_socket(self, raw, *, server_hostname):
            raise ssl.CertificateError("hostname mismatch")

    monkeypatch.setattr(
        "intel_platform.egress_proxy.socket.create_connection", lambda *args, **kwargs: Raw()
    )
    monkeypatch.setattr(
        "intel_platform.egress_proxy.ssl.create_default_context", lambda: WrongHostname()
    )
    canonical = CanonicalDestination(
        "https://example.com", "example.com", 443, "https", ("8.8.8.8",)
    )
    with pytest.raises(ssl.CertificateError):
        PinnedHttpsTransport(settings()).request(
            canonical, "8.8.8.8", "GET", "https://example.com", {}, b""
        )


def test_pinned_transport_enforces_response_size(monkeypatch):
    class Socket:
        def close(self):
            pass

        def settimeout(self, value):
            pass

        def sendall(self, value):
            pass

    class Context:
        def wrap_socket(self, raw, *, server_hostname):
            return raw

    class Incoming:
        status = 200

        def __init__(self, tls):
            pass

        def begin(self):
            pass

        def getheaders(self):
            return []

        def read(self, limit):
            return b"x" * limit

    monkeypatch.setattr(
        "intel_platform.egress_proxy.socket.create_connection", lambda *args, **kwargs: Socket()
    )
    monkeypatch.setattr(
        "intel_platform.egress_proxy.ssl.create_default_context", lambda: Context()
    )
    monkeypatch.setattr("intel_platform.egress_proxy.http.client.HTTPResponse", Incoming)
    canonical = CanonicalDestination(
        "https://example.com", "example.com", 443, "https", ("8.8.8.8",)
    )
    with pytest.raises(ProxySecurityError, match="RESPONSE_TOO_LARGE"):
        PinnedHttpsTransport(
            settings(trusted_egress_proxy_max_response_bytes=1024)
        ).request(canonical, "8.8.8.8", "GET", "https://example.com", {}, b"")


def test_control_plane_or_receipt_failure_never_opens_socket():
    class Unavailable(FakeControlPlane):
        def start_receipt(self, decision_id, payload):
            raise ProxySecurityError("DENIED", "CONTROL_PLANE_UNAVAILABLE", 503)

    transport = FakeTransport()
    with pytest.raises(ProxySecurityError, match="CONTROL_PLANE_UNAVAILABLE"):
        execute(cp=Unavailable(), transport=transport)
    assert transport.calls == []


def test_two_proxy_callers_cannot_both_pass_atomic_control_plane():
    lock = __import__("threading").Lock()
    consumed = False
    sockets = []

    class AtomicControlPlane(FakeControlPlane):
        def validate(self, decision_id, payload):
            nonlocal consumed
            with lock:
                if consumed:
                    return {"valid": False, "reason_codes": ["AUTHORIZATION_EXHAUSTED"]}
                consumed = True
                return {"valid": True, "reason_codes": []}

    class CountingTransport(FakeTransport):
        def request(self, *args):
            sockets.append(1)
            return super().request(*args)

    def invoke():
        try:
            execute(cp=AtomicControlPlane(), transport=CountingTransport())
            return "executed"
        except ProxySecurityError as exc:
            return exc.outcome

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: invoke(), range(2)))
    assert sorted(outcomes) == ["AUTHORITY_CONSUMED", "executed"]
    assert len(sockets) == 1


def test_durable_receipt_derives_identity_and_never_returns_sensitive_fields(client):
    organization_id = client.post(
        "/api/v1/organizations", json={"name": "Proxy receipt test"}
    ).json()["id"]
    security_client = client.post(
        "/api/v1/security/clients",
        json={
            "organization_id": organization_id,
            "external_client_id": "proxy-workload",
            "name": "Proxy workload",
        },
    ).json()
    agent = client.post(
        "/api/v1/security/agents",
        json={
            "organization_id": organization_id,
            "security_client_id": security_client["id"],
            "name": "proxy-agent",
        },
    ).json()
    client.post(
        f"/api/v1/security/agents/{agent['id']}/capability-grants",
        json={"organization_id": organization_id, "capability": "web.read"},
    )
    client.post(
        "/api/v1/security/destinations",
        json={
            "organization_id": organization_id,
            "destination": "https://8.8.8.8",
            "trust_state": "TRUSTED",
        },
    )
    control_plane_app.dependency_overrides[get_workload_principal] = lambda: WorkloadPrincipal(
        subject="proxy-workload@clients", client_id="proxy-workload"
    )
    from datetime import UTC, datetime

    evaluation = client.post(
        "/api/v1/security/evaluate",
        json={
            "agent_id": agent["id"],
            "action": "fetch",
            "capability": "web.read",
            "destination": "https://8.8.8.8",
            "environment": "production",
            "data_classifications": ["PUBLIC"],
            "resource_scope": {"method": "GET"},
            "context": {},
            "request_id": "proxy-receipt-request-0001",
            "idempotency_key": "proxy-receipt-idempotency-0001",
            "nonce": "proxy-receipt-nonce-0001",
            "timestamp": datetime.now(UTC).isoformat(),
        },
    ).json()
    receipt = client.post(
        f"/api/v1/security/decisions/{evaluation['decision_id']}/proxy-receipts",
        json={
            "capability": "web.read",
            "method": "GET",
            "pinned_address": "8.8.8.8",
            "correlation_id": "proxy-correlation-0001",
            "request_body_hash": "",
            "request_classifications": [],
        },
    )
    assert receipt.status_code == 201
    receipt_id = receipt.json()["proxy_request_id"]
    assert client.patch(
        f"/api/v1/security/proxy-receipts/{receipt_id}",
        json={
            "outcome": "ALLOWED_AND_EXECUTED",
            "security_reason": "EXECUTED",
            "response_status": 200,
            "bytes_sent": 0,
            "bytes_received": 2,
            "redirect_count": 0,
            "latency_ms": 12,
        },
    ).status_code == 200
    control_plane_app.dependency_overrides.pop(get_workload_principal)
    listed = client.get(
        f"/api/v1/security/proxy-receipts?organization_id={organization_id}"
    ).json()
    assert listed[0]["agent_id"] == agent["id"]
    assert listed[0]["outcome"] == "ALLOWED_AND_EXECUTED"
    serialized = str(listed[0]).lower()
    assert "authorization" not in serialized
    assert "cookie" not in serialized
    assert "body" not in serialized
