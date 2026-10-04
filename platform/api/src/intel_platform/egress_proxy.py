from __future__ import annotations

import base64
import hashlib
import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator

from .config import Settings, get_settings
from .destination_security import CanonicalDestination, UnsafeDestination, canonicalize_destination
from .egress import scan_artifact

READ_METHODS = {"GET", "HEAD"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
BLOCKED_HEADER_NAMES = {
    "connection",
    "content-length",
    "host",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
OUTCOMES = {
    "AUTHORIZATION_EXHAUSTED": "AUTHORITY_CONSUMED",
    "AUTHORIZATION_EXPIRED": "AUTHORITY_EXPIRED",
    "AUTHORIZATION_REVOKED": "AUTHORITY_REVOKED",
    "RESOLUTION_BINDING_CHANGED": "DNS_CHANGED",
    "POLICY_AUTHORITY_CHANGED": "POLICY_CHANGED",
    "CAPABILITY_AUTHORITY_CHANGED": "CAPABILITY_REVOKED",
}


class ProxyRequest(BaseModel):
    decision_id: str = Field(min_length=36, max_length=36)
    action: str = Field(min_length=1, max_length=160)
    capability: str = Field(min_length=3, max_length=160)
    url: str = Field(min_length=1, max_length=2048)
    method: str = Field(default="GET", min_length=3, max_length=12)
    environment: str = Field(default="production", max_length=80)
    resource_scope: dict = Field(default_factory=dict, max_length=100)
    headers: dict[str, str] = Field(default_factory=dict, max_length=100)
    body_base64: str = Field(default="", max_length=14 * 1024 * 1024)
    correlation_id: str = Field(min_length=8, max_length=128)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.upper()
        if method not in READ_METHODS | WRITE_METHODS:
            raise ValueError("Unsupported HTTP method")
        return method


@dataclass(frozen=True)
class TransportResult:
    status_code: int
    headers: dict[str, str]
    body: bytes
    bytes_sent: int


class ProxySecurityError(RuntimeError):
    def __init__(self, outcome: str, reason: str, http_status: int = 403):
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason
        self.http_status = http_status


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, float] = {}

    def add(self, name: str, value: float = 1) -> None:
        with self._lock:
            self._values[name] = self._values.get(name, 0) + value

    def render(self) -> str:
        with self._lock:
            values = dict(self._values)
        return "\n".join(
            f"cypheryn_egress_proxy_{key} {value}" for key, value in sorted(values.items())
        ) + "\n"


metrics = Metrics()


class ControlPlane:
    def __init__(self, settings: Settings, token: str):
        self.base_url = settings.trusted_egress_proxy_control_plane_url.rstrip("/")
        self.headers = {"Authorization": token}
        self.timeout = settings.trusted_egress_proxy_validation_timeout_seconds
        self.verify: bool | ssl.SSLContext = True
        if self.base_url.startswith("https://"):
            if not all(
                (
                    settings.trusted_egress_proxy_mtls_ca_file,
                    settings.trusted_egress_proxy_mtls_cert_file,
                    settings.trusted_egress_proxy_mtls_key_file,
                )
            ):
                raise ProxySecurityError("DENIED", "MTLS_CONFIGURATION_REQUIRED", 503)
            context = ssl.create_default_context(
                cafile=settings.trusted_egress_proxy_mtls_ca_file
            )
            context.load_cert_chain(
                settings.trusted_egress_proxy_mtls_cert_file,
                settings.trusted_egress_proxy_mtls_key_file,
            )
            self.verify = context

    def _request(self, method: str, path: str, payload: dict) -> dict:
        try:
            # A fresh authenticated TLS channel avoids authorization state leaking
            # across workloads and keeps revocation semantics independent of pooling.
            with httpx.Client(
                verify=self.verify,
                timeout=self.timeout,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers=self.headers,
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise ProxySecurityError("DENIED", "CONTROL_PLANE_UNAVAILABLE", 503) from exc
        if response.status_code >= 400:
            detail = (
                "CONTROL_PLANE_DENIED"
                if response.status_code < 500
                else "CONTROL_PLANE_UNAVAILABLE"
            )
            raise ProxySecurityError("DENIED", detail, 403 if response.status_code < 500 else 503)
        return response.json()

    def start_receipt(self, decision_id: str, payload: dict) -> str:
        result = self._request(
            "POST", f"/api/v1/security/decisions/{decision_id}/proxy-receipts", payload
        )
        return str(result["proxy_request_id"])

    def validate(self, decision_id: str, payload: dict) -> dict:
        return self._request("POST", f"/api/v1/security/decisions/{decision_id}/validate", payload)

    def finish_receipt(self, receipt_id: str, payload: dict) -> None:
        self._request("PATCH", f"/api/v1/security/proxy-receipts/{receipt_id}", payload)


class PinnedHttpsTransport:
    def __init__(self, settings: Settings):
        self.settings = settings

    def request(
        self,
        canonical: CanonicalDestination,
        pinned_address: str,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> TransportResult:
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        raw = socket.create_connection(
            (pinned_address, canonical.port),
            timeout=self.settings.trusted_egress_proxy_connect_timeout_seconds,
        )
        tls = None
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            tls = context.wrap_socket(raw, server_hostname=canonical.hostname)
            tls.settimeout(self.settings.trusted_egress_proxy_read_timeout_seconds)
            outbound = {
                "Host": canonical.hostname,
                "Connection": "close",
                "Accept-Encoding": "identity",
                **headers,
            }
            if body:
                outbound["Content-Length"] = str(len(body))
            request_head = f"{method} {path} HTTP/1.1\r\n" + "".join(
                f"{name}: {value}\r\n" for name, value in outbound.items()
            ) + "\r\n"
            encoded_head = request_head.encode("latin-1")
            if len(encoded_head) > self.settings.trusted_egress_proxy_max_header_bytes:
                raise ProxySecurityError("DENIED", "REQUEST_HEADERS_TOO_LARGE", 413)
            tls.sendall(encoded_head + body)
            response = http.client.HTTPResponse(tls)
            response.begin()
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            header_bytes = sum(len(name) + len(value) + 4 for name, value in response.getheaders())
            if header_bytes > self.settings.trusted_egress_proxy_max_header_bytes:
                raise ProxySecurityError("UPSTREAM_ERROR", "RESPONSE_HEADERS_TOO_LARGE", 502)
            limit = self.settings.trusted_egress_proxy_max_response_bytes
            content = response.read(limit + 1)
            if len(content) > limit:
                raise ProxySecurityError("UPSTREAM_ERROR", "RESPONSE_TOO_LARGE", 502)
            return TransportResult(response.status, response_headers, content, len(body))
        finally:
            if tls is not None:
                tls.close()
            else:
                raw.close()


def _capability_for_method(method: str) -> str:
    return "web.read" if method in READ_METHODS else "web.write"


def _inspect_headers(headers: dict[str, str], settings: Settings) -> dict[str, str]:
    safe: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.strip().lower()
        if normalized in BLOCKED_HEADER_NAMES or normalized.startswith(
            ("x-cypheryn-", "x-internal-")
        ):
            raise ProxySecurityError("QUARANTINED", "SENSITIVE_HEADER_BLOCKED")
        if any(char in name + value for char in "\r\n"):
            raise ProxySecurityError("DENIED", "INVALID_HEADER")
        encoded = base64.b64encode(f"{name}: {value}".encode()).decode()
        scan = scan_artifact(filename="headers.txt", content_base64=encoded, settings=settings)
        if "secret" in scan.classification:
            raise ProxySecurityError("QUARANTINED", "SECRET_HEADER_DETECTED")
        safe[name] = value
    return safe


def _decode_body(payload: ProxyRequest, settings: Settings) -> tuple[bytes, str]:
    if not payload.body_base64:
        return b"", ""
    try:
        body = base64.b64decode(payload.body_base64, validate=True)
    except ValueError as exc:
        raise ProxySecurityError("DENIED", "BODY_NOT_VALID_BASE64", 422) from exc
    if len(body) > settings.trusted_egress_proxy_max_request_bytes:
        raise ProxySecurityError("DENIED", "REQUEST_BODY_TOO_LARGE", 413)
    return body, hashlib.sha256(body).hexdigest()


def _inspect_body(payload: ProxyRequest, settings: Settings) -> list[str]:
    if not payload.body_base64:
        return []
    scan = scan_artifact(
        filename="request.txt", content_base64=payload.body_base64, settings=settings
    )
    if "secret" in scan.classification or "uninspectable" in scan.classification:
        raise ProxySecurityError("QUARANTINED", "REQUEST_BODY_REQUIRES_QUARANTINE")
    return scan.classification


def _same_origin(first: str, second: str) -> bool:
    left, right = urlsplit(first), urlsplit(second)
    return (left.scheme, left.hostname, left.port or 443) == (
        right.scheme,
        right.hostname,
        right.port or 443,
    )


def execute_proxy_request(
    payload: ProxyRequest,
    authorization: str,
    settings: Settings,
    *,
    transport: PinnedHttpsTransport | None = None,
    control_plane: ControlPlane | None = None,
) -> dict:
    started = time.monotonic()
    if not settings.trusted_egress_proxy_enabled:
        raise ProxySecurityError("DENIED", "TRUSTED_PROXY_DISABLED", 503)
    expected_capability = _capability_for_method(payload.method)
    if payload.capability != expected_capability:
        raise ProxySecurityError("DENIED", "METHOD_CAPABILITY_MISMATCH")
    if payload.resource_scope.get("method") != payload.method:
        raise ProxySecurityError("DENIED", "METHOD_SCOPE_MISMATCH")
    dns_started = time.monotonic()
    try:
        canonical = canonicalize_destination(payload.url)
    except UnsafeDestination as exc:
        metrics.add("dns_safety_failures_total")
        raise ProxySecurityError("UNSAFE_DESTINATION", str(exc)) from exc
    finally:
        metrics.add("dns_latency_ms_total", (time.monotonic() - dns_started) * 1000)
    pinned_address = canonical.resolved_addresses[0]
    body, body_hash = _decode_body(payload, settings)
    classifications: list[str] = []
    cp = control_plane or ControlPlane(settings, authorization)
    replica_id = settings.trusted_egress_proxy_replica_id or socket.gethostname()
    receipt_started = time.monotonic()
    try:
        receipt_id = cp.start_receipt(
            payload.decision_id,
            {
                "capability": payload.capability,
                "method": payload.method,
                "pinned_address": pinned_address,
                "correlation_id": payload.correlation_id,
                "request_body_hash": body_hash,
                "request_classifications": [],
                "proxy_replica_id": replica_id,
            },
        )
    except Exception:
        metrics.add("receipt_start_failures_total")
        raise
    finally:
        metrics.add(
            "receipt_start_latency_ms_total", (time.monotonic() - receipt_started) * 1000
        )
    outcome = "UPSTREAM_ERROR"
    reason = "UNEXPECTED_PROXY_FAILURE"
    response_status = None
    bytes_received = 0
    redirects = 0
    try:
        safe_headers = _inspect_headers(payload.headers, settings)
        classifications = _inspect_body(payload, settings)
        approved_body_hash = payload.resource_scope.get("body_sha256", "")
        if body_hash and approved_body_hash != body_hash:
            raise ProxySecurityError("DENIED", "BODY_BINDING_MISMATCH")
        if not body_hash and approved_body_hash:
            raise ProxySecurityError("DENIED", "BODY_BINDING_MISMATCH")
        validation_started = time.monotonic()
        try:
            validation = cp.validate(
                payload.decision_id,
                {
                    "action": payload.action,
                    "capability": payload.capability,
                    "destination": payload.url,
                    "environment": payload.environment,
                    "resource_scope": payload.resource_scope,
                    "connected_address": pinned_address,
                    "consume": True,
                },
            )
        except Exception:
            metrics.add("final_validation_failures_total")
            raise
        finally:
            metrics.add(
                "final_validation_latency_ms_total",
                (time.monotonic() - validation_started) * 1000,
            )
        if not validation.get("valid"):
            reasons = validation.get("reason_codes") or ["FINAL_VALIDATION_DENIED"]
            reason = ",".join(reasons)
            outcome = next((OUTCOMES[item] for item in reasons if item in OUTCOMES), "DENIED")
            raise ProxySecurityError(outcome, reason)
        # No await, logging, or unrelated work belongs between this authoritative
        # consume and the proxy-owned socket operation.
        network = transport or PinnedHttpsTransport(settings)
        current_url = payload.url
        seen = {current_url}
        while True:
            socket_started = time.monotonic()
            try:
                result = network.request(
                    canonical, pinned_address, payload.method, current_url, safe_headers, body
                )
            finally:
                metrics.add(
                    "tls_socket_latency_ms_total",
                    (time.monotonic() - socket_started) * 1000,
                )
            response_status = result.status_code
            bytes_received = len(result.body)
            if result.status_code not in {301, 302, 303, 307, 308}:
                outcome, reason = "ALLOWED_AND_EXECUTED", "EXECUTED"
                metrics.add("allowed_executions_total")
                metrics.add("bytes_transferred_total", result.bytes_sent + bytes_received)
                return {
                    "proxy_request_id": receipt_id,
                    "decision_id": payload.decision_id,
                    "status_code": result.status_code,
                    "headers": {
                        key: value
                        for key, value in result.headers.items()
                        if key not in {"set-cookie", "www-authenticate", "proxy-authenticate"}
                    },
                    "body_base64": base64.b64encode(result.body).decode(),
                    "outcome": outcome,
                    "redirect_count": redirects,
                }
            location = result.headers.get("location")
            if not location:
                raise ProxySecurityError("UPSTREAM_ERROR", "REDIRECT_WITHOUT_LOCATION", 502)
            redirected = urljoin(current_url, location)
            if not _same_origin(payload.url, redirected):
                raise ProxySecurityError(
                    "REDIRECT_REQUIRES_REAUTHORIZATION", "CROSS_ORIGIN_REDIRECT_BLOCKED"
                )
            redirects += 1
            if redirects > settings.trusted_egress_proxy_max_redirects or redirected in seen:
                raise ProxySecurityError("UPSTREAM_ERROR", "REDIRECT_LIMIT_OR_LOOP", 502)
            seen.add(redirected)
            current_url = redirected
    except ProxySecurityError as exc:
        outcome, reason = exc.outcome, exc.reason
        metrics.add("denials_total")
        metrics.add(f"outcome_{outcome.lower()}_total")
        raise
    except TimeoutError as exc:
        outcome, reason = "TIMEOUT", "UPSTREAM_TIMEOUT"
        metrics.add("timeouts_total")
        raise ProxySecurityError(outcome, reason, 504) from exc
    except ssl.SSLError as exc:
        outcome, reason = "UPSTREAM_ERROR", "TLS_VALIDATION_FAILED"
        metrics.add("tls_failures_total")
        raise ProxySecurityError(outcome, reason, 502) from exc
    except OSError as exc:
        outcome, reason = "UPSTREAM_ERROR", "UPSTREAM_CONNECTION_FAILED"
        metrics.add("upstream_errors_total")
        raise ProxySecurityError(outcome, reason, 502) from exc
    finally:
        elapsed = int((time.monotonic() - started) * 1000)
        metrics.add("latency_ms_total", elapsed)
        finish_started = time.monotonic()
        try:
            cp.finish_receipt(
                receipt_id,
                {
                    "outcome": outcome,
                    "security_reason": reason,
                    "response_status": response_status,
                    "bytes_sent": len(body),
                    "bytes_received": bytes_received,
                    "redirect_count": redirects,
                    "latency_ms": elapsed,
                    "request_classifications": classifications,
                },
            )
        except Exception:
            metrics.add("receipt_finish_failures_total")
            raise
        finally:
            metrics.add(
                "receipt_finish_latency_ms_total",
                (time.monotonic() - finish_started) * 1000,
            )


app = FastAPI(title="CYPHERYN Trusted Agent Egress Proxy", version="0.10.0")


@app.get("/health")
def health() -> dict:
    settings = get_settings()
    return {
        "status": "healthy",
        "enabled": settings.trusted_egress_proxy_enabled,
        "replica_id": settings.trusted_egress_proxy_replica_id or socket.gethostname(),
    }


@app.get("/metrics")
def prometheus_metrics() -> Response:
    return Response(metrics.render(), media_type="text/plain; version=0.0.4")


@app.post("/v1/proxy")
def proxy(
    payload: ProxyRequest,
    authorization: str = Header(default=""),
) -> dict:
    metrics.add("requests_total")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Workload bearer token required")
    try:
        return execute_proxy_request(payload, authorization, get_settings())
    except ProxySecurityError as exc:
        raise HTTPException(
            exc.http_status, {"outcome": exc.outcome, "reason": exc.reason}
        ) from exc
