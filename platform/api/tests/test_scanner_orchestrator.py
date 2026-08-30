from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from intel_platform import scanner_orchestrator
from intel_platform.docker_api_scanner import DockerApiScannerRunner
from intel_platform.scanner_isolation import (
    ScannerCancelledError,
    ScannerExecutionResult,
    ScannerIsolationError,
    ScannerPolicy,
    ScannerUnavailableError,
)
from intel_platform.scanner_orchestrator_client import ScannerOrchestratorClient

TOKEN = "orchestrator-test-token-that-is-long-enough-123456"  # noqa: S105


class ImmediateThread:
    def __init__(self, *, target, args, daemon):
        self.target = target
        self.args = args

    def start(self):
        self.target(*self.args)


class DeferredThread:
    def __init__(self, *, target, args, daemon):
        pass

    def start(self):
        pass


class SuccessfulRunner:
    available = True

    def run(self, command, policy, *, cancellation=None):
        assert policy.image == "cypheryn/nmap:1.0.0"
        assert policy.environment == {}
        return ScannerExecutionResult(
            command=tuple(command),
            image=policy.image,
            container_id="container-id",
            returncode=0,
            stdout="scan result",
            stderr="",
            started_at=time.time() - 1,
            ended_at=time.time(),
        )


class CancellableRunner:
    available = True
    started = threading.Event()

    def run(self, command, policy, *, cancellation=None):
        self.started.set()
        assert cancellation is not None
        assert cancellation.wait(2)
        raise ScannerCancelledError("Scanner execution was cancelled")


def _request(**overrides):
    payload = {
        "provider": "nmap",
        "command": ["nmap", "-sV", "203.0.113.10"],
        "job_id": "job-1",
        "target_id": "target-1",
        "authorization_id": "authorization-1",
        "policy": {
            "cpu_limit": 1,
            "memory_mb": 512,
            "pids_limit": 128,
            "timeout_seconds": 60,
            "output_limit_bytes": 2000000,
            "tmpfs_mb": 128,
            "network": "bridge",
        },
    }
    payload.update(overrides)
    return payload


def test_orchestrator_requires_auth_and_enforces_server_allowlists(monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_ORCHESTRATOR_TOKEN", TOKEN)
    monkeypatch.setenv("PLATFORM_SCANNER_IMAGES", '{"nmap":"cypheryn/nmap:1.0.0"}')
    scanner_orchestrator._executions.clear()
    client = TestClient(scanner_orchestrator.app)
    assert client.post("/v1/executions", json=_request()).status_code == 401
    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert (
        client.post(
            "/v1/executions",
            headers=headers,
            json=_request(provider="masscan", command=["masscan", "203.0.113.10"]),
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/executions", headers=headers, json=_request(command=["sh", "-c", "id"])
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/executions", headers=headers, json=_request(authorization_id=None)
        ).status_code
        == 422
    )


def test_orchestrator_executes_and_returns_only_job_scoped_results(monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_ORCHESTRATOR_TOKEN", TOKEN)
    monkeypatch.setenv("PLATFORM_SCANNER_IMAGES", '{"nmap":"cypheryn/nmap:1.0.0"}')
    monkeypatch.setattr(scanner_orchestrator.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(scanner_orchestrator, "DockerApiScannerRunner", SuccessfulRunner)
    scanner_orchestrator._executions.clear()
    client = TestClient(scanner_orchestrator.app)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    created = client.post("/v1/executions", headers=headers, json=_request())
    assert created.status_code == 202
    execution_id = created.json()["execution_id"]
    result = client.get(f"/v1/executions/{execution_id}", headers=headers)
    assert result.status_code == 200
    assert result.json()["status"] == "completed"
    assert result.json()["stdout"] == "scan result"
    assert result.json()["authorization_id"] == "authorization-1"
    assert "command" not in result.json()


def test_orchestrator_rejects_excessive_policy_and_bounds_capacity(monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_ORCHESTRATOR_TOKEN", TOKEN)
    monkeypatch.setenv("PLATFORM_SCANNER_IMAGES", '{"nmap":"cypheryn/nmap:1.0.0"}')
    headers = {"Authorization": f"Bearer {TOKEN}"}
    client = TestClient(scanner_orchestrator.app)
    excessive = _request()
    excessive["policy"]["memory_mb"] = 4096
    assert client.post("/v1/executions", headers=headers, json=excessive).status_code == 422


def test_production_requires_digest_and_managed_active_egress(monkeypatch) -> None:
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "production")
    monkeypatch.setenv("SCANNER_ORCHESTRATOR_TOKEN", TOKEN)
    monkeypatch.setenv("PLATFORM_SCANNER_IMAGES", '{"nmap":"cypheryn/nmap:1.0.0"}')
    monkeypatch.setattr(scanner_orchestrator.threading, "Thread", DeferredThread)
    scanner_orchestrator._executions.clear()
    client = TestClient(scanner_orchestrator.app)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert client.post("/v1/executions", headers=headers, json=_request()).status_code == 422
    digest = "cypheryn/nmap@sha256:" + "a" * 64
    monkeypatch.setenv("PLATFORM_SCANNER_IMAGES", json.dumps({"nmap": digest}))
    assert client.post("/v1/executions", headers=headers, json=_request()).status_code == 422
    request = _request()
    request["policy"]["network"] = "cypheryn-egress-owned-targets"
    assert client.post("/v1/executions", headers=headers, json=request).status_code == 202


def test_orchestrator_cancellation_reaches_the_container_runner(monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_ORCHESTRATOR_TOKEN", TOKEN)
    monkeypatch.setenv("PLATFORM_SCANNER_IMAGES", '{"nmap":"cypheryn/nmap:1.0.0"}')
    monkeypatch.setattr(scanner_orchestrator, "DockerApiScannerRunner", CancellableRunner)
    CancellableRunner.started.clear()
    scanner_orchestrator._executions.clear()
    client = TestClient(scanner_orchestrator.app)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    execution_id = client.post(
        "/v1/executions", headers=headers, json=_request()
    ).json()["execution_id"]
    assert CancellableRunner.started.wait(1)
    assert client.delete(f"/v1/executions/{execution_id}", headers=headers).status_code == 202
    deadline = time.monotonic() + 2
    payload = {}
    while time.monotonic() < deadline:
        payload = client.get(f"/v1/executions/{execution_id}", headers=headers).json()
        if payload["status"] == "cancelled":
            break
        time.sleep(0.01)
    assert payload["status"] == "cancelled"


def test_compose_grants_docker_socket_only_to_orchestrator() -> None:
    root = Path(__file__).resolve().parents[3]
    compose = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    for service in ("api", "worker", "frontend", "taxii"):
        mounts = json.dumps(services[service].get("volumes", []))
        assert "docker.sock" not in mounts
    orchestrator_mounts = json.dumps(services["scanner-orchestrator"]["volumes"])
    assert "/var/run/docker.sock" in orchestrator_mounts
    assert services["scanner-orchestrator"]["cap_drop"] == ["ALL"]
    assert services["scanner-orchestrator"]["read_only"] is True
    assert "SCANNER_ORCHESTRATOR_TOKEN" not in services["api"]["environment"]


def test_worker_client_uses_token_and_does_not_select_an_image() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            payload = json.loads(request.content)
            assert "image" not in payload
            assert "environment" not in payload["policy"]
            return httpx.Response(202, json={"execution_id": "execution-1"})
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "image": "cypheryn/nmap:1.0.0",
                "container_id": "container-id",
                "returncode": 0,
                "stdout": "ok",
                "stderr": "",
                "started_at": 1,
                "ended_at": 2,
                "output_truncated": False,
            },
        )

    client = ScannerOrchestratorClient(
        "http://scanner-orchestrator:8010",
        TOKEN,
        poll_interval=0,
        transport=httpx.MockTransport(handler),
    )
    result = client.run(
        "nmap",
        ["nmap", "-sV", "203.0.113.10"],
        ScannerPolicy(image="cypheryn/nmap:1.0.0", network="bridge"),
        job_id="job-1",
        target_id="target-1",
        authorization_id="authorization-1",
    )
    assert result.stdout == "ok"
    assert requests[0].headers["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize(
    ("status_code", "payload", "expected"),
    [
        (401, {"detail": "Unauthorized"}, ScannerUnavailableError),
        (422, {"detail": "Scanner is not allowlisted"}, ScannerIsolationError),
    ],
)
def test_worker_client_fails_closed_on_orchestrator_rejection(
    status_code: int, payload: dict, expected: type[Exception]
) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(status_code, json=payload))
    client = ScannerOrchestratorClient(
        "http://scanner-orchestrator:8010", TOKEN, transport=transport
    )
    with pytest.raises(expected):
        client.run(
            "nmap",
            ["nmap", "203.0.113.10"],
            ScannerPolicy(image="cypheryn/nmap:1.0.0"),
            job_id="job-1",
            target_id="target-1",
            authorization_id="authorization-1",
        )


@pytest.mark.parametrize(
    ("remote_status", "expected"),
    [("cancelled", ScannerCancelledError), ("timed_out", TimeoutError)],
)
def test_worker_client_propagates_terminal_state(
    remote_status: str, expected: type[Exception]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json={"execution_id": "execution-1"})
        return httpx.Response(200, json={"status": remote_status, "error": "bounded failure"})

    client = ScannerOrchestratorClient(
        "http://scanner-orchestrator:8010",
        TOKEN,
        poll_interval=0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(expected, match="bounded failure"):
        client.run(
            "nmap",
            ["nmap", "203.0.113.10"],
            ScannerPolicy(image="cypheryn/nmap:1.0.0"),
            job_id="job-1",
            target_id="target-1",
            authorization_id="authorization-1",
        )


def test_worker_client_rejects_missing_trust_configuration() -> None:
    with pytest.raises(ScannerUnavailableError):
        ScannerOrchestratorClient("", TOKEN)
    with pytest.raises(ScannerUnavailableError):
        ScannerOrchestratorClient("http://scanner-orchestrator:8010", "short")


def test_docker_api_runner_applies_container_policy_and_cleans_up() -> None:
    requests: list[httpx.Request] = []
    container_id = "a" * 64

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/_ping":
            return httpx.Response(200, text="OK")
        if request.url.path == "/networks/cypheryn-egress-owned-targets":
            return httpx.Response(
                200, json={"Labels": {"cypheryn.egress-policy": "enforced"}}
            )
        if request.url.path == "/containers/create":
            config = json.loads(request.content)
            assert config["Env"] == []
            assert config["HostConfig"]["ReadonlyRootfs"] is True
            assert config["HostConfig"]["CapDrop"] == ["ALL"]
            assert config["HostConfig"]["SecurityOpt"] == ["no-new-privileges:true"]
            assert config["Labels"] == {
                "cypheryn.scanner.managed": "true",
                "cypheryn.scanner.namespace": "cypheryn",
            }
            assert config["Tty"] is False
            return httpx.Response(201, json={"Id": container_id})
        if request.url.path.endswith("/start"):
            return httpx.Response(204)
        if request.url.path == "/containers/json":
            return httpx.Response(200, json=[{"Id": container_id}, {"Id": "invalid"}])
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={"State": {"Running": False, "ExitCode": 0}})
        if request.url.path.endswith("/logs"):
            return httpx.Response(200, content=b"bounded output")
        if request.method == "DELETE":
            return httpx.Response(204)
        raise AssertionError(request.url)

    runner = DockerApiScannerRunner(transport=httpx.MockTransport(handler))
    assert runner.available is True
    result = runner.run(
        ["nmap", "203.0.113.10"],
        ScannerPolicy(
            image="cypheryn/nmap:1.0.0", network="cypheryn-egress-owned-targets"
        ),
    )
    assert result.stdout == "bounded output"
    assert result.returncode == 0
    assert runner.cleanup_managed() == 1
    assert any(request.method == "DELETE" for request in requests)
    framed = b"\x01\0\0\0\0\0\0\x03out" + b"\x02\0\0\0\0\0\0\x03err"
    assert runner._decode_logs(framed, 6) == ("out", "err", False)


def test_docker_runner_rejects_unattested_egress_network() -> None:
    runner = DockerApiScannerRunner(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"Labels": {}})
        )
    )
    with pytest.raises(ScannerIsolationError, match="enforced-policy label"):
        runner.run(
            ["nmap", "203.0.113.10"],
            ScannerPolicy(
                image="cypheryn/nmap:1.0.0",
                network="cypheryn-egress-owned-targets",
            ),
        )


def test_docker_api_runner_forces_cancellation() -> None:
    container_id = "b" * 64
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/containers/create":
            return httpx.Response(201, json={"Id": container_id})
        if request.url.path.endswith("/start"):
            return httpx.Response(204)
        if request.url.path.endswith("/logs"):
            return httpx.Response(404)
        if request.method == "DELETE":
            deleted.append(request.url.path)
            return httpx.Response(204)
        if request.url.path.endswith("/json"):
            return httpx.Response(404)
        raise AssertionError(request.url)

    cancellation = threading.Event()
    cancellation.set()
    runner = DockerApiScannerRunner(transport=httpx.MockTransport(handler))
    with pytest.raises(ScannerCancelledError):
        runner.run(
            ["nmap", "203.0.113.10"],
            ScannerPolicy(image="cypheryn/nmap:1.0.0"),
            cancellation=cancellation,
        )
    assert deleted


def test_docker_api_runner_rejects_engine_failure() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(500))
    runner = DockerApiScannerRunner(transport=transport)
    assert runner.available is False
    with pytest.raises(ScannerIsolationError, match="create"):
        runner.run(
            ["nmap", "203.0.113.10"],
            ScannerPolicy(image="cypheryn/nmap:1.0.0"),
        )

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unavailable", request=request)

    disconnected = DockerApiScannerRunner(transport=httpx.MockTransport(unavailable))
    with pytest.raises(ScannerUnavailableError):
        disconnected.run(
            ["nmap", "203.0.113.10"],
            ScannerPolicy(image="cypheryn/nmap:1.0.0"),
        )
