from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import httpx

from intel_platform.pilot_agent import run_read


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "request failed", request=httpx.Request("POST", "https://internal"), response=None
            )

    def json(self):
        return self.payload


def _args(token_file: Path) -> Namespace:
    return Namespace(
        token_file=str(token_file),
        api_url="http://api:8000",
        proxy_url="http://egress-proxy:8020",
        agent_id="00000000-0000-0000-0000-000000000001",
        url="https://example.com/read",
        environment="production",
        timeout=5.0,
    )


def test_pilot_evaluates_then_uses_proxy(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("workload-token", encoding="utf-8")
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/evaluate"):
            return FakeResponse(
                {
                    "decision": "ALLOW",
                    "decision_id": "00000000-0000-0000-0000-000000000002",
                    "correlation_id": "pilot-correlation-0001",
                }
            )
        return FakeResponse({"outcome": "ALLOWED_AND_EXECUTED"})

    monkeypatch.setattr("intel_platform.pilot_agent.httpx.post", post)
    result = run_read(_args(token_file))
    assert result["execution"]["outcome"] == "ALLOWED_AND_EXECUTED"
    assert [item[0] for item in calls] == [
        "http://api:8000/api/v1/security/evaluate",
        "http://egress-proxy:8020/v1/proxy",
    ]
    assert all(item[1]["headers"]["Authorization"] == "Bearer workload-token" for item in calls)


def test_denied_pilot_operation_never_calls_proxy(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("workload-token", encoding="utf-8")
    calls = []

    def post(url, **kwargs):
        calls.append(url)
        return FakeResponse({"decision": "DENY", "reason_codes": ["POLICY_DEFAULT_DENY"]})

    monkeypatch.setattr("intel_platform.pilot_agent.httpx.post", post)
    result = run_read(_args(token_file))
    assert result["execution"] is None
    assert calls == ["http://api:8000/api/v1/security/evaluate"]


def test_pilot_compose_network_is_internal_and_proxy_only():
    compose = (Path(__file__).parents[3] / "compose.yaml").read_text(encoding="utf-8")
    pilot = compose.split("  protected-agent-pilot:", 1)[1].split("\n  frontend:", 1)[0]
    assert "networks: [protected-agents]" in pilot
    assert "proxy-egress" not in pilot
    assert "edge" not in pilot
    assert "protected-agents:\n    internal: true" in compose
    api = compose.split("  api:", 1)[1].split("\n  worker:", 1)[0]
    assert "protected-agents" not in api
    assert "proxy-control" not in api
    proxy = compose.split("  egress-proxy:", 1)[1].split(
        "\n  egress-control-plane:", 1
    )[0]
    assert "networks: [proxy-control, protected-agents, proxy-egress]" in proxy
    assert "backend" not in proxy
    service_gateway = compose.split("  egress-control-plane:", 1)[1].split(
        "\n  agent-control-plane:", 1
    )[0]
    assert "networks: [backend, proxy-control]" in service_gateway
    assert "proxy-control:\n    internal: true" in compose
    gateway = compose.split("  agent-control-plane:", 1)[1].split(
        "\n  protected-agent-pilot:", 1
    )[0]
    assert "networks: [backend, protected-agents]" in gateway
    gateway_config = (
        Path(__file__).parents[3] / "deploy" / "egress" / "AgentCaddyfile"
    ).read_text(encoding="utf-8")
    assert "path /api/v1/security/evaluate" in gateway_config
    assert "protected agents are not authorized" in gateway_config
