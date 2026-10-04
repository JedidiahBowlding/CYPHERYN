from __future__ import annotations

import argparse
import base64
import os
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx


def _token(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("Pilot workload token file is empty")
    return value


def run_read(args: argparse.Namespace) -> dict:
    token = _token(args.token_file)
    headers = {"Authorization": f"Bearer {token}"}
    unique = secrets.token_urlsafe(18)
    evaluation = httpx.post(
        f"{args.api_url.rstrip('/')}/api/v1/security/evaluate",
        headers=headers,
        json={
            "agent_id": args.agent_id,
            "action": "fetch",
            "capability": "web.read",
            "destination": args.url,
            "environment": args.environment,
            "data_classifications": ["PUBLIC"],
            "resource_scope": {"method": "GET"},
            "context": {"pilot": "protected-read-agent"},
            "requested_decision": "ALLOW",
            "request_id": f"pilot-{unique}",
            "idempotency_key": f"pilot-idempotency-{unique}",
            "nonce": f"pilot-nonce-{unique}",
            "timestamp": datetime.now(UTC).isoformat(),
        },
        timeout=args.timeout,
    )
    evaluation.raise_for_status()
    decision = evaluation.json()
    if decision.get("decision") != "ALLOW":
        return {"decision": decision, "execution": None}
    proxied = httpx.post(
        f"{args.proxy_url.rstrip('/')}/v1/proxy",
        headers=headers,
        json={
            "decision_id": decision["decision_id"],
            "action": "fetch",
            "capability": "web.read",
            "url": args.url,
            "method": "GET",
            "environment": args.environment,
            "resource_scope": {"method": "GET"},
            "headers": {"Accept": "application/json,text/plain;q=0.8"},
            "body_base64": base64.b64encode(b"").decode(),
            "correlation_id": decision["correlation_id"],
        },
        timeout=args.timeout,
    )
    proxied.raise_for_status()
    return {"decision": decision, "execution": proxied.json()}


def main() -> int:
    parser = argparse.ArgumentParser(description="CYPHERYN protected read-only pilot agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("wait", help="Remain idle until an operator runs a certified read")
    run = subparsers.add_parser("read", help="Evaluate and execute one read-only HTTPS operation")
    run.add_argument("--agent-id", required=True)
    run.add_argument("--url", required=True)
    run.add_argument(
        "--token-file",
        default=os.getenv("CYPHERYN_WORKLOAD_TOKEN_FILE", "/run/secrets/pilot-workload-token"),
    )
    run.add_argument(
        "--api-url", default=os.getenv("CYPHERYN_API_URL", "http://api:8000")
    )
    run.add_argument(
        "--proxy-url",
        default=os.getenv("CYPHERYN_EGRESS_PROXY_URL", "http://egress-proxy:8020"),
    )
    run.add_argument("--environment", default="production")
    run.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.command == "wait":
        while True:
            time.sleep(3600)
    result = run_read(args)
    print({"decision": result["decision"]["decision"], "executed": bool(result["execution"])})
    return 0 if result["execution"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
