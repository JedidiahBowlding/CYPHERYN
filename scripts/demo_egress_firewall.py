#!/usr/bin/env python3
"""Synthetic, non-destructive Agent Egress Firewall demonstration."""

from __future__ import annotations

import argparse
import base64
import io
import json
import urllib.error
import urllib.request


def request(base_url: str, path: str, method: str = "GET", payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    call = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Dev-Subject": "egress-demo-owner",
            "X-Dev-Email": "egress-demo@example.test",
        },
    )
    with urllib.request.urlopen(call, timeout=15) as response:
        return json.load(response)


def synthetic_screenshot() -> str:
    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise SystemExit("Pillow is required; run this inside the CYPHERYN API container") from exc
    image = Image.new("RGB", (1000, 260), "white")
    draw = ImageDraw.Draw(image)
    draw.text(
        (30, 40),
        "SYNTHETIC APPROVAL CENTER\nApplicant: demo@example.test\n"
        "API_KEY=synthetic_example_only_123456789\nPrivate repository evidence",
        fill="black",
        spacing=12,
    )
    output = io.BytesIO()
    image.save(output, format="PNG")
    return base64.b64encode(output.getvalue()).decode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    organization = request(args.api, "/api/v1/organizations", "POST", {"name": "Synthetic Egress Demo"})
    agent = request(
        args.api,
        "/api/v1/egress/agents",
        "POST",
        {
            "organization_id": organization["id"],
            "name": "synthetic-development-agent",
            "runtime": "documented-demo",
            "workspace": "/synthetic/demo",
        },
    )
    decision = request(
        args.api,
        "/api/v1/egress/evaluate",
        "POST",
        {
            "organization_id": organization["id"],
            "agent_id": agent["id"],
            "action_type": "github.repository.create",
            "destination": "api.github.com",
            "repository": "synthetic/public-image-host",
            "requested_visibility": "public",
            "correlation_id": "synthetic-egress-demo",
            "artifacts": [
                {"filename": "synthetic-approval.png", "content_base64": synthetic_screenshot()}
            ],
        },
    )
    evidence = request(args.api, f"/api/v1/egress/events/{decision['event_id']}/evidence")
    print(json.dumps({"decision": decision, "evidence_integrity": evidence["integrity"]}, indent=2))
    if decision["decision"] not in {"BLOCK", "QUARANTINE"}:
        raise SystemExit("FAIL: unsafe synthetic publication was not blocked")
    print("PASS: the public upload was blocked and integrity evidence was exported.")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"CYPHERYN API returned HTTP {exc.code}: {exc.read().decode()}") from exc
