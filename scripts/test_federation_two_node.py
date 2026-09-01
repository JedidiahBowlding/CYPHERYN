#!/usr/bin/env python3
"""Exercise two independent Compose nodes without a central CYPHERYN service."""

from __future__ import annotations

import copy
import subprocess
import time
from datetime import UTC, datetime, timedelta

import httpx

COMPOSE = ["docker", "compose", "-f", "compose.federation.yaml"]
HEADERS = {"X-Dev-Subject": "federation-integration", "X-Dev-Email": "test@localhost"}


def request(client: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    response = client.request(method, path, headers=HEADERS, **kwargs)
    response.raise_for_status()
    return response


def wait_ready(base_url: str, timeout_seconds: float = 45) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{base_url}/health/ready", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Node did not recover readiness: {base_url}")


def create_local_evidence_and_report(client: httpx.Client, suffix: str) -> dict:
    organization = request(
        client, "POST", "/api/v1/organizations", json={"name": f"Node {suffix} Org"}
    ).json()
    investigation = request(
        client,
        "POST",
        f"/api/v1/organizations/{organization['id']}/investigations",
        json={"name": f"Independent collection {suffix}"},
    ).json()
    now = datetime.now(UTC)
    authorization = request(
        client,
        "POST",
        f"/api/v1/organizations/{organization['id']}/authorizations",
        json={
            "basis": "Authorized federation integration test",
            "passive_allowed": True,
            "active_allowed": False,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(hours=1)).isoformat(),
        },
    ).json()
    request(
        client,
        "POST",
        f"/api/v1/investigations/{investigation['id']}/targets",
        json={
            "authorization_id": authorization["id"],
            "target_type": "domain",
            "value": "example.com",
        },
    )
    request(client, "POST", f"/api/v1/investigations/{investigation['id']}/collect")
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        workspace = request(
            client, "GET", f"/api/v1/investigations/{investigation['id']}/workspace"
        ).json()
        if workspace["evidence_sources"]:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(f"Node {suffix} worker did not persist local evidence")
    request(client, "POST", f"/api/v1/investigations/{investigation['id']}/analysis")
    report = request(
        client,
        "GET",
        f"/api/v1/investigations/{investigation['id']}/reports/pdf?style=technical",
    )
    if not report.content.startswith(b"%PDF-"):
        raise RuntimeError(f"Node {suffix} did not generate a local PDF report")
    return {"organization": organization, "investigation": investigation, "workspace": workspace}


def main() -> int:
    with httpx.Client(base_url="http://127.0.0.1:8101", timeout=10) as node_a, httpx.Client(
        base_url="http://127.0.0.1:8102", timeout=10
    ) as node_b:
        identity_a = request(node_a, "GET", "/api/federation/v1/identity").json()
        identity_b = request(node_b, "GET", "/api/federation/v1/identity").json()
        local_a = create_local_evidence_and_report(node_a, "A")
        local_b = create_local_evidence_and_report(node_b, "B-before-partition")

        subprocess.run([*COMPOSE, "restart", "node-b-db"], check=True)
        wait_ready("http://127.0.0.1:8102")
        subprocess.run([*COMPOSE, "restart", "node-b", "node-b-worker"], check=True)
        wait_ready("http://127.0.0.1:8102")

        peer_a_on_b = request(
            node_b,
            "POST",
            f"/api/federation/v1/organizations/{local_b['organization']['id']}/peers",
            json=identity_a,
        ).json()
        peer_b_on_a = request(
            node_a,
            "POST",
            f"/api/federation/v1/organizations/{local_a['organization']['id']}/peers",
            json=identity_b,
        ).json()
        for client, org_id, peer in (
            (node_b, local_b["organization"]["id"], peer_a_on_b),
            (node_a, local_a["organization"]["id"], peer_b_on_a),
        ):
            request(
                client,
                "PATCH",
                f"/api/federation/v1/organizations/{org_id}/peers/{peer['id']}",
                json={"status": "trusted"},
            )

        assertion = request(
            node_a,
            "POST",
            f"/api/federation/v1/organizations/{local_a['organization']['id']}/assertions",
            json={
                "assertion_type": "indicator_assessment",
                "subject_type": "domain",
                "subject_fingerprint": "a" * 64,
                "evidence_fingerprint": "b" * 64,
                "source_category": "threat_intelligence",
                "confidence": 80,
                "severity": "high",
                "observation_time": datetime.now(UTC).isoformat(),
            },
        ).json()
        inbound = f"/api/federation/v1/organizations/{local_b['organization']['id']}/assertions/inbound"
        accepted = node_b.post(inbound, headers=HEADERS, json=assertion)
        if accepted.status_code != 202:
            raise RuntimeError(f"Signed assertion exchange failed: {accepted.status_code}")
        if node_b.post(inbound, headers=HEADERS, json=assertion).status_code != 422:
            raise RuntimeError("Replay was not rejected")
        tampered = copy.deepcopy(assertion)
        tampered["assertion_id"] = "urn:uuid:tampered-integration"
        tampered["severity"] = "low"
        if node_b.post(inbound, headers=HEADERS, json=tampered).status_code != 422:
            raise RuntimeError("Tampering was not rejected")
        request(
            node_b,
            "PATCH",
            f"/api/federation/v1/organizations/{local_b['organization']['id']}/peers/{peer_a_on_b['id']}",
            json={"status": "revoked"},
        )
        post_revocation = request(
            node_a,
            "POST",
            f"/api/federation/v1/organizations/{local_a['organization']['id']}/assertions",
            json={
                "assertion_type": "indicator_assessment",
                "subject_type": "domain",
                "subject_fingerprint": "c" * 64,
                "evidence_fingerprint": "d" * 64,
                "source_category": "attack_surface",
                "confidence": 60,
                "severity": "medium",
                "observation_time": datetime.now(UTC).isoformat(),
            },
        ).json()
        revoked_delivery = node_b.post(inbound, headers=HEADERS, json=post_revocation)
        if revoked_delivery.status_code != 422 or "not trusted" not in revoked_delivery.text:
            raise RuntimeError("Revoked peer delivery was not explicitly rejected")

    subprocess.run([*COMPOSE, "stop", "node-a", "node-a-worker"], check=True)
    with httpx.Client(base_url="http://127.0.0.1:8102", timeout=10) as node_b:
        request(node_b, "GET", "/health/ready")
        create_local_evidence_and_report(node_b, "B-after-node-A-stop")
        federation_health = request(node_b, "GET", "/api/federation/v1/health").json()
        if federation_health != {"status": "ready", "federation_enabled": True}:
            raise RuntimeError(f"Node B federation health was inaccurate: {federation_health}")
        try:
            httpx.get("http://127.0.0.1:8101/health/ready", timeout=2)
        except httpx.TransportError:
            pass
        else:
            raise RuntimeError("Stopped Node A was unexpectedly reachable")
    print("Two-node federation independence test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
