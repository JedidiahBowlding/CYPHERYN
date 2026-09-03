from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path

import httpx

from ..provider_contract import (
    ProviderCancelledError,
    ProviderCapabilities,
    ProviderContext,
    ProviderResult,
)
from .local_tools import LocalToolProvider

GREENBONE_DIR = Path(__file__).resolve().parents[4] / "greenbone"
COMPOSE_FILE = GREENBONE_DIR / "compose.yaml"


class OpenVasProvider(LocalToolProvider):
    name = "openvas"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address"}),
        passive_only=False,
        requires_credentials=True,
        supports_cancellation=False,
    )

    def __init__(self) -> None:
        # The remote bridge owns its Greenbone service account. CYPHERYN only
        # receives a narrowly scoped bridge token, so no user-entered provider
        # credentials are needed in that deployment mode.
        if os.environ.get("OPENVAS_BRIDGE_URL"):
            self.capabilities = ProviderCapabilities(
                target_types=frozenset({"domain", "ip_address"}),
                passive_only=False,
                requires_credentials=False,
                supports_cancellation=False,
            )

    @cached_property
    def available(self) -> bool:
        return bool(os.environ.get("OPENVAS_BRIDGE_URL")) or (
            shutil.which("docker") is not None and COMPOSE_FILE.is_file()
        )

    @cached_property
    def version(self) -> str | None:
        if not self.available:
            return None
        if os.environ.get("OPENVAS_BRIDGE_URL"):
            return "Remote Greenbone Community Containers"
        docker = shutil.which("docker")
        if not docker:
            return None
        try:
            result = subprocess.run(  # noqa: S603 - fixed local Docker command
                [
                    docker,
                    "compose",
                    "-f",
                    str(COMPOSE_FILE),
                    "images",
                    "gvmd",
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return "Greenbone Community Containers" if result.returncode == 0 else None

    @staticmethod
    def _seconds_remaining(context: ProviderContext) -> float:
        if context.deadline_at is None:
            return 300.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, (deadline - datetime.now(UTC)).total_seconds())

    def _bridge(self, context: ProviderContext, payload: dict) -> dict:
        timeout = min(30.0, self._seconds_remaining(context))
        remote_url = os.environ.get("OPENVAS_BRIDGE_URL", "").rstrip("/")
        if remote_url:
            token = os.environ.get("OPENVAS_BRIDGE_TOKEN", "")
            if len(token) < 32:
                raise RuntimeError("OpenVAS bridge token is not configured")
            try:
                response = httpx.post(
                    f"{remote_url}/v1/bridge",
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                    timeout=timeout,
                    follow_redirects=False,
                )
                response.raise_for_status()
                result = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise RuntimeError("Remote Greenbone bridge request failed") from exc
            if not result.get("ok"):
                error = str(result.get("error") or "request failed")[:300]
                raise RuntimeError(f"Greenbone: {error}")
            return dict(result.get("data") or {})
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError("Docker is not installed")
        try:
            result = subprocess.run(  # noqa: S603 - fixed local Docker command
                [
                    docker,
                    "compose",
                    "-f",
                    str(COMPOSE_FILE),
                    "run",
                    "--rm",
                    "--no-deps",
                    "-T",
                    "gvm-tools",
                    "python3",
                    "/opt/cypheryn/gmp_bridge.py",
                ],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Greenbone management request timed out") from exc
        output = result.stdout.strip().splitlines()
        try:
            response = json.loads(output[-1]) if output else {}
        except json.JSONDecodeError as exc:
            raise RuntimeError("Greenbone management bridge returned an invalid response") from exc
        if result.returncode != 0 or not response.get("ok"):
            error = str(response.get("error") or result.stderr.strip() or "request failed")
            raise RuntimeError(f"Greenbone: {error[:300]}")
        return dict(response.get("data") or {})

    @staticmethod
    def _raise_if_cancelled(context: ProviderContext) -> None:
        context.db.refresh(context.job, attribute_names=["cancellation_requested_at"])
        if context.job.cancellation_requested_at is not None:
            raise ProviderCancelledError("OpenVAS scan was cancelled")

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        username = str(context.credentials.get("username") or "").strip()
        password = str(context.credentials.get("password") or "")
        if not os.environ.get("OPENVAS_BRIDGE_URL") and (not username or not password):
            raise RuntimeError("OpenVAS username and password are required")

        request = {
            "target": target,
            "task_name": (
                f"CYPHERYN-{context.job.investigation_id}-{context.target.id}"
            ),
        }
        if not os.environ.get("OPENVAS_BRIDGE_URL"):
            request.update({"username": username, "password": password})
        while True:
            self._raise_if_cancelled(context)
            try:
                latest = self._bridge(context, request)
                break
            except (RuntimeError, TimeoutError) as exc:
                message = str(exc)
                initializing = (
                    isinstance(exc, TimeoutError)
                    or "did not return a config" in message
                    or "Connection reset by peer" in message
                    or "connection refused" in message.lower()
                )
                if not initializing:
                    raise
                if self._seconds_remaining(context) <= 12:
                    raise TimeoutError(
                        "Greenbone is still importing its scan configurations"
                    ) from exc
                time.sleep(min(10.0, self._seconds_remaining(context) - 7.0))
        while latest.get("status") not in {"Done", "Stopped", "Interrupted"}:
            self._raise_if_cancelled(context)
            if self._seconds_remaining(context) <= 7:
                progress = int(latest.get("progress") or 0)
                raise TimeoutError(
                    f"OpenVAS scanner deadline reached while its persisted task is still "
                    f"running ({progress}% complete); the target did not fail"
                )
            time.sleep(min(5.0, max(1.0, self._seconds_remaining(context) - 5.0)))
            latest = self._bridge(context, request)

        if latest.get("status") != "Done":
            raise RuntimeError(f"OpenVAS scan ended with status {latest.get('status', 'Unknown')}")

        rows = list(latest.get("results") or [])[:500]
        # A stable task name lets a later collection job resume an OpenVAS
        # scan that outlived an earlier worker deadline. Once its evidence is
        # safely in memory, remove the completed task so a future rescan starts
        # a genuinely fresh assessment.
        try:
            self._bridge(context, {**request, "action": "delete_task"})
        except (RuntimeError, TimeoutError):
            pass
        entities = []
        findings = []
        for row in rows:
            host = str(row.get("host") or target)
            port = str(row.get("port") or "general")
            asset = f"{host}:{port}" if port != "general" else host
            cves = [str(value).upper() for value in row.get("cves") or []]
            rule_id = (
                f"vuln.cve.{cves[0]}" if cves else f"openvas.{row.get('oid') or row.get('id')}"
            )
            description = str(row.get("description") or "OpenVAS detected a vulnerability.")
            solution = str(row.get("solution") or "").strip()
            if solution:
                description = f"{description}\n\nRemediation: {solution}"
            entities.append(
                self._entity(
                    context,
                    "vulnerability",
                    f"{asset}|{rule_id}",
                    {
                        "source": self.name,
                        "host": host,
                        "port": port,
                        "cves": cves,
                        "cvss": row.get("cvss"),
                        "qod": row.get("qod"),
                        "solution": solution,
                    },
                )
            )
            findings.append(
                {
                    "rule_id": rule_id[:100],
                    "title": str(row.get("name") or rule_id)[:300],
                    "description": description,
                    "severity": str(row.get("severity") or "info"),
                    "confidence": max(1, min(int(float(row.get("qod") or 80)), 100)),
                    "asset_value": asset,
                    "entity_value": f"{asset}|{rule_id}",
                }
            )

        payload = {
            "target": target,
            "task_id": latest.get("task_id"),
            "report_id": latest.get("report_id"),
            "status": latest.get("status"),
            "progress": latest.get("progress"),
            "results": rows,
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=len(entities),
            entity_ids=tuple(item.id for item in entities),
            metadata={
                "finding_candidates": findings,
                "scan_status": latest.get("status"),
                "scan_progress": latest.get("progress"),
                "task_id": latest.get("task_id"),
                "report_id": latest.get("report_id"),
            },
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload=payload,
        )
