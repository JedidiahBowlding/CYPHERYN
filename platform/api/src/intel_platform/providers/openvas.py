from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path

from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult
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

    @cached_property
    def available(self) -> bool:
        return shutil.which("docker") is not None and COMPOSE_FILE.is_file()

    @cached_property
    def version(self) -> str | None:
        if not self.available:
            return None
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

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        username = str(context.credentials.get("username") or "").strip()
        password = str(context.credentials.get("password") or "")
        if not username or not password:
            raise RuntimeError("OpenVAS username and password are required")

        request = {
            "username": username,
            "password": password,
            "target": target,
            "task_name": (
                f"CYPHERYN-{context.job.investigation_id}-{context.target.id}-{context.job.id}"
            ),
        }
        while True:
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
            if self._seconds_remaining(context) <= 7:
                progress = int(latest.get("progress") or 0)
                raise TimeoutError(f"OpenVAS scan is still running ({progress}% complete)")
            time.sleep(min(5.0, max(1.0, self._seconds_remaining(context) - 5.0)))
            latest = self._bridge(context, request)

        if latest.get("status") != "Done":
            raise RuntimeError(f"OpenVAS scan ended with status {latest.get('status', 'Unknown')}")

        rows = list(latest.get("results") or [])[:500]
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
