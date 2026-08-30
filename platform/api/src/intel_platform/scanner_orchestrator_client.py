from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

import httpx

from .scanner_isolation import (
    ScannerCancelledError,
    ScannerExecutionResult,
    ScannerIsolationError,
    ScannerPolicy,
    ScannerUnavailableError,
)


class ScannerOrchestratorClient:
    """Narrow client used by workers that deliberately have no Docker access."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        poll_interval: float = 0.25,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            raise ScannerUnavailableError("Scanner orchestrator URL is invalid")
        if len(token) < 32:
            raise ScannerUnavailableError("Scanner orchestrator token is not configured")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.poll_interval = poll_interval
        self.transport = transport

    def run(
        self,
        provider: str,
        command: Sequence[str],
        policy: ScannerPolicy,
        *,
        job_id: str,
        target_id: str,
        authorization_id: str | None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> ScannerExecutionResult:
        policy.validate()
        headers = {"Authorization": f"Bearer {self.token}"}
        request = {
            "provider": provider,
            "command": list(command),
            "job_id": job_id,
            "target_id": target_id,
            "authorization_id": authorization_id,
            "policy": {
                "cpu_limit": policy.cpu_limit,
                "memory_mb": policy.memory_mb,
                "pids_limit": policy.pids_limit,
                "timeout_seconds": policy.timeout_seconds,
                "output_limit_bytes": policy.output_limit_bytes,
                "tmpfs_mb": policy.tmpfs_mb,
                "network": policy.network,
            },
        }
        timeout = httpx.Timeout(10.0, connect=5.0)
        try:
            with httpx.Client(
                timeout=timeout, follow_redirects=False, transport=self.transport
            ) as client:
                response = client.post(
                    f"{self.base_url}/v1/executions", headers=headers, json=request
                )
                self._raise_for_status(response)
                execution_id = str(response.json()["execution_id"])
                deadline = time.monotonic() + policy.timeout_seconds + 20
                while time.monotonic() < deadline:
                    if cancel_requested is not None and cancel_requested():
                        client.delete(
                            f"{self.base_url}/v1/executions/{execution_id}", headers=headers
                        )
                        raise ScannerCancelledError("Scanner execution was cancelled")
                    response = client.get(
                        f"{self.base_url}/v1/executions/{execution_id}", headers=headers
                    )
                    self._raise_for_status(response)
                    payload = response.json()
                    if payload["status"] == "completed":
                        return ScannerExecutionResult(
                            command=tuple(command),
                            image=str(payload["image"]),
                            container_id=str(payload.get("container_id", "")),
                            returncode=int(payload["returncode"]),
                            stdout=str(payload.get("stdout", "")),
                            stderr=str(payload.get("stderr", "")),
                            started_at=float(payload["started_at"]),
                            ended_at=float(payload["ended_at"]),
                            output_truncated=bool(payload.get("output_truncated", False)),
                        )
                    if payload["status"] in {"failed", "cancelled", "timed_out"}:
                        message = str(payload.get("error", "Scanner execution failed"))[:300]
                        if payload["status"] == "cancelled":
                            raise ScannerCancelledError(message)
                        if payload["status"] == "timed_out":
                            raise TimeoutError(message)
                        raise ScannerIsolationError(message)
                    time.sleep(self.poll_interval)
        except httpx.HTTPError as exc:
            raise ScannerUnavailableError("Scanner orchestrator is unavailable") from exc
        raise TimeoutError("Scanner orchestrator did not finish before its execution deadline")

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code in {401, 403}:
            raise ScannerUnavailableError("Scanner orchestrator authentication failed")
        if response.status_code >= 400:
            try:
                detail = str(response.json().get("detail", "request rejected"))
            except ValueError:
                detail = "request rejected"
            raise ScannerIsolationError(f"Scanner orchestrator: {detail[:300]}")
