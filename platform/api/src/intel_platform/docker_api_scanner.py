from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Sequence

import httpx

from .scanner_isolation import (
    ScannerCancelledError,
    ScannerExecutionResult,
    ScannerIsolationError,
    ScannerPolicy,
    ScannerUnavailableError,
)

CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")
NAMESPACE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


class DockerApiScannerRunner:
    """Minimal Docker Engine API client for the trusted orchestrator only."""

    def __init__(
        self,
        socket_path: str = "/var/run/docker.sock",
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.transport = transport or httpx.HTTPTransport(uds=socket_path)
        self.namespace = os.environ.get("SCANNER_ORCHESTRATOR_NAMESPACE", "cypheryn")
        if not NAMESPACE.fullmatch(self.namespace):
            raise ScannerIsolationError("Scanner orchestrator namespace is invalid")

    @property
    def available(self) -> bool:
        try:
            with self._client() as client:
                return client.get("/_ping").status_code == 200
        except httpx.HTTPError:
            return False

    def run(
        self,
        command: Sequence[str],
        policy: ScannerPolicy,
        *,
        cancellation: threading.Event | None = None,
    ) -> ScannerExecutionResult:
        try:
            return self._run(command, policy, cancellation=cancellation)
        except httpx.HTTPError as exc:
            raise ScannerUnavailableError("Docker Engine is unavailable") from exc

    def _run(
        self,
        command: Sequence[str],
        policy: ScannerPolicy,
        *,
        cancellation: threading.Event | None = None,
    ) -> ScannerExecutionResult:
        policy.validate()
        if not command or any("\x00" in value for value in command):
            raise ScannerIsolationError("Scanner command is empty or invalid")
        started_at = time.time()
        container_id = ""
        timed_out = False
        cancelled = False
        with self._client() as client:
            if policy.network.startswith("cypheryn-egress-"):
                network = client.get(f"/networks/{policy.network}")
                self._require(network, "inspect scanner egress network")
                labels = network.json().get("Labels") or {}
                if labels.get("cypheryn.egress-policy") != "enforced":
                    raise ScannerIsolationError(
                        "Scanner egress network is missing the enforced-policy label"
                    )
            response = client.post(
                "/containers/create",
                json={
                    "Image": policy.image,
                    "Cmd": list(command),
                    # Raw-packet scanners need uid 0 in their isolated user
                    # namespace to activate the two explicitly bounded network
                    # capabilities. All other scanners retain the image user.
                    "User": "0:0" if policy.capabilities else "",
                    "Env": [f"{key}={value}" for key, value in policy.environment.items()],
                    "AttachStdout": True,
                    "AttachStderr": True,
                    "Tty": False,
                    "Labels": {
                        "cypheryn.scanner.managed": "true",
                        "cypheryn.scanner.namespace": self.namespace,
                    },
                    "HostConfig": {
                        "ReadonlyRootfs": True,
                        "CapDrop": ["ALL"],
                        "CapAdd": list(policy.capabilities),
                        "SecurityOpt": ["no-new-privileges:true"],
                        "NanoCpus": int(policy.cpu_limit * 1_000_000_000),
                        "Memory": policy.memory_mb * 1024 * 1024,
                        "PidsLimit": policy.pids_limit,
                        "NetworkMode": policy.network,
                        "Tmpfs": {
                            "/tmp": (  # noqa: S108 - isolated in-container bounded tmpfs
                                "rw,noexec,nosuid,nodev," f"size={policy.tmpfs_mb * 1024 * 1024}"
                            )
                        },
                    },
                },
            )
            self._require(response, "create scanner container")
            container_id = str(response.json().get("Id", ""))
            if not CONTAINER_ID.fullmatch(container_id):
                raise ScannerIsolationError("Docker returned an invalid container identifier")
            self._require(client.post(f"/containers/{container_id}/start"), "start scanner")
            deadline = time.monotonic() + policy.timeout_seconds
            while True:
                if cancellation is not None and cancellation.is_set():
                    cancelled = True
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                inspection = client.get(f"/containers/{container_id}/json")
                self._require(inspection, "inspect scanner")
                if not inspection.json().get("State", {}).get("Running", False):
                    break
                time.sleep(0.05)
            if cancelled or timed_out:
                client.delete(f"/containers/{container_id}", params={"force": "1", "v": "1"})
            logs = client.get(
                f"/containers/{container_id}/logs",
                params={"stdout": "1", "stderr": "1"},
            )
            output = logs.content if logs.status_code == 200 else b""
            inspection = client.get(f"/containers/{container_id}/json")
            returncode = (
                int(inspection.json().get("State", {}).get("ExitCode", -1))
                if inspection.status_code == 200
                else -1
            )
            client.delete(f"/containers/{container_id}", params={"force": "1", "v": "1"})
        ended_at = time.time()
        stdout, stderr, truncated = self._decode_logs(output, policy.output_limit_bytes)
        if cancelled:
            raise ScannerCancelledError("Scanner execution was cancelled")
        if timed_out:
            raise TimeoutError(f"Scanner exceeded {policy.timeout_seconds:.1f} second limit")
        return ScannerExecutionResult(
            command=tuple(command),
            image=policy.image,
            container_id=container_id,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            ended_at=ended_at,
            output_truncated=truncated,
        )

    def cleanup_managed(self) -> int:
        filters = json.dumps(
            {
                "label": [
                    "cypheryn.scanner.managed=true",
                    f"cypheryn.scanner.namespace={self.namespace}",
                ]
            }
        )
        try:
            with self._client() as client:
                response = client.get("/containers/json", params={"all": "1", "filters": filters})
                self._require(response, "list managed scanner containers")
                container_ids = [
                    str(item.get("Id", ""))
                    for item in response.json()
                    if CONTAINER_ID.fullmatch(str(item.get("Id", "")))
                ]
                for container_id in container_ids:
                    client.delete(
                        f"/containers/{container_id}", params={"force": "1", "v": "1"}
                    )
                return len(container_ids)
        except httpx.HTTPError as exc:
            raise ScannerUnavailableError("Docker Engine is unavailable") from exc

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url="http://docker",
            transport=self.transport,
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=False,
        )

    @staticmethod
    def _require(response: httpx.Response, operation: str) -> None:
        if response.status_code >= 400:
            raise ScannerIsolationError(f"Docker could not {operation}")

    @staticmethod
    def _decode_logs(data: bytes, limit: int) -> tuple[str, str, bool]:
        stdout = bytearray()
        stderr = bytearray()
        consumed = 0
        index = 0
        framed = False
        while index + 8 <= len(data):
            stream = data[index]
            size = int.from_bytes(data[index + 4 : index + 8], "big")
            end = index + 8 + size
            if stream not in {1, 2} or data[index + 1 : index + 4] != b"\0\0\0" or end > len(data):
                break
            framed = True
            payload = data[index + 8 : end]
            budget = max(0, limit - consumed)
            target = stdout if stream == 1 else stderr
            target.extend(payload[:budget])
            consumed += len(payload)
            index = end
        if not framed:
            return data[:limit].decode(errors="replace"), "", len(data) > limit
        return (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
            consumed > limit or index < len(data),
        )
