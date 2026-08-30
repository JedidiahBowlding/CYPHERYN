from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .process_isolation import MAX_CAPTURE_BYTES

IMAGE_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,299}$")
SAFE_ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ScannerIsolationError(RuntimeError):
    pass


class ScannerUnavailableError(ScannerIsolationError):
    pass


class ScannerCancelledError(ScannerIsolationError):
    pass


@dataclass(frozen=True)
class ScannerPolicy:
    image: str
    cpu_limit: float = 1.0
    memory_mb: int = 512
    pids_limit: int = 128
    timeout_seconds: float = 300.0
    output_limit_bytes: int = MAX_CAPTURE_BYTES
    tmpfs_mb: int = 128
    network: str = "none"
    environment: Mapping[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not IMAGE_PATTERN.fullmatch(self.image) or "latest" in self.image.rsplit("/", 1)[-1]:
            raise ScannerIsolationError("Scanner image must be an explicit, valid tag or digest")
        if not 0.1 <= self.cpu_limit <= 16:
            raise ScannerIsolationError("Scanner CPU limit must be between 0.1 and 16")
        if not 64 <= self.memory_mb <= 32768:
            raise ScannerIsolationError("Scanner memory limit must be between 64 and 32768 MiB")
        if not 16 <= self.pids_limit <= 4096:
            raise ScannerIsolationError("Scanner PID limit must be between 16 and 4096")
        if not 1 <= self.timeout_seconds <= 86400:
            raise ScannerIsolationError("Scanner timeout must be between 1 second and 24 hours")
        if not 1024 <= self.output_limit_bytes <= 16_000_000:
            raise ScannerIsolationError("Scanner output limit is outside the permitted range")
        if not 16 <= self.tmpfs_mb <= 4096:
            raise ScannerIsolationError("Scanner temporary filesystem limit is invalid")
        if self.network not in {"none", "bridge"} and not self.network.startswith("signaltrace-"):
            raise ScannerIsolationError(
                "Scanner network must be none, bridge, or SignalTrace-managed"
            )
        if any(not SAFE_ENV_PATTERN.fullmatch(key) for key in self.environment):
            raise ScannerIsolationError("Scanner environment contains an invalid variable name")


@dataclass(frozen=True)
class ScannerExecutionResult:
    command: tuple[str, ...]
    image: str
    container_id: str
    returncode: int
    stdout: str
    stderr: str
    started_at: float
    ended_at: float
    timed_out: bool = False
    cancelled: bool = False
    output_truncated: bool = False


def configured_scanner_images() -> dict[str, str]:
    raw = os.environ.get("PLATFORM_SCANNER_IMAGES", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ScannerIsolationError("PLATFORM_SCANNER_IMAGES must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ScannerIsolationError("PLATFORM_SCANNER_IMAGES must be a JSON object")
    return {str(key): str(value) for key, value in parsed.items()}


class DisposableScannerRunner:
    """Launch one scanner job in one disposable Docker container.

    This trusted orchestrator requires Docker access, but scanner containers never
    receive the Docker socket, application environment, host mounts, or repository access.
    """

    def __init__(self, docker_executable: str | None = None) -> None:
        self.docker = docker_executable or shutil.which("docker")

    def run(
        self,
        command: Sequence[str],
        policy: ScannerPolicy,
        *,
        cancellation: threading.Event | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> ScannerExecutionResult:
        policy.validate()
        if not command or any("\x00" in value for value in command):
            raise ScannerIsolationError("Scanner command is empty or invalid")
        if not self.docker:
            raise ScannerUnavailableError("Docker is required for isolated scanner execution")
        started_at = time.time()
        with tempfile.TemporaryDirectory(prefix="signaltrace-scanner-") as temporary:
            cidfile = Path(temporary) / "container.id"
            docker_command = self._docker_command(command, policy, cidfile)
            process = subprocess.Popen(  # noqa: S603 - fixed Docker executable, array arguments
                docker_command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self._docker_environment(),
                start_new_session=os.name != "nt",
            )
            deadline = time.monotonic() + policy.timeout_seconds
            timed_out = False
            cancelled = False
            while process.poll() is None:
                if (cancellation is not None and cancellation.is_set()) or (
                    cancel_requested is not None and cancel_requested()
                ):
                    cancelled = True
                    self._force_remove(cidfile)
                    process.kill()
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    self._force_remove(cidfile)
                    process.kill()
                    break
                time.sleep(0.05)
            stdout, stderr = process.communicate()
            container_id = self._container_id(cidfile)
            self._force_remove(cidfile)
        ended_at = time.time()
        truncated = (
            len(stdout.encode()) > policy.output_limit_bytes
            or len(stderr.encode()) > policy.output_limit_bytes
        )
        stdout = stdout.encode()[: policy.output_limit_bytes].decode(errors="replace")
        stderr = stderr.encode()[: policy.output_limit_bytes].decode(errors="replace")
        result = ScannerExecutionResult(
            command=tuple(command),
            image=policy.image,
            container_id=container_id,
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            ended_at=ended_at,
            timed_out=timed_out,
            cancelled=cancelled,
            output_truncated=truncated,
        )
        if cancelled:
            raise ScannerCancelledError("Scanner execution was cancelled")
        if timed_out:
            raise TimeoutError(f"Scanner exceeded {policy.timeout_seconds:.1f} second limit")
        return result

    def _docker_command(
        self, command: Sequence[str], policy: ScannerPolicy, cidfile: Path
    ) -> list[str]:
        result = [
            str(self.docker),
            "run",
            "--rm",
            "--cidfile",
            str(cidfile),
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--label=signaltrace.scanner.managed=true",
            f"--cpus={policy.cpu_limit}",
            f"--memory={policy.memory_mb}m",
            f"--pids-limit={policy.pids_limit}",
            f"--network={policy.network}",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_mb}m",
        ]
        for key, value in sorted(policy.environment.items()):
            result.extend(["--env", f"{key}={value}"])
        return [*result, policy.image, *command]

    def cleanup_managed(self) -> int:
        """Remove scanner containers orphaned by an orchestrator restart."""
        if not self.docker:
            raise ScannerUnavailableError("Docker is required for scanner cleanup")
        discovered = subprocess.run(  # noqa: S603 - fixed Docker command
            [
                str(self.docker),
                "ps",
                "-aq",
                "--filter",
                "label=signaltrace.scanner.managed=true",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=self._docker_environment(),
        )
        container_ids = [
            value
            for value in discovered.stdout.splitlines()
            if re.fullmatch(r"[a-f0-9]{12,64}", value)
        ]
        if not container_ids:
            return 0
        subprocess.run(  # noqa: S603 - fixed Docker command and validated IDs
            [str(self.docker), "rm", "-f", *container_ids],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            env=self._docker_environment(),
        )
        return len(container_ids)

    @staticmethod
    def _docker_environment() -> dict[str, str]:
        return {
            key: value
            for key, value in os.environ.items()
            if key in {"DOCKER_HOST", "DOCKER_CONTEXT", "HOME", "PATH", "SYSTEMROOT", "TEMP"}
        }

    @staticmethod
    def _container_id(cidfile: Path) -> str:
        try:
            return cidfile.read_text(encoding="utf-8").strip()[:128]
        except OSError:
            return ""

    def _force_remove(self, cidfile: Path) -> None:
        container_id = self._container_id(cidfile)
        if not container_id or not self.docker:
            return
        subprocess.run(  # noqa: S603 - fixed Docker command and validated container ID
            [str(self.docker), "rm", "-f", container_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            env=self._docker_environment(),
        )
