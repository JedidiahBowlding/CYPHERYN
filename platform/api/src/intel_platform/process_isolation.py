from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import Mapping, Sequence

MAX_CAPTURE_BYTES = 2_000_000


def _sanitized_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    allowed = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "SYSTEMROOT",
            "TMP",
            "TMPDIR",
            "TEMP",
            "USERPROFILE",
        }
    }
    allowed["NO_COLOR"] = "1"
    if extra:
        allowed.update(extra)
    return allowed


def run_isolated_process(
    command: Sequence[str],
    *,
    timeout: float,
    stdin: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a local tool in a new process group with bounded output and hard termination."""
    creationflags = 0
    start_new_session = os.name != "nt"
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    process = subprocess.Popen(  # noqa: S603 - callers resolve an allowlisted executable
        list(command),
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_sanitized_environment(environment),
        start_new_session=start_new_session,
        creationflags=creationflags,
    )
    try:
        stdout, stderr = process.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            taskkill = os.path.join(
                os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "taskkill.exe"
            )
            subprocess.run(  # noqa: S603,S607 - fixed system utility and numeric PID
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout, stderr = process.communicate()
        raise TimeoutError(f"Process exceeded {timeout:.1f} second limit") from exc
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=process.returncode,
        stdout=stdout[:MAX_CAPTURE_BYTES],
        stderr=stderr[:MAX_CAPTURE_BYTES],
    )
