from __future__ import annotations

import hmac
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from .docker_api_scanner import DockerApiScannerRunner
from .scanner_isolation import (
    ScannerCancelledError,
    ScannerExecutionResult,
    ScannerIsolationError,
    ScannerPolicy,
    configured_scanner_images,
)

SCANNER_BINARIES = {
    "subfinder": "subfinder",
    "projectdiscovery_httpx": "httpx",
    "naabu": "naabu",
    "nmap": "nmap",
    "rustscan": "rustscan",
    "masscan": "masscan",
    "nuclei": "nuclei",
    "katana": "katana",
    "katana_authenticated": "cypheryn-katana-auth",
    "dnstwist": "dnstwist",
    "nikto": "cypheryn-nikto",
    "zap_passive": "cypheryn-zap-passive",
    "zap_active": "cypheryn-zap-active",
    "testssl": "cypheryn-testssl",
}
ACTIVE_SCANNERS = {
    "projectdiscovery_httpx",
    "naabu",
    "nmap",
    "rustscan",
    "masscan",
    "nuclei",
    "katana",
    "katana_authenticated",
    "nikto",
    "zap_passive",
    "zap_active",
    "testssl",
}


class ExecutionPolicyRequest(BaseModel):
    cpu_limit: float = 1.0
    memory_mb: int = 512
    pids_limit: int = 128
    timeout_seconds: float = 300.0
    output_limit_bytes: int = 2_000_000
    tmpfs_mb: int = 128
    network: str = "none"
    environment: dict[str, str] = Field(default_factory=dict, max_length=8)


class ExecutionRequest(BaseModel):
    provider: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    command: list[str] = Field(min_length=1, max_length=128)
    job_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    authorization_id: str | None = Field(default=None, max_length=128)
    policy: ExecutionPolicyRequest


@dataclass
class ExecutionState:
    execution_id: str
    request: ExecutionRequest
    image: str
    status: Literal["queued", "running", "completed", "failed", "cancelled", "timed_out"]
    created_at: float
    cancel: threading.Event = field(default_factory=threading.Event)
    result: ScannerExecutionResult | None = None
    error: str = ""


@asynccontextmanager
async def lifespan(_: FastAPI):
    runner = DockerApiScannerRunner()
    if runner.available:
        runner.cleanup_managed()
    try:
        yield
    finally:
        if runner.available:
            runner.cleanup_managed()


app = FastAPI(
    title="CYPHERYN Trusted Scanner Orchestrator",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
_executions: dict[str, ExecutionState] = {}
_lock = threading.Lock()


def _authenticate(authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("SCANNER_ORCHESTRATOR_TOKEN", "")
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if len(expected) < 32 or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


def _images() -> dict[str, str]:
    images = configured_scanner_images()
    for provider in images:
        if provider not in SCANNER_BINARIES:
            raise ScannerIsolationError(f"Unsupported scanner provider: {provider}")
    return images


@app.get("/health")
def health() -> dict[str, object]:
    images = _images()
    runner = DockerApiScannerRunner()
    if not runner.available or len(os.environ.get("SCANNER_ORCHESTRATOR_TOKEN", "")) < 32:
        raise HTTPException(status_code=503, detail="Scanner orchestrator is not ready")
    return {
        "status": "healthy",
        "docker_available": True,
        "configured_scanners": sorted(images),
    }


@app.post("/v1/executions", status_code=status.HTTP_202_ACCEPTED)
def create_execution(
    request: ExecutionRequest, _: None = Depends(_authenticate)
) -> dict[str, str]:
    images = _images()
    image = images.get(request.provider)
    if not image:
        raise HTTPException(status_code=422, detail="Scanner provider is not allowlisted")
    if request.provider in ACTIVE_SCANNERS and not request.authorization_id:
        raise HTTPException(status_code=422, detail="Active scanner authorization is required")
    expected_binary = SCANNER_BINARIES[request.provider]
    if request.command[0] != expected_binary or any("\x00" in item for item in request.command):
        raise HTTPException(status_code=422, detail="Scanner command is not allowlisted")
    if any(len(item) > 4096 for item in request.command):
        raise HTTPException(status_code=422, detail="Scanner argument exceeds the size limit")
    allowed_environment = (
        {"CYPHERYN_AUTHORIZATION_HEADER"}
        if request.provider == "katana_authenticated"
        else set()
    )
    if set(request.policy.environment) - allowed_environment or any(
        len(value) > 8192 for value in request.policy.environment.values()
    ):
        raise HTTPException(status_code=422, detail="Scanner environment is not allowlisted")
    capabilities = ("NET_ADMIN", "NET_RAW") if request.provider == "masscan" else ()
    policy = ScannerPolicy(
        image=image,
        capabilities=capabilities,
        **request.policy.model_dump(),
    )
    try:
        policy.validate()
    except ScannerIsolationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    production = os.environ.get("PLATFORM_ENVIRONMENT", "development").lower() == "production"
    if production and request.provider in ACTIVE_SCANNERS and not policy.network.startswith(
        "cypheryn-egress-"
    ):
        raise HTTPException(
            status_code=422,
            detail="Production active scanners require a managed egress-policy network",
        )
    if (
        policy.cpu_limit > 2
        or policy.memory_mb > 2048
        or policy.pids_limit > 512
        or policy.timeout_seconds > 3600
        or policy.output_limit_bytes > 4_000_000
        or policy.tmpfs_mb > 512
    ):
        raise HTTPException(status_code=422, detail="Scanner policy exceeds orchestrator limits")
    execution_id = str(uuid.uuid4())
    state = ExecutionState(execution_id, request, image, "queued", time.time())
    with _lock:
        _prune()
        active = sum(value.status in {"queued", "running"} for value in _executions.values())
        maximum = max(1, min(int(os.environ.get("SCANNER_ORCHESTRATOR_MAX_JOBS", "4")), 32))
        if active >= maximum:
            raise HTTPException(status_code=429, detail="Scanner execution capacity is full")
        _executions[execution_id] = state
    threading.Thread(target=_execute, args=(state, policy), daemon=True).start()
    return {"execution_id": execution_id, "status": state.status}


def _execute(state: ExecutionState, policy: ScannerPolicy) -> None:
    state.status = "running"
    try:
        state.result = DockerApiScannerRunner().run(
            state.request.command, policy, cancellation=state.cancel
        )
        state.status = "completed"
    except ScannerCancelledError as exc:
        state.status = "cancelled"
        state.error = str(exc)
    except TimeoutError as exc:
        state.status = "timed_out"
        state.error = str(exc)
    except (OSError, ScannerIsolationError) as exc:
        state.status = "failed"
        state.error = str(exc)[:300]


@app.get("/v1/executions/{execution_id}")
def execution_status(
    execution_id: str, _: None = Depends(_authenticate)
) -> dict[str, object]:
    with _lock:
        state = _executions.get(execution_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    payload: dict[str, object] = {
        "execution_id": state.execution_id,
        "status": state.status,
        "image": state.image,
        "job_id": state.request.job_id,
        "target_id": state.request.target_id,
        "authorization_id": state.request.authorization_id,
        "created_at": state.created_at,
        "error": state.error,
    }
    if state.result is not None:
        payload.update(
            {
                "container_id": state.result.container_id,
                "returncode": state.result.returncode,
                "stdout": state.result.stdout,
                "stderr": state.result.stderr,
                "started_at": state.result.started_at,
                "ended_at": state.result.ended_at,
                "output_truncated": state.result.output_truncated,
            }
        )
    return payload


@app.delete("/v1/executions/{execution_id}", status_code=status.HTTP_202_ACCEPTED)
def cancel_execution(
    execution_id: str, _: None = Depends(_authenticate)
) -> dict[str, str]:
    with _lock:
        state = _executions.get(execution_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    if state.status in {"queued", "running"}:
        state.cancel.set()
    return {"execution_id": execution_id, "status": state.status}


def _prune() -> None:
    cutoff = time.time() - 3600
    expired = [
        key
        for key, value in _executions.items()
        if value.created_at < cutoff
        and value.status in {"completed", "failed", "cancelled", "timed_out"}
    ]
    for key in expired:
        _executions.pop(key, None)
