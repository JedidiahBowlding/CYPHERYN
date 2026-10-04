#!/usr/bin/env python3
"""Measure the deterministic evaluator without setting pass/fail latency thresholds."""

from __future__ import annotations

import json
import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from intel_platform.auth import Principal, WorkloadPrincipal, get_principal, get_workload_principal
from intel_platform.database import Base, get_db
from intel_platform.main import app


def percentile(values: list[float], percentage: int) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentage / 100) * (len(ordered) - 1))))
    return ordered[index]


def require_status(response, expected: int) -> None:
    if response.status_code != expected:
        raise RuntimeError(
            f"Expected HTTP {expected}, received {response.status_code}: {response.text}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cypheryn-evaluator-benchmark-") as directory:
        engine = create_engine(
            f"sqlite:///{Path(directory) / 'benchmark.db'}",
            connect_args={"check_same_thread": False},
        )
        sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        Base.metadata.create_all(engine)

        def override_db():
            with sessions() as db:
                yield db

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_principal] = lambda: Principal(
            subject="benchmark-admin", email="benchmark@example.test"
        )
        try:
            with TestClient(app) as client:
                acceptance = client.post(
                    "/api/v1/legal/acceptance",
                    json={
                        "accepted": True,
                        "terms_version": "1.0",
                        "responsible_use_version": "1.0",
                    },
                )
                require_status(acceptance, 200)
                organization_id = client.post(
                    "/api/v1/organizations", json={"name": "Evaluator benchmark"}
                ).json()["id"]
                security_client_id = client.post(
                    "/api/v1/security/clients",
                    json={
                        "organization_id": organization_id,
                        "external_client_id": "benchmark-workload",
                        "name": "Benchmark workload",
                    },
                ).json()["id"]
                agent_id = client.post(
                    "/api/v1/security/agents",
                    json={
                        "organization_id": organization_id,
                        "security_client_id": security_client_id,
                        "name": "benchmark-agent",
                    },
                ).json()["id"]
                grant = client.post(
                    f"/api/v1/security/agents/{agent_id}/capability-grants",
                    json={"organization_id": organization_id, "capability": "web.read"},
                )
                require_status(grant, 201)
                destination = client.post(
                    "/api/v1/security/destinations",
                    json={
                        "organization_id": organization_id,
                        "destination": "https://8.8.8.8",
                        "trust_state": "TRUSTED",
                    },
                )
                require_status(destination, 201)
                app.dependency_overrides[get_workload_principal] = lambda: WorkloadPrincipal(
                    subject="benchmark-workload@clients", client_id="benchmark-workload"
                )

                query_count = 0

                def count_query(*_args) -> None:
                    nonlocal query_count
                    query_count += 1

                event.listen(engine, "before_cursor_execute", count_query)

                def evaluate(number: int):
                    payload = {
                        "agent_id": agent_id,
                        "action": "fetch",
                        "capability": "web.read",
                        "destination": "https://8.8.8.8",
                        "environment": "production",
                        "data_classifications": ["PUBLIC"],
                        "resource_scope": {"method": "GET"},
                        "context": {"purpose": "benchmark"},
                        "request_id": f"benchmark-request-{number:08d}",
                        "idempotency_key": f"benchmark-idempotency-{number:08d}",
                        "nonce": f"benchmark-nonce-value-{number:08d}",
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                    started = time.perf_counter()
                    response = client.post("/api/v1/security/evaluate", json=payload)
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    require_status(response, 201)
                    return elapsed_ms, response.json()["decision_id"]

                sequential_count = 50
                sequential_results = [evaluate(number) for number in range(sequential_count)]
                latencies = [item[0] for item in sequential_results]
                sequential_queries = query_count

                query_count = 0
                validation_latencies = []
                validation_payload = {
                    "action": "fetch",
                    "capability": "web.read",
                    "destination": "https://8.8.8.8",
                    "environment": "production",
                    "resource_scope": {"method": "GET"},
                    "connected_address": "8.8.8.8",
                    "consume": False,
                }
                for _elapsed, decision_id in sequential_results:
                    started = time.perf_counter()
                    response = client.post(
                        f"/api/v1/security/decisions/{decision_id}/validate",
                        json=validation_payload,
                    )
                    validation_latencies.append((time.perf_counter() - started) * 1000)
                    require_status(response, 200)
                    if not response.json()["valid"]:
                        raise RuntimeError(response.text)
                validation_queries = query_count

                query_count = 0
                concurrent_started = time.perf_counter()
                with ThreadPoolExecutor(max_workers=8) as pool:
                    concurrent_results = list(
                        pool.map(evaluate, range(sequential_count, sequential_count + 32))
                    )
                concurrent_latencies = [item[0] for item in concurrent_results]
                concurrent_elapsed_ms = (time.perf_counter() - concurrent_started) * 1000
                result = {
                    "engine": "sqlite-local-deterministic-baseline",
                    "sequential_requests": sequential_count,
                    "latency_ms": {
                        "mean": round(statistics.mean(latencies), 3),
                        "p50": round(percentile(latencies, 50), 3),
                        "p95": round(percentile(latencies, 95), 3),
                        "max": round(max(latencies), 3),
                    },
                    "queries_per_sequential_decision": round(
                        sequential_queries / sequential_count, 2
                    ),
                    "validation_latency_ms": {
                        "mean": round(statistics.mean(validation_latencies), 3),
                        "p50": round(percentile(validation_latencies, 50), 3),
                        "p95": round(percentile(validation_latencies, 95), 3),
                        "max": round(max(validation_latencies), 3),
                    },
                    "queries_per_final_validation": round(
                        validation_queries / sequential_count, 2
                    ),
                    "concurrent_requests": len(concurrent_latencies),
                    "concurrent_workers": 8,
                    "concurrent_wall_ms": round(concurrent_elapsed_ms, 3),
                    "concurrent_p95_ms": round(percentile(concurrent_latencies, 95), 3),
                    "concurrent_queries": query_count,
                }
                print(json.dumps(result, indent=2, sort_keys=True))
        finally:
            app.dependency_overrides.clear()
            engine.dispose()


if __name__ == "__main__":
    main()
