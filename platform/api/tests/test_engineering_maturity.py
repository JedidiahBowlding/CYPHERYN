import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from intel_platform.integrity import seal_evidence_source
from intel_platform.integrity_anchor import (
    FileAnchorDestination,
    create_evidence_checkpoint,
    export_chain,
    generate_due_anchors,
    latest_anchor_metadata,
    load_active_private_key,
    rotate_signing_key,
    sign_checkpoint,
    signing_key_id,
    verify_export_anchor,
)
from intel_platform.models import Base, CollectionJob, EvidenceSource, Investigation, JobStatus
from intel_platform.observability import (
    correlation_id,
    heartbeat_worker,
    operational_snapshot,
    prometheus_metrics,
    structured_log,
    worker_heartbeat_loop,
)
from intel_platform.provider_certification import (
    ProviderTier,
    provider_tier,
    verification_freshness,
)
from intel_platform.scanner_isolation import (
    DisposableScannerRunner,
    ScannerCancelledError,
    ScannerIsolationError,
    ScannerPolicy,
    ScannerUnavailableError,
)


def test_scanner_policy_rejects_latest_and_unmanaged_networks() -> None:
    with pytest.raises(ScannerIsolationError):
        ScannerPolicy(image="scanner:latest").validate()
    with pytest.raises(ScannerIsolationError):
        ScannerPolicy(image="scanner:1.2.3", network="host").validate()


def test_scanner_command_has_hard_resource_and_filesystem_limits(tmp_path: Path) -> None:
    runner = DisposableScannerRunner("docker")
    policy = ScannerPolicy(image="scanner:1.2.3", network="cypheryn-scanner-egress")
    command = runner._docker_command(["scan", "example.test"], policy, tmp_path / "cid")
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges:true" in command
    assert "--label=cypheryn.scanner.managed=true" in command
    assert "--pids-limit=128" in command
    assert "--network=cypheryn-scanner-egress" in command
    assert not any("docker.sock" in item for item in command)


def test_scanner_runner_fails_closed_without_docker() -> None:
    runner = DisposableScannerRunner("")
    runner.docker = None
    with pytest.raises(ScannerUnavailableError):
        runner.run(["scan"], ScannerPolicy(image="scanner:1.2.3"))


def test_scanner_cancellation_terminates_container_process(monkeypatch) -> None:
    class FakeProcess:
        returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def communicate(self):
            return "", ""

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    runner = DisposableScannerRunner("docker")
    with pytest.raises(ScannerCancelledError, match="cancelled"):
        runner.run(
            ["scan"],
            ScannerPolicy(image="scanner:1.2.3"),
            cancel_requested=lambda: True,
        )


def test_scanner_output_is_bounded_and_resource_exit_is_preserved(monkeypatch) -> None:
    class FakeProcess:
        returncode = 137

        def poll(self):
            return self.returncode

        def communicate(self):
            return "x" * 4096, "memory limit"

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    result = DisposableScannerRunner("docker").run(
        ["scan"],
        ScannerPolicy(image="scanner:1.2.3", output_limit_bytes=1024),
    )
    assert result.returncode == 137
    assert result.output_truncated is True
    assert len(result.stdout) == 1024


def test_scanner_orchestrator_cleanup_removes_only_valid_managed_container_ids(
    monkeypatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="a" * 64 + "\nnot-a-container-id\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    removed = DisposableScannerRunner("docker").cleanup_managed()
    assert removed == 1
    assert "label=cypheryn.scanner.managed=true" in commands[0]
    assert commands[1][-1] == "a" * 64


def test_provider_certification_and_freshness_are_truthful() -> None:
    now = datetime.now(UTC)
    assert provider_tier("virustotal") == ProviderTier.SUPPORTED
    assert provider_tier("nmap") == ProviderTier.ADAPTER_ONLY
    assert verification_freshness(None, now=now) == "never_verified"
    assert verification_freshness(now - timedelta(days=8), now=now) == "verification_aging"
    assert verification_freshness(now - timedelta(days=31), now=now) == "verification_stale"


def test_worker_and_queue_health_are_distinct_from_api_health(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'metrics.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(
            CollectionJob(
                id="job",
                investigation_id="investigation",
                target_id="target",
                provider="virustotal",
                status=JobStatus.QUEUED,
                created_at=datetime.now(UTC) - timedelta(seconds=10),
            )
        )
        db.commit()
        snapshot = operational_snapshot(db)
        assert snapshot["worker_healthy"] is False
        assert snapshot["queue"]["queued"] == 1
        heartbeat_worker(db, "worker-1", version="0.8.0")
        snapshot = operational_snapshot(db)
        assert snapshot["worker_healthy"] is True
        metrics = prometheus_metrics(snapshot)
        assert "cypheryn_worker_healthy 1" in metrics
        assert 'cypheryn_provider_requests{provider="virustotal"} 1' in metrics


def test_observability_classifies_provider_failures_and_redacts_log_fields(
    tmp_path: Path, caplog
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'failure-metrics.db'}")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    failures = [
        ("timeout", JobStatus.FAILED, "request timed out"),
        ("throttle", JobStatus.FAILED, "HTTP 429 rate limited"),
        ("auth", JobStatus.FAILED, "HTTP 401 invalid credential"),
        ("cancel", JobStatus.CANCELLED, "cancelled by analyst"),
    ]
    with Session(engine) as db:
        for suffix, status, error in failures:
            db.add(
                CollectionJob(
                    id=f"job-{suffix}",
                    investigation_id="investigation",
                    target_id="target",
                    provider="virustotal",
                    status=status,
                    created_at=now,
                    error_summary=error,
                )
            )
        db.commit()
        metric = operational_snapshot(db)["providers"]["virustotal"]
    assert metric["timeouts"] == 1
    assert metric["throttled"] == 1
    assert metric["authentication_failures"] == 1
    assert metric["cancellations"] == 1
    assert correlation_id("valid-correlation.id") == "valid-correlation.id"
    assert correlation_id("not valid!") != "not valid!"
    sensitive_value = "must-not-appear"
    with caplog.at_level("INFO", logger="cypheryn"):
        structured_log("test.redaction", token=sensitive_value, job_id="safe")
    assert sensitive_value not in caplog.text
    assert '"job_id": "safe"' in caplog.text


def test_worker_heartbeat_loop_persists_one_poll(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'heartbeat-loop.db'}")
    Base.metadata.create_all(engine)

    class OneIterationStop:
        def __init__(self) -> None:
            self.finished = False

        def is_set(self) -> bool:
            return self.finished

        def wait(self, _interval: float) -> None:
            self.finished = True

    stop = OneIterationStop()
    worker_heartbeat_loop(
        lambda: Session(engine),
        "worker-loop",
        version="0.8.0",
        stop=stop,  # type: ignore[arg-type]
        interval_seconds=0,
    )
    with Session(engine) as db:
        assert operational_snapshot(db)["workers"][0]["id"] == "worker-loop"


def test_signed_anchor_verifies_chain_and_detects_divergence(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'anchor.db'}")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as db:
        for index in range(2):
            source = EvidenceSource(
                investigation_id="investigation",
                job_id=f"job-{index}",
                target_id="target",
                authorization_id="authorization",
                provider="virustotal",
                provider_version="v3",
                ruleset_version="provider-native",
                query="example.test",
                raw_response_hash=str(index) * 64,
                redacted_payload={"index": index},
                redaction_policy="central-default-v2",
                retrieved_at=now + timedelta(seconds=index),
                retain_until=now + timedelta(days=30),
            )
            db.add(source)
            db.flush()
            seal_evidence_source(db, source)
        db.commit()
        checkpoint, records = create_evidence_checkpoint(
            db, "investigation", application_version="0.8.0"
        )
    private_key = Ed25519PrivateKey.generate()
    anchor = sign_checkpoint(checkpoint, private_key)
    exported = export_chain(records, checkpoint)
    result = verify_export_anchor(exported, anchor, expected_key_id=anchor["signing_key_id"])
    assert result["valid"] is True
    tampered = json.loads(json.dumps(exported))
    tampered["records"][0]["query"] = "attacker.invalid"
    with pytest.raises(ValueError, match="record hash"):
        verify_export_anchor(tampered, anchor)


def test_anchor_signature_rejects_substitution() -> None:
    checkpoint = {
        "checkpoint_version": "cypheryn-checkpoint-v1",
        "scope_type": "investigation",
        "scope_id": "one",
        "chain_head": "a" * 64,
        "record_count": 1,
        "first_sequence": "one",
        "last_sequence": "one",
        "timestamp": datetime.now(UTC).isoformat(),
        "application_version": "0.8.0",
        "hash_algorithm": "sha256",
    }
    from intel_platform.integrity_anchor import IntegrityCheckpoint

    anchor = sign_checkpoint(IntegrityCheckpoint(**checkpoint), Ed25519PrivateKey.generate())
    anchor["signature"] = anchor["signature"][:-4] + "AAAA"
    with pytest.raises((InvalidSignature, ValueError)):
        verify_export_anchor({"records": [{}], "scope_id": "one"}, anchor)


def test_scheduled_anchor_bundle_is_immutable_and_key_rotation_retains_history(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'scheduled-anchor.db'}")
    Base.metadata.create_all(engine)
    key_directory = tmp_path / "keys"
    destination = tmp_path / "independent-store"
    first_key = rotate_signing_key(key_directory)
    second_key = rotate_signing_key(key_directory)
    assert first_key["key_id"] != second_key["key_id"]
    assert (key_directory / first_key["filename"]).is_file()
    active_key_id = signing_key_id(load_active_private_key(key_directory).public_key())
    assert active_key_id == second_key["key_id"]

    now = datetime.now(UTC)
    with Session(engine) as db:
        db.add(
            Investigation(
                id="investigation",
                organization_id="organization",
                owner_id="owner",
                name="Anchored investigation",
            )
        )
        source = EvidenceSource(
            investigation_id="investigation",
            job_id="job",
            target_id="target",
            authorization_id="authorization",
            provider="virustotal",
            provider_version="v3",
            ruleset_version="provider-native",
            query="example.test",
            raw_response_hash="a" * 64,
            redacted_payload={"verdict": "clean"},
            redaction_policy="central-default-v2",
            retrieved_at=now,
            retain_until=now + timedelta(days=30),
        )
        db.add(source)
        db.flush()
        seal_evidence_source(db, source)
        db.commit()

    sessions = lambda: Session(engine)  # noqa: E731 - session-factory contract
    assert (
        generate_due_anchors(
            sessions,
            key_directory=key_directory,
            destination_directory=destination,
            interval_minutes=1440,
            application_version="0.9.0",
            now=now,
        )
        == 1
    )
    assert (
        generate_due_anchors(
            sessions,
            key_directory=key_directory,
            destination_directory=destination,
            interval_minutes=1440,
            application_version="0.9.0",
            now=now,
        )
        == 0
    )
    metadata = latest_anchor_metadata(destination, "investigation")
    assert metadata is not None
    assert metadata["signing_key_id"] == second_key["key_id"]
    anchor_path = destination / metadata["anchor_filename"]
    export_path = destination / metadata["integrity_export_filename"]
    result = verify_export_anchor(
        json.loads(export_path.read_text(encoding="utf-8")),
        json.loads(anchor_path.read_text(encoding="utf-8")),
        expected_key_id=second_key["key_id"],
    )
    assert result["valid"] is True
    with pytest.raises(FileExistsError):
        FileAnchorDestination(destination).store(
            anchor_path.name.removesuffix(".anchor.json"), b"x"
        )
