import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_release_version_metadata_is_consistent() -> None:
    product_version = (ROOT / "VERSION").read_text(encoding="utf-8").strip().split()[-1]
    api_version = tomllib.loads(
        (ROOT / "platform/api/pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    frontend_version = json.loads(
        (ROOT / "platform/frontend/package.json").read_text(encoding="utf-8")
    )["version"]
    lock_version = json.loads(
        (ROOT / "platform/frontend/package-lock.json").read_text(encoding="utf-8")
    )["version"]
    assert product_version == api_version == frontend_version == lock_version


def test_release_workflow_uses_only_current_public_brand() -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    security = (ROOT / ".github/workflows/security-supply-chain.yml").read_text(
        encoding="utf-8"
    )
    workflows = release + security
    assert "SignalTrace" not in workflows
    assert "signaltrace-" not in workflows
    for image in ("api", "worker", "frontend", "taxii", "scanner-orchestrator"):
        assert f"cypheryn-{image}" in workflows
    assert 'dist/CYPHERYN-${GITHUB_REF_NAME}.tar.gz' in release
    assert '--title "CYPHERYN $GITHUB_REF_NAME"' in release


def test_release_publishes_digest_and_provenance_for_every_shipped_image() -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "packages: write" in release
    assert 'expected_tag="v$(awk \'{print $2}\' VERSION)"' in release
    assert "dist/image-digests.txt" in release
    for image in (
        "api",
        "worker",
        "frontend",
        "taxii",
        "scanner-orchestrator",
        "egress-proxy",
        "protected-agent-pilot",
    ):
        assert f"cypheryn-{image}" in release
    assert release.count("push-to-registry: true") == 7


def test_production_override_supports_immutable_images_and_three_proxy_replicas() -> None:
    production = (ROOT / "compose.production.yaml").read_text(encoding="utf-8")
    assert "CYPHERYN_EGRESS_PROXY_IMAGE" in production
    assert "CYPHERYN_PROTECTED_AGENT_PILOT_IMAGE" in production
    assert "replicas: ${CYPHERYN_EGRESS_PROXY_REPLICAS:-3}" in production


def test_protected_agent_alerts_fail_loudly_when_proxy_series_disappears() -> None:
    rules = (
        ROOT / "deploy/monitoring/cypheryn-protected-agent.rules.yml"
    ).read_text(encoding="utf-8")
    assert rules.count('absent(up{job="cypheryn-egress-proxy"})') >= 2
    assert "CypherynEgressReceiptPersistenceFailure" in rules
    assert "CypherynProtectedAgentBypassDetected" in rules


def test_frontend_declares_linux_rolldown_bindings_for_container_builds() -> None:
    package = json.loads(
        (ROOT / "platform/frontend/package.json").read_text(encoding="utf-8")
    )
    optional = package["optionalDependencies"]
    assert optional["@rolldown/binding-linux-x64-gnu"] == "1.2.6"
    assert optional["@rolldown/binding-linux-arm64-gnu"] == "1.2.6"
