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
