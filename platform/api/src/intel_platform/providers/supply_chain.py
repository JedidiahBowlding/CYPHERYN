import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path

from sqlalchemy import select

from ..models import Entity
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class SupplyChainProvider:
    binary = ""
    capabilities = ProviderCapabilities(target_types=frozenset(), passive_only=True)

    @cached_property
    def executable(self) -> str | None:
        return shutil.which(self.binary)

    @cached_property
    def available(self) -> bool:
        return self.executable is not None

    @cached_property
    def version(self) -> str | None:
        if not self.executable:
            return None
        try:
            result = subprocess.run(  # noqa: S603
                [self.executable, "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return (result.stdout or result.stderr).strip().splitlines()[0][:160]

    def run(self, context: ProviderContext, arguments: list[str]):
        if not self.executable:
            raise RuntimeError(f"{self.name} is not installed")
        timeout = 120.0
        if context.deadline_at:
            deadline = context.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            timeout = max(1.0, (deadline - datetime.now(UTC)).total_seconds())
        try:
            return subprocess.run(  # noqa: S603
                [self.executable, *arguments],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={**os.environ, "NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"{self.name} exceeded its time limit") from exc

    def finish(self, context: ProviderContext, summary: dict, findings: list[dict]):
        unique = {(item["rule_id"], item["asset_value"]): item for item in findings}
        findings = list(unique.values())[:5000]
        summary["finding_count"] = len(findings)
        entity = self._entity(context, summary)
        encoded = json.dumps(summary, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=max(len(findings), int(summary.get("component_count", 0))),
            entity_ids=(entity.id,),
            metadata={"finding_candidates": findings, "target": context.target.canonical_value},
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload={"target": context.target.canonical_value, **summary},
        )

    def _entity(self, context: ProviderContext, attributes: dict):
        value = context.target.canonical_value
        entity = context.db.scalar(
            select(Entity).where(
                Entity.investigation_id == context.job.investigation_id,
                Entity.entity_type == context.target.target_type.value,
                Entity.canonical_value == value,
            )
        )
        if entity is None:
            entity = Entity(
                investigation_id=context.job.investigation_id,
                entity_type=context.target.target_type.value,
                canonical_value=value,
                confidence=100,
                provider=self.name,
                attributes={"classification": "OBSERVED_FACT", **attributes},
            )
            context.db.add(entity)
            context.db.flush()
        else:
            entity.attributes = {**(entity.attributes or {}), **attributes}
        return entity

    @staticmethod
    def finding(context, rule, title, description, severity, asset, confidence=95):
        normalized = str(severity).lower()
        if normalized not in {"critical", "high", "medium", "low"}:
            normalized = "medium"
        return {
            "rule_id": rule[:100],
            "title": title[:300],
            "description": description[:4000],
            "severity": normalized,
            "confidence": confidence,
            "asset_value": asset[:2048],
            "entity_value": context.target.canonical_value,
        }


class SyftProvider(SupplyChainProvider):
    name = "syft"
    binary = "syft"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"container_image"}), passive_only=True
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        result = self.run(
            context,
            [context.target.canonical_value, "--output", "cyclonedx-json", "--quiet"],
        )
        if result.returncode != 0:
            raise RuntimeError("Syft SBOM generation failed")
        payload = json.loads(result.stdout or "{}")
        components = []
        for item in (payload.get("components") or [])[:5000]:
            components.append(
                {
                    "name": str(item.get("name") or "unknown")[:300],
                    "version": str(item.get("version") or "")[:200],
                    "type": str(item.get("type") or "library")[:50],
                    "purl": str(item.get("purl") or "")[:1000],
                }
            )
        summary = {
            "bom_format": "CycloneDX",
            "spec_version": payload.get("specVersion"),
            "component_count": len(components),
            "components": components,
            "sbom_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        }
        return self.finish(context, summary, [])


class GrypeProvider(SupplyChainProvider):
    name = "grype"
    binary = "grype"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"container_image", "sbom"}), passive_only=True
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = context.target.canonical_value
        if context.target.target_type.value == "sbom":
            target = f"sbom:{Path(target)}"
        result = self.run(context, [target, "--output", "json", "--quiet"])
        if result.returncode not in {0, 1}:
            raise RuntimeError("Grype vulnerability scan failed")
        payload = json.loads(result.stdout or "{}")
        findings, vulnerabilities = [], []
        for match in (payload.get("matches") or [])[:5000]:
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            vuln_id = str(vulnerability.get("id") or "CVE")
            package = str(artifact.get("name") or "package")
            version = str(artifact.get("version") or "unknown")
            fixed = [str(item) for item in vulnerability.get("fix", {}).get("versions", [])]
            asset = f"{package}:{version}:{vuln_id}"
            findings.append(
                self.finding(
                    context,
                    f"container.{vuln_id}",
                    f"{vuln_id} affects {package}",
                    (
                        f"{package} {version} is affected by {vuln_id}. Fixed versions: "
                        f"{', '.join(fixed) or 'not listed'}."
                    ),
                    vulnerability.get("severity") or "medium",
                    asset,
                )
            )
            vulnerabilities.append(
                {"id": vuln_id, "package": package, "version": version, "fixed_versions": fixed}
            )
        return self.finish(
            context,
            {"vulnerability_count": len(vulnerabilities), "vulnerabilities": vulnerabilities},
            findings,
        )


class TrivyProvider(SupplyChainProvider):
    name = "trivy"
    binary = "trivy"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"container_image"}), passive_only=True
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        result = self.run(
            context,
            [
                "image",
                "--format",
                "json",
                "--quiet",
                "--scanners",
                "vuln,secret,misconfig",
                "--image-config-scanners",
                "misconfig,secret",
                context.target.canonical_value,
            ],
        )
        if result.returncode not in {0, 1}:
            raise RuntimeError("Trivy image scan failed")
        payload = json.loads(result.stdout or "{}")
        findings, vulnerabilities, secrets, misconfigurations = [], [], [], []
        for section in payload.get("Results") or []:
            target = str(section.get("Target") or context.target.canonical_value)
            for row in section.get("Vulnerabilities") or []:
                vuln_id = str(row.get("VulnerabilityID") or "CVE")
                package = str(row.get("PkgName") or "package")
                installed = str(row.get("InstalledVersion") or "unknown")
                fixed = str(row.get("FixedVersion") or "")
                asset = f"{package}:{installed}:{vuln_id}"
                findings.append(
                    self.finding(
                        context,
                        f"container.{vuln_id}",
                        f"{vuln_id} affects {package}",
                        (
                            f"{package} {installed} is affected by {vuln_id}. "
                            f"Fixed version: {fixed or 'not listed'}."
                        ),
                        row.get("Severity"),
                        asset,
                    )
                )
                vulnerabilities.append(
                    {
                        "id": vuln_id,
                        "package": package,
                        "version": installed,
                        "fixed_version": fixed,
                    }
                )
            for row in section.get("Secrets") or []:
                rule = str(row.get("RuleID") or "secret")
                location = f"{target}:{row.get('StartLine') or 1}"
                fingerprint = hashlib.sha256(f"{rule}:{location}".encode()).hexdigest()
                findings.append(
                    self.finding(
                        context,
                        f"image.secret.{rule}",
                        f"Potential image secret ({rule})",
                        (
                            f"A secret pattern was detected at {location}. Fingerprint: "
                            f"{fingerprint[:12]}. The secret and source excerpt were not retained."
                        ),
                        row.get("Severity") or "high",
                        location,
                        90,
                    )
                )
                secrets.append({"rule_id": rule, "location": location, "fingerprint": fingerprint})
            for row in section.get("Misconfigurations") or []:
                rule = str(row.get("ID") or "misconfiguration")
                title = str(row.get("Title") or rule)
                asset = f"{target}:{rule}"
                findings.append(
                    self.finding(
                        context,
                        f"image.config.{rule}",
                        title,
                        str(row.get("Description") or "Container configuration requires review."),
                        row.get("Severity"),
                        asset,
                        90,
                    )
                )
                misconfigurations.append({"id": rule, "title": title, "target": target})
        summary = {
            "vulnerability_count": len(vulnerabilities),
            "secret_count": len(secrets),
            "misconfiguration_count": len(misconfigurations),
            "vulnerabilities": vulnerabilities[:5000],
            "secrets": secrets[:1000],
            "misconfigurations": misconfigurations[:1000],
        }
        return self.finish(context, summary, findings)


SUPPLY_CHAIN_PROVIDERS = (SyftProvider, GrypeProvider, TrivyProvider)
