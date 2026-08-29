import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import select

from ..models import Entity, Relationship
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class SourceScannerProvider:
    binary = ""
    version_args = ("--version",)
    capabilities = ProviderCapabilities(target_types=frozenset({"repository"}), passive_only=True)

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
                [self.executable, *self.version_args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return (result.stdout or result.stderr).strip().splitlines()[0][:160]

    @contextmanager
    def repository(self, context: ProviderContext):
        value = context.target.canonical_value
        if value.startswith("https://github.com/"):
            parsed = urlsplit(value)
            if parsed.hostname != "github.com":
                raise RuntimeError("Only GitHub HTTPS repository URLs are supported")
            with tempfile.TemporaryDirectory(prefix="signaltrace-repository-") as directory:
                destination = Path(directory) / "repository"
                result = subprocess.run(  # noqa: S603
                    [
                        "/usr/bin/git",
                        "clone",
                        "--depth",
                        "1",
                        "--filter=blob:none",
                        "--no-tags",
                        value,
                        str(destination),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=min(60.0, self._timeout(context)),
                    check=False,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                )
                if result.returncode != 0:
                    raise RuntimeError("Unable to clone the authorized public GitHub repository")
                yield destination
        else:
            path = Path(value).resolve(strict=True)
            if not path.is_dir() or path in {Path("/"), Path.home()}:
                raise RuntimeError("Repository target is not a safe, specific directory")
            yield path

    def run(self, context: ProviderContext, arguments: list[str]):
        if not self.executable:
            raise RuntimeError(f"{self.name} is not installed")
        try:
            return subprocess.run(  # noqa: S603
                [self.executable, *arguments],
                capture_output=True,
                text=True,
                timeout=self._timeout(context),
                check=False,
                env={**os.environ, "NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"{self.name} exceeded its time limit") from exc

    @staticmethod
    def _timeout(context: ProviderContext) -> float:
        if not context.deadline_at:
            return 60.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, (deadline - datetime.now(UTC)).total_seconds())

    def result(
        self,
        context: ProviderContext,
        root: Path,
        findings: list[dict],
        summary: dict,
    ):
        unique_findings = {(item["rule_id"], item["asset_value"]): item for item in findings}
        findings = list(unique_findings.values())
        summary["finding_count"] = len(findings)
        repository = self._entity(context, context.target.canonical_value, summary)
        correlated_assets = self._correlated_public_assets(context, root)
        relationships = [
            self._relationship(context, repository.id, entity.id) for entity in correlated_assets
        ]
        summary["correlated_public_assets"] = [
            entity.canonical_value for entity in correlated_assets
        ]
        payload = {"repository": context.target.canonical_value, **summary}
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=len(findings),
            entity_ids=(repository.id,),
            relationship_ids=tuple(item.id for item in relationships),
            metadata={"finding_candidates": findings, "target": context.target.canonical_value},
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload=payload,
        )

    def _entity(self, context: ProviderContext, value: str, attributes: dict):
        entity = context.db.scalar(
            select(Entity).where(
                Entity.investigation_id == context.job.investigation_id,
                Entity.entity_type == "repository",
                Entity.canonical_value == value,
            )
        )
        if entity is None:
            entity = Entity(
                investigation_id=context.job.investigation_id,
                entity_type="repository",
                canonical_value=value,
                confidence=100,
                provider=self.name,
                attributes={"classification": "OBSERVED_FACT", **attributes},
            )
            context.db.add(entity)
            context.db.flush()
        return entity

    @staticmethod
    def _correlated_public_assets(context: ProviderContext, root: Path) -> list[Entity]:
        domains = list(
            context.db.scalars(
                select(Entity).where(
                    Entity.investigation_id == context.job.investigation_id,
                    Entity.entity_type.in_(("domain", "subdomain")),
                )
            )
        )[:500]
        remaining = {entity.canonical_value.lower(): entity for entity in domains}
        excluded = {".git", ".venv", "node_modules", "dist", "__pycache__", ".runtime"}
        scanned = 0
        for path in root.rglob("*"):
            if scanned >= 3000 or not remaining:
                break
            try:
                relative_parts = path.relative_to(root).parts
                if any(part in excluded for part in relative_parts):
                    continue
                if not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000:
                    continue
                content = path.read_text(errors="ignore").lower()
            except OSError:
                continue
            scanned += 1
            for domain in tuple(remaining):
                if domain in content:
                    remaining.pop(domain)
        matched = {entity.canonical_value.lower(): entity for entity in domains}
        return [matched[name] for name in sorted(set(matched) - set(remaining))]

    def _relationship(
        self, context: ProviderContext, repository_id: str, public_asset_id: str
    ) -> Relationship:
        relationship = context.db.scalar(
            select(Relationship).where(
                Relationship.investigation_id == context.job.investigation_id,
                Relationship.subject_entity_id == repository_id,
                Relationship.predicate == "REFERENCES_PUBLIC_ASSET",
                Relationship.object_entity_id == public_asset_id,
                Relationship.provider == self.name,
            )
        )
        if relationship is None:
            relationship = Relationship(
                investigation_id=context.job.investigation_id,
                subject_entity_id=repository_id,
                predicate="REFERENCES_PUBLIC_ASSET",
                object_entity_id=public_asset_id,
                confidence=90,
                provider=self.name,
            )
            context.db.add(relationship)
            context.db.flush()
        return relationship

    @staticmethod
    def location(root: Path, filename: str, line: int | str | None) -> str:
        try:
            relative = str(Path(filename).resolve().relative_to(root.resolve()))
        except (OSError, ValueError):
            relative = Path(filename).name
        return f"{relative}:{line or 1}"[:2048]


class GitleaksProvider(SourceScannerProvider):
    name = "gitleaks"
    binary = "gitleaks"

    def collect(self, context: ProviderContext) -> ProviderResult:
        with (
            self.repository(context) as root,
            tempfile.TemporaryDirectory(prefix="signaltrace-gitleaks-") as directory,
        ):
            report = Path(directory) / "report.json"
            result = self.run(
                context,
                [
                    "dir",
                    "--redact=100",
                    "--no-banner",
                    "--report-format=json",
                    f"--report-path={report}",
                    "--max-target-megabytes=5",
                    str(root),
                ],
            )
            if result.returncode not in {0, 1}:
                raise RuntimeError("Gitleaks scan failed")
            rows = json.loads(report.read_text()) if report.exists() else []
            findings = []
            summaries = []
            for row in rows[:1000]:
                location = self.location(
                    root, str(row.get("File") or "unknown"), row.get("StartLine")
                )
                fingerprint = hashlib.sha256(
                    str(row.get("Fingerprint") or row.get("Secret") or location).encode()
                ).hexdigest()
                rule = str(row.get("RuleID") or "secret")[:100]
                findings.append(self._secret_finding(context, rule, location, fingerprint, False))
                summaries.append(
                    {"rule_id": rule, "location": location, "fingerprint": fingerprint}
                )
            return self.result(
                context,
                root,
                findings,
                {"finding_count": len(findings), "findings": summaries},
            )

    def _secret_finding(self, context, rule, location, fingerprint, verified):
        return {
            "rule_id": f"secret.{rule}"[:100],
            "title": f"Potential secret detected ({rule})"[:300],
            "description": (
                f"A {'verified ' if verified else ''}credential pattern was detected "
                f"at {location}. "
                f"Secret fingerprint: {fingerprint[:12]}. The secret value was not retained."
            ),
            "severity": "critical" if verified else "high",
            "confidence": 99 if verified else 90,
            "asset_value": location,
            "entity_value": context.target.canonical_value,
        }


class TrufflehogProvider(GitleaksProvider):
    name = "trufflehog"
    binary = "trufflehog"

    def collect(self, context: ProviderContext) -> ProviderResult:
        with (
            self.repository(context) as root,
            tempfile.TemporaryDirectory(prefix="signaltrace-trufflehog-") as directory,
        ):
            exclusions = Path(directory) / "exclude-paths.txt"
            exclusions.write_text(
                r"(^|/)(\.git|\.venv|node_modules|dist|__pycache__|\.runtime)(/|$)" + "\n"
            )
            result = self.run(
                context,
                [
                    "filesystem",
                    "--json",
                    "--no-update",
                    "--no-verification",
                    "--concurrency=2",
                    "--max-decode-depth=2",
                    "--force-skip-archives",
                    f"--exclude-paths={exclusions}",
                    str(root),
                ],
            )
            if result.returncode != 0:
                raise RuntimeError("TruffleHog scan failed")
            findings, summaries = [], []
            for line in result.stdout.splitlines()[:1000]:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                source = row.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                location = self.location(
                    root, str(source.get("file") or "unknown"), source.get("line")
                )
                detector = str(row.get("DetectorName") or "secret")[:100]
                raw = str(row.get("RawV2") or row.get("Raw") or "")
                fingerprint = hashlib.sha256(raw.encode()).hexdigest()
                verified = bool(row.get("Verified"))
                findings.append(
                    self._secret_finding(context, detector, location, fingerprint, verified)
                )
                summaries.append(
                    {
                        "detector": detector,
                        "location": location,
                        "fingerprint": fingerprint,
                        "verified": verified,
                    }
                )
            return self.result(
                context,
                root,
                findings,
                {"finding_count": len(findings), "findings": summaries},
            )


class SemgrepProvider(SourceScannerProvider):
    name = "semgrep"
    binary = "semgrep"

    def collect(self, context: ProviderContext) -> ProviderResult:
        with self.repository(context) as root:
            result = self.run(
                context,
                [
                    "scan",
                    "--config=p/default",
                    "--json",
                    "--quiet",
                    "--metrics=off",
                    "--max-target-bytes=1000000",
                    "--timeout=5",
                    str(root),
                ],
            )
            if result.returncode not in {0, 1}:
                raise RuntimeError("Semgrep scan failed")
            payload = json.loads(result.stdout or "{}")
            findings, summaries = [], []
            for row in (payload.get("results") or [])[:2000]:
                extra = row.get("extra") or {}
                location = self.location(
                    root, str(row.get("path") or "unknown"), (row.get("start") or {}).get("line")
                )
                rule = str(row.get("check_id") or "semgrep")[:100]
                severity = {"ERROR": "high", "WARNING": "medium"}.get(
                    str(extra.get("severity")), "low"
                )
                findings.append(
                    {
                        "rule_id": f"semgrep.{rule}"[:100],
                        "title": str(extra.get("message") or rule)[:300],
                        "description": (
                            f"Semgrep matched {rule} at {location}. "
                            "Source code excerpts are not retained."
                        ),
                        "severity": severity,
                        "confidence": 90,
                        "asset_value": location,
                        "entity_value": context.target.canonical_value,
                    }
                )
                summaries.append({"rule_id": rule, "location": location, "severity": severity})
            return self.result(
                context,
                root,
                findings,
                {"finding_count": len(findings), "findings": summaries},
            )


class OsvScannerProvider(SourceScannerProvider):
    name = "osv_scanner"
    binary = "osv-scanner"

    def collect(self, context: ProviderContext) -> ProviderResult:
        with self.repository(context) as root:
            result = self.run(
                context,
                ["scan", "source", "--format=json", "--recursive", "--no-resolve", str(root)],
            )
            if result.returncode not in {0, 1}:
                raise RuntimeError("OSV-Scanner scan failed")
            payload = json.loads(result.stdout or "{}")
            findings, summaries = [], []
            for scan_result in payload.get("results") or []:
                source_path = str(
                    (scan_result.get("source") or {}).get("path") or "dependency file"
                )
                for package_row in scan_result.get("packages") or []:
                    package = package_row.get("package") or {}
                    name, version = (
                        str(package.get("name") or "package"),
                        str(package.get("version") or "unknown"),
                    )
                    for vulnerability in package_row.get("vulnerabilities") or []:
                        vuln_id = str(vulnerability.get("id") or "OSV")[:100]
                        location = self.location(root, source_path, 1)
                        asset = f"{location}:{name}:{vuln_id}"[:2048]
                        findings.append(
                            {
                                "rule_id": f"dependency.{vuln_id}"[:100],
                                "title": f"Vulnerable dependency: {name} {version}"[:300],
                                "description": (
                                    f"OSV reports {vuln_id} for {name} {version} in {location}."
                                ),
                                "severity": "high",
                                "confidence": 95,
                                "asset_value": asset,
                                "entity_value": context.target.canonical_value,
                            }
                        )
                        summaries.append(
                            {
                                "id": vuln_id,
                                "package": name,
                                "version": version,
                                "location": location,
                            }
                        )
            return self.result(
                context,
                root,
                findings,
                {"finding_count": len(findings), "vulnerabilities": summaries[:2000]},
            )


class CheckovProvider(SourceScannerProvider):
    name = "checkov"
    binary = "checkov"

    def collect(self, context: ProviderContext) -> ProviderResult:
        with self.repository(context) as root:
            result = self.run(
                context,
                [
                    "--directory",
                    str(root),
                    "--output",
                    "json",
                    "--compact",
                    "--quiet",
                    "--skip-path",
                    r"(^|/)(\.venv|node_modules|dist|\.runtime)(/|$)",
                ],
            )
            if result.returncode not in {0, 1}:
                raise RuntimeError("Checkov infrastructure-as-code scan failed")
            payload = json.loads(result.stdout or "{}")
            reports = payload if isinstance(payload, list) else [payload]
            findings, summaries, frameworks = [], [], set()
            for report in reports:
                framework = str(report.get("check_type") or "iac")
                frameworks.add(framework)
                for row in (report.get("results") or {}).get("failed_checks") or []:
                    rule = str(row.get("check_id") or "CKV")[:100]
                    line_range = row.get("file_line_range") or [1]
                    location = self.location(
                        root,
                        str(row.get("file_abs_path") or row.get("file_path") or "unknown"),
                        line_range[0] if line_range else 1,
                    )
                    resource = str(row.get("resource") or "resource")[:500]
                    title = str(row.get("check_name") or rule)[:300]
                    asset = f"{location}:{resource}:{rule}"[:2048]
                    findings.append(
                        {
                            "rule_id": f"cloud.iac.{rule}"[:100],
                            "title": title,
                            "description": (
                                f"Checkov {framework} policy {rule} failed for {resource} "
                                f"at {location}. Source excerpts were not retained."
                            ),
                            "severity": "medium",
                            "confidence": 95,
                            "asset_value": asset,
                            "entity_value": context.target.canonical_value,
                        }
                    )
                    summaries.append(
                        {
                            "check_id": rule,
                            "framework": framework,
                            "location": location,
                            "resource": resource,
                        }
                    )
            return self.result(
                context,
                root,
                findings,
                {
                    "finding_count": len(findings),
                    "frameworks": sorted(frameworks),
                    "findings": summaries[:5000],
                },
            )


SOURCE_CODE_PROVIDERS = (
    GitleaksProvider,
    TrufflehogProvider,
    SemgrepProvider,
    OsvScannerProvider,
    CheckovProvider,
)
