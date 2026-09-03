import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import select

from ..models import Entity, Finding, Relationship
from ..process_isolation import run_isolated_process
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult
from ..scanner_isolation import ScannerPolicy, configured_scanner_images
from ..scanner_orchestrator_client import ScannerOrchestratorClient

PROJECT_HTTPX = Path(__file__).resolve().parents[4] / ".tools" / "bin" / "httpx"
ZAP_EXECUTABLE = Path("/Applications/ZAP.app/Contents/Java/zap.sh")
BOUNDED_TCP_PORTS = (
    "21,22,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,"
    "2049,2375,2376,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,9200"
)


class LocalToolProvider:
    binary = ""
    version_flag = "-version"
    binary_override: Path | None = None
    capabilities = ProviderCapabilities(target_types=frozenset())

    @cached_property
    def executable(self) -> str | None:
        if self.binary_override and self.binary_override.is_file():
            return str(self.binary_override)
        return shutil.which(self.binary)

    @cached_property
    def available(self) -> bool:
        return self.executable is not None or self.name in configured_scanner_images()

    @cached_property
    def version(self) -> str | None:
        executable = self.executable
        if not executable:
            return None
        flag = self.version_flag
        try:
            result = subprocess.run(  # noqa: S603 - executable is resolved locally
                [executable, flag], capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.stdout + result.stderr)
        for line in output.splitlines():
            if "version" in line.lower() or line.strip().startswith("v"):
                return line.strip()[:160]
        return output.strip().splitlines()[0][:160] if output.strip() else None

    def _run(
        self,
        context: ProviderContext,
        arguments: list[str],
        *,
        stdin: str | None = None,
        remote_binary: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        timeout = 20.0
        if context.deadline_at:
            deadline = context.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            timeout = max(1.0, (deadline - datetime.now(UTC)).total_seconds())
        images = configured_scanner_images()
        image = images.get(self.name)
        try:
            if image:
                if stdin is not None:
                    raise RuntimeError(
                        f"{self.name} container execution does not accept host-provided stdin"
                    )
                isolated = ScannerOrchestratorClient(
                    os.environ.get("PLATFORM_SCANNER_ORCHESTRATOR_URL", ""),
                    os.environ.get("PLATFORM_SCANNER_ORCHESTRATOR_TOKEN", ""),
                ).run(
                    self.name,
                    [remote_binary or self.binary, *arguments],
                    ScannerPolicy(
                        image=image,
                        timeout_seconds=timeout,
                        network=os.environ.get("PLATFORM_SCANNER_NETWORK", "bridge"),
                        memory_mb=1536 if self.name in {"zap_passive", "zap_active"} else 512,
                        # ZAP expands its add-ons and session state beneath /tmp.
                        # Keep the disposable filesystem bounded, but give this
                        # scanner enough room to start reliably.
                        tmpfs_mb=512 if self.name in {"zap_passive", "zap_active"} else 128,
                        environment=environment or {},
                    ),
                    job_id=context.job.id,
                    target_id=context.target.id,
                    authorization_id=context.target.authorization_id,
                    cancel_requested=lambda: self._cancellation_requested(context),
                )
                result = subprocess.CompletedProcess(
                    args=[self.binary, *arguments],
                    returncode=isolated.returncode,
                    stdout=isolated.stdout,
                    stderr=isolated.stderr,
                )
            else:
                executable = self.executable
                if not executable:
                    raise RuntimeError(f"{self.name} is not installed")
                if not self.capabilities.passive_only:
                    raise RuntimeError(
                        f"{self.name} requires a configured disposable scanner image"
                    )
                result = run_isolated_process(
                    [executable, *arguments], timeout=timeout, stdin=stdin
                )
        except TimeoutError as exc:
            raise TimeoutError(f"{self.name} exceeded its time limit") from exc
        if result.returncode not in {0, 1}:
            diagnostic = result.stderr.strip() or result.stdout.strip()
            message = diagnostic.splitlines()[-1] if diagnostic else "failed"
            raise RuntimeError(f"{self.name}: {message[:300]}")
        return result

    @staticmethod
    def _cancellation_requested(context: ProviderContext) -> bool:
        context.db.refresh(context.job, attribute_names=["cancellation_requested_at"])
        return context.job.cancellation_requested_at is not None

    @staticmethod
    def _public_target(value: str) -> str:
        if "/" in value and "://" not in value:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise RuntimeError("Invalid network target") from exc
            if network.num_addresses > 256 or not network.network_address.is_global:
                raise RuntimeError("Local tools require a public network of 256 addresses or fewer")
            return value
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname or value
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [
                ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)
            ]
        if not addresses or any(not address.is_global for address in addresses):
            raise RuntimeError("Local tools require a public target")
        return value

    @staticmethod
    def _json_lines(output: str) -> list[dict]:
        rows = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows

    @staticmethod
    def _entity(context: ProviderContext, entity_type: str, value: str, attributes: dict) -> Entity:
        entity = context.db.scalar(
            select(Entity).where(
                Entity.investigation_id == context.job.investigation_id,
                Entity.entity_type == entity_type,
                Entity.canonical_value == value,
            )
        )
        if entity is None:
            entity = Entity(
                investigation_id=context.job.investigation_id,
                entity_type=entity_type,
                canonical_value=value[:2048],
                confidence=95,
                provider=context.job.provider,
                attributes=attributes,
            )
            context.db.add(entity)
            context.db.flush()
        else:
            entity.attributes = {**(entity.attributes or {}), **attributes}
        return entity

    @staticmethod
    def _result(
        payload: dict,
        entities: list[Entity],
        relationships: list[Relationship] | None = None,
        findings: list[dict] | None = None,
        metadata: dict | None = None,
    ) -> ProviderResult:
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=len(entities),
            entity_ids=tuple(item.id for item in entities),
            relationship_ids=tuple(item.id for item in relationships or []),
            metadata={**(metadata or {}), "finding_candidates": findings or []},
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload=payload,
        )

    def _network_results(
        self, context: ProviderContext, target: str, services: list[dict]
    ) -> ProviderResult:
        entities, findings = [], []
        for service in services[:1000]:
            host = str(service.get("address") or target)
            port = int(service.get("port", 0) or 0)
            protocol = str(service.get("protocol") or "tcp").lower()
            if not port:
                continue
            value = f"{host}:{port}/{protocol}"
            corroborating = sorted(
                {
                    item.provider
                    for item in context.db.scalars(
                        select(Finding).where(
                            Finding.investigation_id == context.job.investigation_id,
                            Finding.asset_value == value,
                            Finding.provider.in_(["censys", "shodan"]),
                        )
                    )
                }
            )
            attributes = {
                **service,
                "source": self.name,
                "corroborating_providers": corroborating,
            }
            entities.append(self._entity(context, "network_service", value, attributes))
            if port not in {80, 443}:
                support = (
                    f" This observation is corroborated by {', '.join(corroborating)}."
                    if corroborating
                    else ""
                )
                findings.append(
                    {
                        "rule_id": f"{self.name}.unexpected_public_service",
                        "title": f"Unexpected public {protocol.upper()} service",
                        "description": (
                            f"{self.name.replace('_', ' ').title()} observed {protocol.upper()} "
                            f"port {port} accepting connections.{support} Confirm that the service "
                            "is intentional, patched, and access-controlled."
                        ),
                        "severity": "medium",
                        "confidence": 99 if corroborating else 95,
                        "asset_value": value,
                        "entity_value": value,
                    }
                )
        return self._result(
            {"target": target, "open_services": services}, entities, findings=findings
        )


class SubfinderProvider(LocalToolProvider):
    name = "subfinder"
    binary = "subfinder"
    capabilities = ProviderCapabilities(target_types=frozenset({"domain"}), passive_only=True)

    def collect(self, context: ProviderContext) -> ProviderResult:
        domain = self._public_target(context.target.canonical_value)
        result = self._run(
            context,
            [
                "-d",
                domain,
                "-silent",
                "-json",
                # Bound individual passive-source requests and the complete
                # enumeration below the worker's outer hard deadline.
                "-timeout",
                "15",
                "-max-time",
                "1",
            ],
        )
        rows = self._json_lines(result.stdout)
        domains = sorted({str(row.get("host", "")).lower() for row in rows if row.get("host")})[
            :500
        ]
        entities = [
            self._entity(context, "domain", value, {"source": self.name}) for value in domains
        ]
        payload = {"domain": domain, "subdomains": domains, "count": len(domains)}
        return self._result(payload, entities, metadata={"discovered_domains": domains})


class HttpxProvider(LocalToolProvider):
    name = "projectdiscovery_httpx"
    binary = "httpx"
    binary_override = PROJECT_HTTPX
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        result = self._run(
            context,
            [
                "-u",
                target,
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-location",
                "-ip",
                "-rate-limit",
                "5",
            ],
        )
        rows = self._json_lines(result.stdout)[:100]
        entities = []
        for row in rows:
            url = str(row.get("url") or row.get("input") or target)
            entities.append(
                self._entity(
                    context,
                    "url",
                    url,
                    {
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "technologies": row.get("tech", []),
                        "ip": row.get("host"),
                    },
                )
            )
        return self._result({"target": target, "responses": rows}, entities)


class NaabuProvider(LocalToolProvider):
    name = "naabu"
    binary = "naabu"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        result = self._run(
            context, ["-host", target, "-silent", "-json", "-top-ports", "100", "-rate", "50"]
        )
        rows = self._json_lines(result.stdout)[:500]
        entities, findings = [], []
        for row in rows:
            host, port = (
                str(row.get("ip") or row.get("host") or target),
                int(row.get("port", 0) or 0),
            )
            if not port:
                continue
            value = f"{host}:{port}/tcp"
            entities.append(
                self._entity(
                    context,
                    "network_service",
                    value,
                    {"port": port, "protocol": "tcp", "source": self.name},
                )
            )
            if port not in {80, 443}:
                findings.append(
                    {
                        "rule_id": "naabu.unexpected_public_service",
                        "title": "Unexpected public TCP service",
                        "description": (
                            f"Naabu observed TCP port {port} accepting connections. "
                            "Confirm that the service is intentional and access-controlled."
                        ),
                        "severity": "medium",
                        "confidence": 95,
                        "asset_value": value,
                        "entity_value": value,
                    }
                )
        return self._result({"target": target, "open_ports": rows}, entities, findings=findings)


class NmapProvider(LocalToolProvider):
    name = "nmap"
    binary = "nmap"
    version_flag = "--version"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        result = self._run(
            context,
            [
                "-sT",
                "-sV",
                "--version-light",
                "-Pn",
                "--top-ports",
                "100",
                "-T3",
                "--script",
                "banner,http-title,http-headers,ssl-cert",
                "-oX",
                "-",
                target,
            ],
        )
        services = []
        try:
            root = ET.fromstring(result.stdout)  # noqa: S314 - locally generated Nmap XML
        except ET.ParseError as exc:
            raise RuntimeError("Nmap returned invalid XML") from exc
        for host in root.findall("host"):
            address_node = host.find("address")
            address = address_node.get("addr") if address_node is not None else target
            for port_node in host.findall("./ports/port"):
                state = port_node.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_node.find("service")
                services.append(
                    {
                        "address": address,
                        "port": int(port_node.get("portid", "0")),
                        "protocol": port_node.get("protocol", "tcp"),
                        "service": service.get("name") if service is not None else None,
                        "product": service.get("product") if service is not None else None,
                        "version": service.get("version") if service is not None else None,
                    }
                )
        return self._network_results(context, target, services)


class RustscanProvider(LocalToolProvider):
    name = "rustscan"
    binary = "rustscan"
    version_flag = "--version"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        result = self._run(
            context,
            [
                "-a",
                target,
                "--ports",
                BOUNDED_TCP_PORTS,
                "--greppable",
                "--no-banner",
                "--batch-size",
                "100",
                "--timeout",
                "1500",
                "--tries",
                "1",
            ],
        )
        port_values: set[int] = set()
        for line in result.stdout.splitlines():
            candidate = line.split("->", 1)[-1] if "->" in line else line
            if not re.fullmatch(r"[\s\[\],\d]+", candidate):
                continue
            port_values.update(
                int(item)
                for item in re.findall(r"\b\d{1,5}\b", candidate)
                if 0 < int(item) <= 65535
            )
        ports = sorted(port_values)
        services = [{"address": target, "port": port, "protocol": "tcp"} for port in ports]
        return self._network_results(context, target, services)


class MasscanProvider(LocalToolProvider):
    name = "masscan"
    binary = "masscan"
    version_flag = "--version"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"ip_address", "network"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        result = self._run(
            context,
            [
                target,
                "-p1-1024",
                "--rate",
                "25",
                "--wait",
                "2",
                "--output-format",
                "json",
                "--output-filename",
                "-",
            ],
        )
        cleaned = result.stdout.strip().rstrip(",")
        try:
            rows = json.loads(cleaned) if cleaned else []
        except json.JSONDecodeError:
            rows = self._json_lines(cleaned)
        services = []
        for row in rows if isinstance(rows, list) else []:
            for port in row.get("ports", []):
                if port.get("status") == "open":
                    services.append(
                        {
                            "address": str(row.get("ip") or target),
                            "port": int(port.get("port", 0)),
                            "protocol": str(port.get("proto") or "tcp"),
                        }
                    )
        return self._network_results(context, target, services)


class NucleiProvider(LocalToolProvider):
    name = "nuclei"
    binary = "nuclei"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        url = target if "://" in target else f"https://{target}"
        result = self._run(
            context,
            [
                "-u",
                url,
                "-silent",
                "-jsonl",
                "-severity",
                "info,low,medium,high,critical",
                "-rate-limit",
                "5",
                "-bulk-size",
                "5",
                "-templates",
                "/opt/nuclei-templates",
                "-disable-update-check",
            ],
        )
        rows = self._json_lines(result.stdout)[:500]
        entities, findings = [], []
        for row in rows:
            info = row.get("info") or {}
            matched = str(row.get("matched-at") or url)
            template_id = str(row.get("template-id") or "unknown")
            severity = str(info.get("severity") or "info").lower()
            entities.append(
                self._entity(
                    context, "url", matched, {"template_id": template_id, "source": self.name}
                )
            )
            classification = info.get("classification") or {}
            cve_values = classification.get("cve-id") or []
            cwe_values = classification.get("cwe-id") or []
            cve = str(cve_values[0]).upper() if cve_values else ""
            cwe = str(cwe_values[0]) if cwe_values else ""
            canonical_rule = (
                f"vuln.cve.{cve}"
                if cve.startswith("CVE-")
                else f"web.cwe.{cwe.lower().removeprefix('cwe-')}"
                if cwe
                else f"nuclei.{template_id}"
            )
            findings.append(
                {
                    "rule_id": canonical_rule[:100],
                    "title": str(info.get("name") or template_id)[:300],
                    "description": str(
                        info.get("description")
                        or f"Nuclei template {template_id} matched {matched}."
                    ),
                    "severity": severity,
                    "confidence": 90,
                    "asset_value": matched,
                    "entity_value": matched,
                }
            )
        return self._result({"target": url, "matches": rows}, entities, findings=findings)


class KatanaProvider(LocalToolProvider):
    name = "katana"
    binary = "katana"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        return self._collect(context, [])

    def _collect(self, context: ProviderContext, authentication_args: list[str]) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        url = target if "://" in target else f"https://{target}"
        result = self._run(
            context,
            [
                "-u",
                url,
                "-silent",
                "-jsonl",
                "-depth",
                "2",
                "-strategy",
                "breadth-first",
                "-field-scope",
                "rdn",
                "-form-extraction",
                "-xhr-extraction",
                "-omit-raw",
                "-omit-body",
                "-concurrency",
                "2",
                "-parallelism",
                "1",
                "-rate-limit",
                "3",
                *authentication_args,
            ],
        )
        rows = self._json_lines(result.stdout)[:1000]
        endpoints: dict[str, dict] = {}
        for row in rows:
            request = row.get("request") or {}
            endpoint = str(request.get("endpoint") or row.get("url") or "")
            if endpoint and endpoint.startswith(("http://", "https://")):
                endpoints[endpoint] = {
                    "method": request.get("method") or "GET",
                    "forms": row.get("forms") or [],
                    "xhr": row.get("xhr") or [],
                }
        entities = [
            self._entity(context, "url", endpoint, {**details, "source": self.name})
            for endpoint, details in sorted(endpoints.items())
        ]
        return self._result(
            {"target": url, "endpoints": endpoints, "count": len(endpoints)}, entities
        )


class DnstwistProvider(LocalToolProvider):
    name = "dnstwist"
    binary = "dnstwist"
    version_flag = "--version"
    capabilities = ProviderCapabilities(target_types=frozenset({"domain"}), passive_only=True)

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value).rstrip(".").lower()
        result = self._run(
            context,
            [
                "--registered",
                "--format",
                "json",
                "--threads",
                "10",
                "--fuzzers",
                (
                    "addition,bitsquatting,homoglyph,hyphenation,insertion,"
                    "omission,repetition,replacement,transposition"
                ),
                target,
            ],
        )
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("dnstwist returned invalid JSON") from exc
        if not isinstance(rows, list):
            raise RuntimeError("dnstwist returned an unexpected response")
        permutations = []
        entities = []
        findings = []
        for row in rows[:500]:
            domain = str(row.get("domain") or "").lower().rstrip(".")
            if not domain or domain == target:
                continue
            details = {
                "domain": domain,
                "fuzzer": str(row.get("fuzzer") or "unknown"),
                "dns_a": row.get("dns_a") or [],
                "dns_aaaa": row.get("dns_aaaa") or [],
                "dns_mx": row.get("dns_mx") or [],
                "dns_ns": row.get("dns_ns") or [],
            }
            permutations.append(details)
            entities.append(
                self._entity(
                    context,
                    "lookalike_domain",
                    domain,
                    {"source": self.name, "classification": "OBSERVED_FACT", **details},
                )
            )
            mail_capable = bool(details["dns_mx"])
            findings.append(
                {
                    "rule_id": "domain.registered_lookalike",
                    "title": "Registered look-alike domain detected",
                    "description": (
                        f"{domain} is a registered {details['fuzzer']} permutation of {target}."
                        + (" It also publishes mail-exchange records." if mail_capable else "")
                    ),
                    "severity": "high" if mail_capable else "medium",
                    "confidence": 90,
                    "asset_value": domain,
                    "entity_value": domain,
                }
            )
        payload = {
            "target": target,
            "registered_lookalikes": permutations,
            "count": len(permutations),
        }
        return self._result(payload, entities, findings=findings)


class KatanaAuthenticatedProvider(KatanaProvider):
    name = "katana_authenticated"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}),
        passive_only=False,
        requires_credentials=True,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        authorization_header = context.credentials.get("authorization_header", "").strip()
        if not authorization_header:
            raise RuntimeError("Authenticated Katana requires an Authorization header")
        target = self._public_target(context.target.canonical_value)
        url = target if "://" in target else f"https://{target}"
        result = self._run(
            context,
            ["-u", url],
            remote_binary="cypheryn-katana-auth",
            environment={"CYPHERYN_AUTHORIZATION_HEADER": authorization_header},
        )
        rows = self._json_lines(result.stdout)[:1000]
        endpoints: dict[str, dict] = {}
        for row in rows:
            request = row.get("request") or {}
            endpoint = str(request.get("endpoint") or row.get("url") or "")
            if endpoint.startswith(("http://", "https://")):
                endpoints[endpoint] = {
                    "method": request.get("method") or "GET",
                    "forms": row.get("forms") or [],
                    "xhr": row.get("xhr") or [],
                }
        entities = [
            self._entity(context, "url", endpoint, {**details, "source": self.name})
            for endpoint, details in sorted(endpoints.items())
        ]
        return self._result(
            {"target": url, "endpoints": endpoints, "count": len(endpoints)}, entities
        )


class NiktoProvider(LocalToolProvider):
    name = "nikto"
    binary = "nikto"
    version_flag = "-Version"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        url = target if "://" in target else f"https://{target}"
        result = self._run(
            context,
            [
                "-h",
                url,
                "-Format",
                "json",
                "-output",
                "-",
                "-nointeractive",
                "-timeout",
                "3",
                "-maxtime",
                "45s",
                "-Tuning",
                "23b",
            ],
            remote_binary="cypheryn-nikto",
        )
        payload = json.loads(result.stdout) if result.stdout.strip() else {}
        if isinstance(payload, list):
            vulnerabilities = [
                item
                for host in payload
                if isinstance(host, dict)
                for item in (host.get("vulnerabilities") or [])
                if isinstance(item, dict)
            ]
        else:
            vulnerabilities = (
                payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
            )
        diagnostic_failures = [
            item
            for item in vulnerabilities
            if str(item.get("id") or "").strip().upper() == "FAIL"
        ]
        if diagnostic_failures:
            detail = str(
                diagnostic_failures[0].get("msg")
                or diagnostic_failures[0].get("message")
                or "Nikto could not assess the target"
            )
            raise RuntimeError(f"Nikto scanner could not assess the target: {detail}")
        findings = []
        for item in vulnerabilities[:500]:
            message = str(item.get("msg") or item.get("message") or "Nikto finding")
            informational = any(
                marker in message.lower()
                for marker in (
                    "link header(s) found",
                    "uncommon header(s)",
                    "robots.txt",
                    "sitemap.xml",
                    "should be manually viewed",
                )
            )
            if informational:
                continue
            rule = str(item.get("id") or hashlib.sha256(message.encode()).hexdigest()[:16])
            uri = str(item.get("url") or item.get("uri") or url)
            findings.append(
                {
                    "rule_id": f"nikto.{rule}"[:100],
                    "title": message[:300],
                    "description": message,
                    "severity": "medium",
                    "confidence": 85,
                    "asset_value": uri,
                    "entity_value": uri,
                }
            )
        entity = self._entity(context, "url", url, {"source": self.name})
        return self._result(
            {"target": url, "vulnerabilities": vulnerabilities}, [entity], findings=findings
        )


class ZapPassiveProvider(LocalToolProvider):
    name = "zap_passive"
    binary = "zap.sh"
    binary_override = ZAP_EXECUTABLE
    version = "2.17.0"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "url"}),
        passive_only=False,
        supports_cancellation=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        url = target if "://" in target else f"https://{target}"
        if self.name in configured_scanner_images():
            result = self._run(
                context,
                [url],
                remote_binary="cypheryn-zap-passive",
            )
            try:
                payload = self._json_document(result.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("zap_passive returned malformed JSON") from exc
            return self._normalize_zap(context, url, payload)
        with tempfile.TemporaryDirectory(prefix="cypheryn-zap-") as directory:
            report = Path(directory) / "report.json"
            plan = Path(directory) / "passive.yaml"
            plan.write_text(
                "env:\n"
                "  contexts:\n"
                "  - name: CYPHERYN\n"
                f"    urls: [{json.dumps(url)}]\n"
                "jobs:\n"
                "- type: spider\n"
                "  parameters:\n"
                "    context: CYPHERYN\n"
                "    maxDuration: 1\n"
                "    maxDepth: 2\n"
                "- type: passiveScan-wait\n"
                "  parameters:\n"
                "    maxDuration: 2\n"
                "- type: report\n"
                "  parameters:\n"
                "    template: traditional-json\n"
                f"    reportDir: {json.dumps(directory)}\n"
                "    reportFile: report.json\n"
            )
            try:
                self._run(
                    context,
                    ["-cmd", "-silent", "-dir", directory, "-autorun", str(plan)],
                )
            except RuntimeError:
                if not report.exists():
                    raise
            payload = json.loads(report.read_text()) if report.exists() else {}
        return self._normalize_zap(context, url, payload)

    @staticmethod
    def _json_document(output: str) -> dict:
        """Decode a JSON report even when a scanner emits bounded startup noise."""
        decoder = json.JSONDecoder()
        for offset, character in enumerate(output):
            if character != "{":
                continue
            try:
                payload, _end = decoder.raw_decode(output[offset:])
            except json.JSONDecodeError:
                continue
            # Some ZAP builds write bounded launcher diagnostics after the
            # report. The report itself remains authoritative; trailing text
            # is scanner telemetry, not evidence that the target failed.
            if isinstance(payload, dict):
                return payload
        raise json.JSONDecodeError("no JSON object found", output, 0)

    def _normalize_zap(self, context: ProviderContext, url: str, payload: dict) -> ProviderResult:
        entities, findings, observations, endpoints = [], [], [], set()
        for site in payload.get("site", []) if isinstance(payload, dict) else []:
            for alert in site.get("alerts", []):
                risk = str(alert.get("riskdesc") or "informational").split()[0].lower()
                severity = {
                    "informational": "info",
                    "low": "low",
                    "medium": "medium",
                    "high": "high",
                }.get(risk, "info")
                for instance in alert.get("instances", []) or [{}]:
                    endpoint = str(instance.get("uri") or url)
                    endpoints.add(endpoint)
                    cwe = str(alert.get("cweid") or "").strip()
                    title = str(alert.get("name") or "ZAP passive alert")[:300]
                    candidate = {
                        "rule_id": (
                            f"web.cwe.{cwe}"
                            if cwe and cwe != "-1"
                            else f"zap.{alert.get('pluginid', 'unknown')}"
                        )[:100],
                        "title": title,
                        "description": str(
                            alert.get("desc")
                            or alert.get("solution")
                            or "Web security observation."
                        ),
                        "severity": severity,
                        "confidence": 90,
                        "asset_value": endpoint,
                        "entity_value": endpoint,
                    }
                    expected_oauth_timestamp = (
                        title == "Timestamp Disclosure - Unix"
                        and urlsplit(endpoint).path.startswith("/oauth2/")
                    )
                    observations.append(
                        {
                            **candidate,
                            "classification": (
                                "expected_oauth_state"
                                if expected_oauth_timestamp
                                else "informational"
                                if severity == "info"
                                else "finding_candidate"
                            ),
                        }
                    )
                    # Preserve informational scanner output and expected OAuth
                    # anti-forgery timestamps as evidence without opening risk
                    # findings for intentional cache/session behavior.
                    if severity != "info" and not expected_oauth_timestamp:
                        findings.append(candidate)
        for endpoint in sorted(endpoints):
            entities.append(self._entity(context, "url", endpoint, {"source": self.name}))
        return self._result(
            {
                "target": url,
                "alerts": observations,
                "endpoint_count": len(endpoints),
                "finding_count": len(findings),
            },
            entities,
            findings=findings,
        )


class ZapActiveProvider(ZapPassiveProvider):
    name = "zap_active"

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        url = target if "://" in target else f"https://{target}"
        result = self._run(
            context,
            [url],
            remote_binary="cypheryn-zap-active",
        )
        try:
            payload = self._json_document(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("ZAP Active returned malformed JSON") from exc
        return self._normalize_zap(context, url, payload)


class TestsslProvider(LocalToolProvider):
    name = "testssl"
    binary = "testssl.sh"
    version_flag = "--version"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address", "url"}), passive_only=False
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        target = self._public_target(context.target.canonical_value)
        if self.name in configured_scanner_images():
            result = self._run(
                context,
                [target],
                remote_binary="cypheryn-testssl",
            )
            try:
                rows = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("testssl returned malformed JSON") from exc
        else:
            with tempfile.TemporaryDirectory(prefix="cypheryn-testssl-") as directory:
                output = Path(directory) / "result.json"
                self._run(
                    context,
                    ["--quiet", "--warnings", "off", "--jsonfile-pretty", str(output), target],
                )
                rows = json.loads(output.read_text()) if output.exists() else []
        raw_rows = rows
        rows = self._testssl_observations(rows)
        scanner_errors = []
        findings = []
        for row in rows if isinstance(rows, list) else []:
            severity = str(row.get("severity") or "INFO").lower()
            rule = str(row.get("id") or "tls_issue")
            if severity in {"fatal", "error"} or rule.lower() in {
                "scanproblem",
                "engineproblem",
            }:
                scanner_errors.append(str(row.get("finding") or rule)[:500])
                continue
            if severity in {"ok", "info"}:
                continue
            findings.append(
                {
                    "rule_id": f"testssl.{rule}"[:100],
                    "title": str(row.get("finding") or rule)[:300],
                    "description": str(row.get("finding") or "TLS configuration requires review."),
                    "severity": severity
                    if severity in {"low", "medium", "high", "critical"}
                    else "medium",
                    "confidence": 95,
                    "asset_value": target,
                    "entity_value": target,
                }
            )
        if scanner_errors:
            raise RuntimeError(
                "testssl scanner could not assess the target: " + "; ".join(scanner_errors[:3])
            )
        entity = self._entity(context, "tls_service", target, {"source": self.name})
        return self._result({"target": target, "results": raw_rows}, [entity], findings=findings)

    @staticmethod
    def _testssl_observations(payload: object) -> list[dict]:
        """Flatten testssl's host/section document to actual result observations."""
        observations: list[dict] = []
        stack = [payload]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if "id" in item and "severity" in item:
                    observations.append(item)
                else:
                    stack.extend(reversed(list(item.values())))
            elif isinstance(item, list):
                stack.extend(reversed(item))
        return observations


LOCAL_TOOL_PROVIDERS = (
    SubfinderProvider,
    HttpxProvider,
    NaabuProvider,
    NmapProvider,
    RustscanProvider,
    MasscanProvider,
    NucleiProvider,
    DnstwistProvider,
    KatanaProvider,
    KatanaAuthenticatedProvider,
    NiktoProvider,
    ZapPassiveProvider,
    ZapActiveProvider,
    TestsslProvider,
)
