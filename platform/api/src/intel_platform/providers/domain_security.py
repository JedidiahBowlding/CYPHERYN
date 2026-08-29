import hashlib
import json
import socket
import ssl
from datetime import UTC, datetime

import certifi
import dns.exception
import dns.resolver
import httpx
from sqlalchemy import select

from ..models import Entity
from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class DomainSecurityProvider:
    """Passive DNS, mail-authentication, certificate, and takeover posture."""

    name = "domain_security"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain"}), passive_only=True, requires_credentials=False
    )
    _dkim_selectors = ("default", "google", "selector1", "selector2", "k1", "mail")
    _takeover_suffixes = (
        ".azurewebsites.net",
        ".cloudfront.net",
        ".github.io",
        ".herokudns.com",
        ".netlify.app",
        ".readthedocs.io",
        ".s3.amazonaws.com",
        ".surge.sh",
        ".vercel.app",
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        domain = context.target.canonical_value.rstrip(".").lower()
        timeout = self._timeout(context)
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = min(timeout, 8.0)
        records = {
            record_type: self._resolve(resolver, domain, record_type)
            for record_type in ("A", "AAAA", "MX", "NS", "CAA", "CNAME")
        }
        txt = self._resolve(resolver, domain, "TXT")
        dmarc = self._resolve(resolver, f"_dmarc.{domain}", "TXT")
        tls_rpt = self._resolve(resolver, f"_smtp._tls.{domain}", "TXT")
        bimi = self._resolve(resolver, f"default._bimi.{domain}", "TXT")
        dkim = {
            selector: self._resolve(resolver, f"{selector}._domainkey.{domain}", "TXT")
            for selector in self._dkim_selectors
        }
        mta_sts_txt = self._resolve(resolver, f"_mta-sts.{domain}", "TXT")
        mta_sts_policy = self._mta_sts_policy(domain, timeout) if mta_sts_txt else None
        certificate = self._certificate(domain, timeout)
        observations = {
            "domain": domain,
            "dns": records,
            "email_security": {
                "spf": [item for item in txt if item.lower().startswith("v=spf1")],
                "dmarc": [item for item in dmarc if item.lower().startswith("v=dmarc1")],
                "dkim": {key: value for key, value in dkim.items() if value},
                "dkim_selectors_checked": list(self._dkim_selectors),
                "mta_sts": mta_sts_txt,
                "mta_sts_policy": mta_sts_policy,
                "tls_rpt": tls_rpt,
                "bimi": bimi,
            },
            "certificate": certificate,
        }
        return self.normalize(context, observations)

    @staticmethod
    def _resolve(resolver: dns.resolver.Resolver, name: str, record_type: str) -> list[str]:
        try:
            answers = resolver.resolve(name, record_type, search=False)
        except (dns.exception.DNSException, OSError):
            return []
        values = []
        for answer in answers:
            value = answer.to_text().strip().rstrip(".")
            if record_type == "TXT":
                value = value.replace('" "', "").strip('"')
            values.append(value)
        return sorted(set(values))[:200]

    @staticmethod
    def _timeout(context: ProviderContext) -> float:
        if not context.deadline_at:
            return 15.0
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return max(1.0, min(20.0, (deadline - datetime.now(UTC)).total_seconds()))

    @staticmethod
    def _mta_sts_policy(domain: str, timeout: float) -> dict | None:
        try:
            response = httpx.get(
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                timeout=min(timeout, 8.0),
                follow_redirects=False,
            )
            if response.status_code != 200:
                return {"status": response.status_code, "valid": False}
            body = response.text[:100_000]
            fields = {}
            for line in body.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    fields[key.strip().lower()] = value.strip()
            return {"status": 200, "valid": fields.get("version") == "STSv1", **fields}
        except httpx.HTTPError:
            return {"status": None, "valid": False}

    @staticmethod
    def _certificate(domain: str, timeout: float) -> dict:
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((domain, 443), timeout=min(timeout, 8.0)) as raw:
                with ssl_context.wrap_socket(raw, server_hostname=domain) as tls:
                    certificate = tls.getpeercert()
                    binary = tls.getpeercert(binary_form=True)
            expires = certificate.get("notAfter")
            return {
                "sha256": hashlib.sha256(binary).hexdigest(),
                "expires_at": datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(expires), UTC
                ).isoformat()
                if expires
                else None,
                "dns_names": sorted(
                    value for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"
                )[:200],
            }
        except (OSError, ssl.SSLError):
            return {"sha256": None, "expires_at": None, "dns_names": []}

    def normalize(self, context: ProviderContext, observations: dict) -> ProviderResult:
        domain = observations["domain"]
        root = self._entity(context, "domain", domain, observations)
        findings = self._findings(observations)
        aliases = observations["dns"].get("CNAME", [])
        for alias in aliases:
            if alias.lower().endswith(self._takeover_suffixes):
                findings.append(
                    {
                        "rule_id": "domain.possible_dangling_cname",
                        "title": "Possible third-party domain takeover exposure",
                        "description": (
                            f"{domain} points to third-party hostname {alias}. Confirm that the "
                            "resource is still claimed; DNS alone does not prove takeoverability."
                        ),
                        "severity": "medium",
                        "confidence": 65,
                        "asset_value": domain,
                        "entity_value": domain,
                    }
                )
        payload = observations
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=1,
            entity_ids=(root.id,),
            metadata={"finding_candidates": findings, "target": domain},
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload=payload,
        )

    @staticmethod
    def _findings(observations: dict) -> list[dict]:
        domain = observations["domain"]
        email = observations["email_security"]
        findings = []
        rules = (
            (not email["spf"], "email.missing_spf", "SPF record is missing", "high"),
            (not email["dmarc"], "email.missing_dmarc", "DMARC record is missing", "high"),
            (not email["mta_sts"], "email.missing_mta_sts", "MTA-STS record is missing", "medium"),
            (not email["tls_rpt"], "email.missing_tls_rpt", "TLS-RPT record is missing", "low"),
            (not email["bimi"], "email.missing_bimi", "BIMI record is missing", "low"),
        )
        for missing, rule_id, title, severity in rules:
            if missing:
                findings.append(
                    {
                        "rule_id": rule_id,
                        "title": title,
                        "description": (
                            f"No valid {title.removesuffix(' is missing')} record was "
                            f"observed for {domain}."
                        ),
                        "severity": severity,
                        "confidence": 95,
                        "asset_value": domain,
                        "entity_value": domain,
                    }
                )
        expires_at = observations["certificate"].get("expires_at")
        if expires_at:
            days = (datetime.fromisoformat(expires_at) - datetime.now(UTC)).days
            if days <= 30:
                findings.append(
                    {
                        "rule_id": "tls.certificate_expiring",
                        "title": "TLS certificate expires soon",
                        "description": f"The certificate for {domain} expires in {days} days.",
                        "severity": "high" if days <= 7 else "medium",
                        "confidence": 100,
                        "asset_value": domain,
                        "entity_value": domain,
                    }
                )
        return findings

    def _entity(self, context: ProviderContext, entity_type: str, value: str, attributes: dict):
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
