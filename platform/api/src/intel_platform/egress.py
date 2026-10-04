from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path, PurePath
from urllib.parse import urlparse

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import Settings
from .models import EgressArtifact, EgressEvent, EgressEventStatus

POLICY_ID = "github-egress"
POLICY_VERSION = "1.0.0"
SUPPORTED_TEXT_MIMES = {
    "text/plain",
    "text/x-python",
    "text/javascript",
    "application/json",
    "application/yaml",
    "text/yaml",
}
IMAGE_MIMES = {"image/png", "image/jpeg"}
KNOWN_DESTINATIONS = {"github.com", "api.github.com", "uploads.github.com"}
SECRET_PATTERNS = {
    "github_token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic_secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"]?([^\s'\"]{12,})"
    ),
}
PII_PATTERNS = {
    "email_address": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "us_ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
    "phone_number": re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)"),
}
FINANCIAL_PATTERNS = {
    "payment_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "routing_account": re.compile(
        r"(?i)\b(?:routing|account)\s*(?:number|no\.?|#)?\s*[:=]\s*\d{6,17}\b"
    ),
    "wallet_identifier": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
}
PRIVATE_NETWORK = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
INTERNAL_DOMAIN = re.compile(r"\b[a-z0-9.-]+\.(?:internal|local|corp)\b", re.I)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def safe_filename(value: str) -> str:
    candidate = PurePath(value).name
    if not candidate or candidate != value or value in {".", ".."} or "\x00" in value:
        raise ValueError("Unsafe artifact filename")
    return candidate[:255]


def verify_mime(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    sample = data[:4096]
    if b"\x00" not in sample:
        try:
            decoded = sample.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            stripped = decoded.lstrip()
            if stripped.startswith(("{", "[")):
                return "application/json"
            return "text/plain"
    return "application/octet-stream"


def _luhn(candidate: str) -> bool:
    digits = [int(value) for value in re.sub(r"\D", "", candidate)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _scan_text(text_value: str, organization_patterns: list[str]) -> tuple[list[str], list[dict]]:
    classes: set[str] = set()
    findings: list[dict] = []
    groups = (("secret", SECRET_PATTERNS), ("personal_information", PII_PATTERNS))
    for classification, patterns in groups:
        for name, pattern in patterns.items():
            matches = list(pattern.finditer(text_value))
            if matches:
                classes.add(classification)
                findings.append({"type": name, "count": len(matches), "redaction": "required"})
    for name, pattern in FINANCIAL_PATTERNS.items():
        matches = list(pattern.finditer(text_value))
        if name == "payment_card":
            matches = [match for match in matches if _luhn(match.group())]
        if matches:
            classes.add("financial_data")
            findings.append({"type": name, "count": len(matches), "redaction": "required"})
    for name, pattern in (("private_ip", PRIVATE_NETWORK), ("internal_domain", INTERNAL_DOMAIN)):
        matches = list(pattern.finditer(text_value))
        if matches:
            classes.add("internal_infrastructure")
            findings.append({"type": name, "count": len(matches), "redaction": "recommended"})
    for index, value in enumerate(organization_patterns):
        try:
            matches = list(re.finditer(value, text_value, re.I))
        except re.error:
            continue
        if matches:
            classes.add("organization_sensitive")
            findings.append(
                {
                    "type": f"organization_pattern_{index + 1}",
                    "count": len(matches),
                    "redaction": "required",
                }
            )
    return sorted(classes), findings


@dataclass(frozen=True)
class ArtifactScan:
    filename: str
    mime_type: str
    size: int
    sha256: str
    classification: list[str]
    findings: list[dict]
    ocr_status: str
    quarantine_reference: str = ""


def scan_artifact(*, filename: str, content_base64: str, settings: Settings) -> ArtifactScan:
    name = safe_filename(filename)
    try:
        data = base64.b64decode(content_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Artifact content must be valid base64") from exc
    if len(data) > settings.egress_max_artifact_bytes:
        raise ValueError("Artifact exceeds the configured size limit")
    mime = verify_mime(data)
    artifact_hash = hashlib.sha256(data).hexdigest()
    text_value = ""
    ocr_status = "not_applicable"
    if mime in SUPPORTED_TEXT_MIMES:
        text_value = data.decode("utf-8", errors="replace")
    elif mime in IMAGE_MIMES:
        ocr_status = "unavailable"
        try:
            tesseract = shutil.which("tesseract")
            if not tesseract:
                raise FileNotFoundError("tesseract is not installed")
            suffix = ".png" if mime == "image/png" else ".jpg"
            with tempfile.NamedTemporaryFile(suffix=suffix) as image:
                image.write(data)
                image.flush()
                result = subprocess.run(  # noqa: S603 - fixed executable and bounded argv
                    [tesseract, image.name, "stdout"],
                    capture_output=True,
                    check=False,
                    timeout=settings.egress_scan_timeout_seconds,
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"},
                )
            if result.returncode == 0:
                text_value = result.stdout[:1_000_000].decode("utf-8", errors="replace")
                ocr_status = "completed"
            else:
                ocr_status = "failed"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            ocr_status = "unavailable"
    elif mime == "application/pdf":
        # PDF parsing is deliberately fail-closed until a hardened parser worker is shipped.
        ocr_status = "unsupported_safe_parser"
    if (mime in IMAGE_MIMES and ocr_status != "completed") or mime in {
        "application/pdf",
        "application/octet-stream",
    }:
        quarantine = Path(settings.egress_quarantine_dir) / artifact_hash[:2] / artifact_hash
        quarantine.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                quarantine,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as stored:
                stored.write(data)
        return ArtifactScan(
            name,
            mime,
            len(data),
            artifact_hash,
            ["uninspectable"],
            [{"type": "inspection_incomplete", "count": 1, "redaction": "quarantine"}],
            ocr_status,
            str(quarantine),
        )
    classification, findings = _scan_text(text_value, settings.egress_organization_patterns)
    return ArtifactScan(name, mime, len(data), artifact_hash, classification, findings, ocr_status)


def normalize_action(payload: dict) -> dict:
    destination = str(payload.get("destination", "")).strip().lower()
    parsed = urlparse(destination if "://" in destination else f"https://{destination}")
    host = (parsed.hostname or "").rstrip(".")
    action = {
        "action_type": str(payload.get("action_type", "")).strip().lower(),
        "agent_id": str(payload.get("agent_id", "")).strip(),
        "actor_id": str(payload.get("actor_id", "")).strip(),
        "repository": str(payload.get("repository", "")).strip().lower(),
        "requested_visibility": str(payload.get("requested_visibility", "")).strip().lower(),
        "destination": host,
        "artifact_hashes": sorted(set(payload.get("artifact_hashes", []))),
        "working_directory": str(payload.get("working_directory", "")).strip(),
        "correlation_id": str(payload.get("correlation_id", "")).strip(),
    }
    return action


def evaluate_policy(
    action: dict,
    *,
    artifact_classifications: list[str],
    approved_private_repositories: list[str],
    mandatory_scanners_healthy: bool,
    approved_destinations: set[str] | None = None,
) -> tuple[str, list[str], str]:
    if not mandatory_scanners_healthy:
        return "BLOCK", ["MANDATORY_SCANNER_UNHEALTHY"], "A mandatory local scanner is unavailable."
    visibility = action["requested_visibility"]
    action_type = action["action_type"]
    destination = action["destination"]
    sensitive = bool(set(artifact_classifications) - {"public"})
    if "uninspectable" in artifact_classifications:
        return (
            "QUARANTINE",
            ["ARTIFACT_UNINSPECTABLE"],
            "The artifact could not be safely inspected.",
        )
    if visibility == "public" and action_type in {
        "github.repository.create",
        "github.repository.visibility_change",
    }:
        return (
            "BLOCK",
            ["PUBLIC_REPOSITORY_PROHIBITED"],
            "Agents may not create or expose public repositories.",
        )
    destination_allowlist = (
        approved_destinations if approved_destinations is not None else KNOWN_DESTINATIONS
    )
    if destination not in destination_allowlist:
        return (
            "BLOCK",
            ["UNKNOWN_OUTBOUND_DESTINATION"],
            "The outbound destination is not approved.",
        )
    if sensitive and visibility == "public":
        return (
            "BLOCK",
            ["SENSITIVE_ARTIFACT_DETECTED"],
            "Sensitive artifacts may not be published publicly.",
        )
    if action.get("repository") in approved_private_repositories and visibility in {"", "private"}:
        return (
            "ALLOW",
            ["APPROVED_PRIVATE_REPOSITORY"],
            "The private repository is explicitly approved.",
        )
    if action_type in {
        "github.repository.create",
        "github.release.create",
        "github.release.upload",
    }:
        return (
            "REQUIRE_APPROVAL",
            ["HUMAN_APPROVAL_REQUIRED"],
            "This external publication action requires human approval.",
        )
    return (
        "REQUIRE_APPROVAL",
        ["NEW_OUTBOUND_ACTION"],
        "The outbound action requires human approval.",
    )


def seal_event(db: Session, event: EgressEvent) -> None:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
            {"scope": f"cypheryn-egress:{event.organization_id}"},
        )
    previous = db.scalar(
        select(EgressEvent)
        .where(EgressEvent.organization_id == event.organization_id, EgressEvent.id != event.id)
        .order_by(EgressEvent.created_at.desc(), EgressEvent.id.desc())
        .limit(1)
    )
    event.previous_event_hash = previous.event_hash if previous else None
    event.event_hash = digest(event_payload(event))


def event_payload(event: EgressEvent) -> dict:
    created_at = event.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    payload = {
        "id": event.id,
        "organization_id": event.organization_id,
        "agent_id": event.agent_id,
        "actor_id": event.actor_id,
        "correlation_id": event.correlation_id,
        "action_type": event.action_type,
        "destination": event.destination,
        "repository": event.repository,
        "normalized_request": event.normalized_request,
        "request_hash": event.request_hash,
        "decision": event.decision.value if hasattr(event.decision, "value") else event.decision,
        "reason_codes": event.reason_codes,
        "policy_id": event.policy_id,
        "policy_version": event.policy_version,
        "previous_event_hash": event.previous_event_hash,
        "created_at": created_at.astimezone(UTC).isoformat(),
    }
    if event.security_client_id is not None:
        payload.update(
            {
                "security_client_id": event.security_client_id,
                "capability": event.capability,
                "environment": event.environment,
                "resource_scope": event.resource_scope,
                "data_classifications": event.data_classifications,
                "policy_trace": event.policy_trace,
                "policy_mode": event.policy_mode,
                "evaluated_decision": event.evaluated_decision,
                "effective_decision": event.effective_decision,
                "enforced_decision": event.enforced_decision,
                "request_id": event.request_id,
                "idempotency_key_hash": event.idempotency_key_hash,
                "nonce_hash": event.nonce_hash,
            }
        )
    return payload


def verify_event(event: EgressEvent) -> bool:
    return bool(event.event_hash) and secrets.compare_digest(
        event.event_hash, digest(event_payload(event))
    )


def status_for(decision: str) -> EgressEventStatus:
    return {
        "ALLOW": EgressEventStatus.ALLOWED,
        "BLOCK": EgressEventStatus.BLOCKED,
        "REQUIRE_APPROVAL": EgressEventStatus.REQUESTED,
        "ALLOW_WITH_REDACTION": EgressEventStatus.ALLOWED,
        "QUARANTINE": EgressEventStatus.QUARANTINED,
    }[decision]


def store_artifact(event_id: str, scan: ArtifactScan) -> EgressArtifact:
    return EgressArtifact(
        event_id=event_id,
        filename=scan.filename,
        verified_mime_type=scan.mime_type,
        size=scan.size,
        sha256=scan.sha256,
        classification=scan.classification,
        findings=scan.findings,
        ocr_status=scan.ocr_status,
        quarantine_reference=scan.quarantine_reference,
    )
