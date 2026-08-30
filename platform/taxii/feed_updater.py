"""Build the local TAXII collection from trusted public defensive feeds."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import select

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
NAMESPACE = uuid.UUID("bf66816e-986f-4c5f-a8cd-e47b22786c21")
MITRE_TYPES = {"attack-pattern", "campaign", "malware", "tool", "identity"}


def stix_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, value)}"


def timestamp(value: str | None = None) -> str:
    if value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def download_json(client: httpx.Client, url: str) -> dict:
    response = client.get(url)
    response.raise_for_status()
    return response.json()


def mitre_objects(client: httpx.Client) -> list[dict]:
    bundle = download_json(client, MITRE_URL)
    selected = [
        item
        for item in bundle.get("objects", [])
        if isinstance(item, dict) and item.get("type") in MITRE_TYPES
    ]
    return selected[:1800]


def cisa_objects(client: httpx.Client) -> list[dict]:
    catalog = download_json(client, CISA_KEV_URL)
    result = []
    for item in catalog.get("vulnerabilities", [])[:1800]:
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        created = timestamp(item.get("dateAdded"))
        result.append(
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": stix_id("vulnerability", f"cisa-kev:{cve}"),
                "created": created,
                "modified": created,
                "name": cve,
                "description": (
                    f"{item.get('vendorProject', '')} {item.get('product', '')}: "
                    f"{item.get('vulnerabilityName', '')}. "
                    f"Required action: {item.get('requiredAction', '')}"
                ).strip(),
                "labels": ["cisa-kev", "known-exploited-vulnerability"],
                "confidence": 100,
                "external_references": [
                    {
                        "source_name": "cisa-kev",
                        "external_id": cve,
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    }
                ],
            }
        )
    return result


def abuse_key(api_dir: Path) -> str:
    sys.path.insert(0, str(api_dir / "src"))
    previous = Path.cwd()
    try:
        os.chdir(api_dir)
        from intel_platform.config import get_settings
        from intel_platform.database import SessionLocal
        from intel_platform.models import ProviderConfiguration
        from intel_platform.provider_secrets import decrypt_credentials

        with SessionLocal() as db:
            configuration = db.scalar(
                select(ProviderConfiguration).where(
                    ProviderConfiguration.provider.in_(("abuse_ch", "urlhaus")),
                    ProviderConfiguration.encrypted_credentials.is_not(None),
                )
            )
            if not configuration or not configuration.encrypted_credentials:
                return ""
            credentials = decrypt_credentials(
                configuration.encrypted_credentials,
                get_settings().provider_encryption_key,
            )
            return str(credentials.get("auth_key") or credentials.get("api_key") or "")
    finally:
        os.chdir(previous)


def urlhaus_objects(client: httpx.Client, key: str) -> list[dict]:
    if not key:
        return []
    response = client.get(URLHAUS_EXPORT.format(key=key))
    if response.status_code != 200:
        raise RuntimeError(f"URLhaus export returned HTTP {response.status_code}")
    lines = (line for line in response.text.splitlines() if not line.startswith("#"))
    result = []
    for row in csv.reader(lines):
        if len(row) < 8 or row[0].lower() in {"id", "urlhaus_id"}:
            continue
        _, date_added, url, status, *_rest = row
        if status.lower() != "online" or not url.startswith(("http://", "https://")):
            continue
        created = timestamp(date_added)
        valid_until = (datetime.now(UTC) + timedelta(days=7)).isoformat().replace("+00:00", "Z")
        escaped = url.replace("\\", "\\\\").replace("'", "\\'")
        result.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": stix_id("indicator", f"urlhaus:{url}"),
                "created": created,
                "modified": created,
                "name": "URLhaus active malware URL",
                "description": "Active malware-distribution URL published by abuse.ch URLhaus.",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[url:value = '{escaped}']",
                "pattern_type": "stix",
                "valid_from": created,
                "valid_until": valid_until,
                "confidence": 90,
                "labels": ["urlhaus", "malware-distribution"],
                "external_references": [
                    {"source_name": "urlhaus", "url": "https://urlhaus.abuse.ch/"}
                ],
            }
        )
        if len(result) >= 1200:
            break
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--status-file", type=Path, required=True)
    parser.add_argument("--api-dir", type=Path, required=True)
    parser.add_argument("--refresh-hours", type=int, default=24)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.output.exists() and not args.force:
        age = datetime.now(UTC).timestamp() - args.output.stat().st_mtime
        if age < args.refresh_hours * 3600:
            print("Local TAXII feeds are current; refresh skipped.")
            return

    objects: list[dict] = []
    status: dict[str, dict] = {}
    try:
        key = abuse_key(args.api_dir)
    except (OSError, RuntimeError, ValueError):
        key = ""
    with httpx.Client(timeout=90, follow_redirects=False, headers={"User-Agent": "CYPHERYN-FeedSync/1.0"}) as client:
        for name, loader in (
            ("mitre_attack", lambda: mitre_objects(client)),
            ("cisa_kev", lambda: cisa_objects(client)),
            ("urlhaus", lambda: urlhaus_objects(client, key)),
        ):
            try:
                loaded = loader()
                objects.extend(loaded)
                status[name] = {"status": "updated", "objects": len(loaded)}
            except (httpx.HTTPError, json.JSONDecodeError, OSError, RuntimeError, ValueError) as exc:
                status[name] = {"status": "failed", "error": str(exc)[:200]}

    unique = {str(item.get("id")): item for item in objects if item.get("id")}
    if not unique:
        raise RuntimeError("No trusted feed produced usable STIX objects; existing collection retained")
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(unique.values())[:4900],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(".tmp")
    temporary.write_text(json.dumps(bundle, separators=(",", ":")))
    temporary.replace(args.output)
    status["updated_at"] = timestamp()
    status["total_objects"] = len(bundle["objects"])
    args.status_file.write_text(json.dumps(status, indent=2) + "\n")
    print(f"Local TAXII feeds updated: {len(bundle['objects'])} STIX objects")


if __name__ == "__main__":
    main()
