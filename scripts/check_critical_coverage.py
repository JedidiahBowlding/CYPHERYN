#!/usr/bin/env python3
"""Enforce measured coverage on CYPHERYN-owned security and integrity modules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

THRESHOLDS = {
    "integrity.py": 90,
    "observability.py": 85,
    "process_isolation.py": 80,
    "provider_certification.py": 90,
    "provider_contract.py": 85,
    "provider_safety.py": 85,
    "providers/threat_intel.py": 90,
    "security_controls.py": 90,
    "integrity_anchor.py": 70,
    "scanner_isolation.py": 80,
    "docker_api_scanner.py": 80,
    "scanner_orchestrator.py": 80,
    "scanner_orchestrator_client.py": 80,
    "worker.py": 75,
    "detection_engine.py": 70,
    "normalization.py": 90,
    "report_exports.py": 90,
    "notifications.py": 80,
    "malware_analysis.py": 90,
}


def check(report: dict) -> list[str]:
    measured = {
        str(path).replace("\\", "/"): value
        for path, value in report.get("files", {}).items()
    }
    failures = []
    for suffix, threshold in THRESHOLDS.items():
        matches = [value for path, value in measured.items() if path.endswith(suffix)]
        if len(matches) != 1:
            failures.append(f"{suffix}: coverage record missing or ambiguous")
            continue
        percent = float(matches[0]["summary"]["percent_covered"])
        if percent + 0.0001 < threshold:
            failures.append(f"{suffix}: {percent:.2f}% is below required {threshold}%")
        else:
            print(f"[PASS] {suffix}: {percent:.2f}% >= {threshold}%")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage_json", type=Path)
    args = parser.parse_args()
    failures = check(json.loads(args.coverage_json.read_text(encoding="utf-8")))
    for failure in failures:
        print(f"[FAIL] {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
