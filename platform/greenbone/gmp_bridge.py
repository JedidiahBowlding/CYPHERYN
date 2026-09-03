"""Minimal JSON bridge between CYPHERYN and the local Greenbone GMP socket."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp


SOCKET_PATH = "/run/gvmd/gvmd.sock"


def _xml(response: ET.Element | str) -> ET.Element:
    return ET.fromstring(response) if isinstance(response, str) else response


def _first_id(response: ET.Element | str, tag: str) -> str:
    response = _xml(response)
    item = response.find(f".//{tag}")
    if item is None or not item.get("id"):
        raise RuntimeError(f"Greenbone did not return a {tag}")
    return str(item.get("id"))


def _text(item: ET.Element | str | None, path: str, default: str = "") -> str:
    if item is None:
        return default
    item = _xml(item)
    value = item.findtext(path)
    return value.strip() if value else default


def _severity(value: float) -> str:
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0:
        return "low"
    return "info"


def _results(response: ET.Element | str) -> list[dict]:
    response = _xml(response)
    rows = []
    for result in response.findall(".//result")[:500]:
        score_text = _text(result, "severity", "0")
        try:
            score = float(score_text)
        except ValueError:
            score = 0.0
        nvt = result.find("nvt")
        refs = []
        if nvt is not None:
            refs = [
                {"type": ref.get("type", ""), "id": ref.get("id", "")}
                for ref in nvt.findall("refs/ref")
            ]
        cves = sorted(
            {ref["id"].upper() for ref in refs if ref["id"].upper().startswith("CVE-")}
        )
        rows.append(
            {
                "id": result.get("id", ""),
                "name": _text(result, "name", "OpenVAS vulnerability"),
                "host": _text(result, "host"),
                "port": _text(result, "port"),
                "description": _text(result, "description"),
                "solution": _text(result, "nvt/solution"),
                "qod": _text(result, "qod/value", "0"),
                "oid": nvt.get("oid", "") if nvt is not None else "",
                "cvss": score,
                "severity": _severity(score),
                "cves": cves,
                "references": refs[:30],
            }
        )
    return rows


def run(payload: dict) -> dict:
    connection = UnixSocketConnection(path=SOCKET_PATH)
    with Gmp(connection=connection) as gmp:
        authentication = _xml(gmp.authenticate(payload["username"], payload["password"]))
        if not authentication.get("status", "").startswith("2"):
            raise RuntimeError(authentication.get("status_text", "Authentication failed"))
        if payload.get("action") == "ping":
            version = _xml(gmp.get_version())
            return {"version": _text(version, ".//version"), "socket": SOCKET_PATH}
        if payload.get("action") == "users":
            users = _xml(gmp.send_command("<get_users/>"))
            return {
                "users": [
                    {"id": item.get("id", ""), "name": _text(item, "name")}
                    for item in users.findall(".//user")
                ]
            }
        target_value = payload["target"]
        task_name = payload["task_name"]
        tasks = _xml(gmp.get_tasks(filter_string=f'name="{task_name}"', details=True))
        task = tasks.find(".//task")

        if payload.get("action") == "delete_task":
            if task is not None and task.get("id"):
                gmp.delete_task(str(task.get("id")), ultimate=True)
            return {"deleted": task is not None}

        if task is None:
            configs = gmp.get_scan_configs(filter_string='name="Full and fast"')
            scanners = gmp.get_scanners(filter_string='name="OpenVAS Default"')
            port_lists = gmp.get_port_lists(filter_string='name="All IANA assigned TCP"')
            config_id = _first_id(configs, "config")
            scanner_id = _first_id(scanners, "scanner")
            port_list_id = _first_id(port_lists, "port_list")
            targets = _xml(gmp.get_targets(filter_string=f'name="{task_name}"'))
            target = targets.find(".//target")
            if target is not None and target.get("id"):
                target_id = str(target.get("id"))
            else:
                target_response = _xml(
                    gmp.create_target(
                        name=task_name,
                        hosts=[target_value],
                        port_list_id=port_list_id,
                        alive_test="ICMP, TCP-ACK Service & ARP Ping",
                    )
                )
                target_id = str(target_response.get("id"))
            task_response = _xml(
                gmp.create_task(
                    name=task_name,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id,
                )
            )
            task_id = str(task_response.get("id"))
            start_response = _xml(gmp.start_task(task_id))
            return {
                "task_id": task_id,
                "report_id": _text(start_response, "report_id"),
                "status": "Requested",
                "progress": 0,
                "results": [],
            }

        task_id = str(task.get("id"))
        status = _text(task, "status", "Unknown")
        progress_text = _text(task, "progress", "0")
        try:
            progress = int(float(progress_text))
        except ValueError:
            progress = 0
        report = task.find("last_report/report")
        report_id = str(report.get("id")) if report is not None else ""
        rows = []
        if status == "Done" and report_id:
            report_response = gmp.get_report(
                report_id=report_id,
                details=True,
                filter_string="apply_overrides=0 levels=hmlg min_qod=70 rows=500",
            )
            rows = _results(report_response)
        return {
            "task_id": task_id,
            "report_id": report_id,
            "status": status,
            "progress": progress,
            "results": rows,
        }


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        print(json.dumps({"ok": True, "data": run(payload)}, separators=(",", ":")))
    except Exception as exc:  # returned to the trusted local API only
        print(json.dumps({"ok": False, "error": str(exc)[:500]}, separators=(",", ":")))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
