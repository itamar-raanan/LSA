#!/usr/bin/env python3
"""Export the scanner's authoritative controls for the platform policy composer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CIS_ROLE = ROOT / "scanner" / "roles" / "cis_debian13_audit"
HEALTH_ROLE = ROOT / "scanner" / "roles" / "linux_security_health"
DEFAULT_OUTPUT = ROOT / "apps" / "api" / "lsa" / "data" / "control_catalog.json"


class ControlLoader(yaml.SafeLoader):
    pass


ControlLoader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))


def load_yaml(path: Path):
    return yaml.load(path.read_text(encoding="utf-8"), Loader=ControlLoader)


def controls(role: Path):
    for path in sorted((role / "vars").glob("*.yml")):
        for value in (load_yaml(path) or {}).values():
            if not isinstance(value, list):
                continue
            for item in value:
                if isinstance(item, dict) and "id" in item and "title" in item:
                    yield item


def cis_category(control_id: str) -> str:
    if control_id.startswith(("1.1", "7.")):
        return "filesystem"
    if control_id.startswith("1.2"):
        return "packages"
    if control_id.startswith("1.3"):
        return "mandatory_access"
    if control_id.startswith(("1.4", "1.5")):
        return "kernel"
    if control_id.startswith(("1.6", "5.2", "5.3", "5.4")):
        return "accounts"
    if control_id.startswith(("1.7", "2.1", "2.2", "2.4")):
        return "services"
    if control_id.startswith("2.3"):
        return "time"
    if control_id.startswith(("3.", "4.")):
        return "network"
    if control_id.startswith("5.1"):
        return "ssh"
    if control_id.startswith("6.1"):
        return "logging"
    if control_id.startswith(("6.2", "6.3")):
        return "audit"
    return "services"


def build_catalog() -> list[dict[str, str]]:
    catalog = [
        {
            "control_id": f"CIS-DEBIAN13-{control['id']}",
            "title": str(control["title"]),
            "category": cis_category(str(control["id"])),
            "module": "cis_debian13",
        }
        for control in controls(CIS_ROLE)
    ]
    catalog.extend(
        {
            "control_id": f"LSA-HEALTH-{control['id']}",
            "title": str(control["title"]),
            "category": str(control["category"]),
            "module": "security_health",
        }
        for control in controls(HEALTH_ROLE)
    )
    identifiers = [item["control_id"] for item in catalog]
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError("control catalog contains duplicate IDs")
    return sorted(catalog, key=lambda item: (item["category"], item["control_id"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(build_catalog(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
