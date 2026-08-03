#!/usr/bin/python
from __future__ import annotations

import subprocess
from contextlib import suppress
from typing import Any

from ansible.module_utils.basic import AnsibleModule


def parse_dpkg(output: str) -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[3].startswith("ii"):
            continue
        name, version, architecture, _status, publisher = parts
        applications.append(
            {
                "kind": "package",
                "name": name,
                "version": version,
                "architecture": architecture,
                "source": "dpkg",
                "publisher": publisher or None,
                "status": "installed",
                "enabled": None,
                "running": None,
            }
        )
    return applications


def parse_rpm(output: str) -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        name, version, architecture, publisher = parts
        applications.append(
            {
                "kind": "package",
                "name": name,
                "version": version,
                "architecture": architecture,
                "source": "rpm",
                "publisher": publisher or None,
                "status": "installed",
                "enabled": None,
                "running": None,
            }
        )
    return applications


def parse_services(unit_files: str, units: str) -> list[dict[str, Any]]:
    runtime: dict[str, tuple[str, str, str]] = {}
    for line in units.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            runtime[parts[0]] = (
                parts[2],
                parts[3],
                parts[4] if len(parts) == 5 else "",
            )

    applications: list[dict[str, Any]] = []
    for line in unit_files.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].endswith(".service"):
            continue
        name, unit_state = parts[:2]
        active_state, sub_state, description = runtime.get(name, ("inactive", "dead", ""))
        applications.append(
            {
                "kind": "service",
                "name": name,
                "version": None,
                "architecture": None,
                "source": "systemd",
                "description": description or None,
                "status": active_state,
                "enabled": unit_state in {"enabled", "enabled-runtime", "linked", "linked-runtime"},
                "running": sub_state == "running",
            }
        )
    return applications


def run(command: list[str]) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout


def collect() -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    try:
        applications.extend(
            parse_dpkg(
                run(
                    [
                        "dpkg-query",
                        "-W",
                        "-f=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${Maintainer}\\n",
                    ]
                )
            )
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        with suppress(FileNotFoundError, subprocess.CalledProcessError):
            applications.extend(
                parse_rpm(run(["rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n"]))
            )

    with suppress(FileNotFoundError, subprocess.CalledProcessError):
        applications.extend(
            parse_services(
                run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]),
                run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"]),
            )
        )

    deduplicated = {
        (item["kind"], item["source"], item["name"], item.get("version"), item.get("architecture")): item
        for item in applications
    }
    return [deduplicated[key] for key in sorted(deduplicated, key=lambda item: tuple(value or "" for value in item))]


def main() -> None:
    module = AnsibleModule(argument_spec={}, supports_check_mode=True)
    try:
        module.exit_json(changed=False, applications=collect())
    except Exception as exc:
        module.fail_json(msg=f"Application inventory collection failed: {exc}")


if __name__ == "__main__":
    main()
