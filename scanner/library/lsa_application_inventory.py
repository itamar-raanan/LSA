#!/usr/bin/python
from __future__ import annotations

import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from ansible.module_utils.basic import AnsibleModule


def package_purl(
    package_type: str,
    namespace: str,
    name: str,
    version: str,
    architecture: str | None,
    distribution_version: str | None,
) -> str:
    qualifiers: dict[str, str] = {}
    if architecture:
        qualifiers["arch"] = architecture
    if distribution_version:
        qualifiers["distro"] = f"{namespace}-{distribution_version}"
    value = (
        f"pkg:{package_type}/{quote(namespace, safe='')}/{quote(name, safe='')}"
        f"@{quote(version, safe='')}"
    )
    return f"{value}?{urlencode(qualifiers)}" if qualifiers else value


def parse_dpkg(
    output: str,
    distribution: str = "debian",
    distribution_version: str | None = None,
) -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) not in {5, 7} or not parts[3].startswith("ii"):
            continue
        name, version, architecture, _status, publisher = parts[:5]
        binary_name = name.split(":", 1)[0]
        source_package = parts[5] if len(parts) == 7 else binary_name
        source_version = parts[6] if len(parts) == 7 else version
        applications.append(
            {
                "kind": "package",
                "name": name,
                "version": version,
                "architecture": architecture,
                "source": "dpkg",
                "source_package": source_package or binary_name,
                "source_version": source_version or version,
                "purl": package_purl(
                    "deb", distribution, binary_name, version, architecture, distribution_version
                ),
                "publisher": publisher or None,
                "status": "installed",
                "enabled": None,
                "running": None,
            }
        )
    return applications


def parse_source_rpm(value: str, installed_version: str, fallback_name: str) -> tuple[str, str]:
    normalized = value.removesuffix(".src.rpm")
    parts = normalized.rsplit("-", 2)
    if len(parts) != 3:
        return fallback_name, installed_version
    name, version, release = parts
    epoch = installed_version.split(":", 1)[0] if ":" in installed_version else "0"
    source_version = f"{version}-{release}"
    if epoch not in {"", "0", "(none)"}:
        source_version = f"{epoch}:{source_version}"
    return name, source_version


def parse_rpm(
    output: str,
    distribution: str = "rhel",
    distribution_version: str | None = None,
) -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) not in {4, 5}:
            continue
        name, version, architecture, publisher = parts[:4]
        source_package, source_version = (
            parse_source_rpm(parts[4], version, name) if len(parts) == 5 else (name, version)
        )
        applications.append(
            {
                "kind": "package",
                "name": name,
                "version": version,
                "architecture": architecture,
                "source": "rpm",
                "source_package": source_package,
                "source_version": source_version,
                "purl": package_purl(
                    "rpm", distribution, name, version, architecture, distribution_version
                ),
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


def os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def collect() -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    release = os_release()
    distribution = release.get("ID", "linux").lower()
    distribution_version = release.get("VERSION_ID")
    try:
        applications.extend(
            parse_dpkg(
                run(
                    [
                        "dpkg-query",
                        "-W",
                        "-f=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${Maintainer}\\t${source:Package}\\t${source:Version}\\n",
                    ]
                ),
                distribution=distribution,
                distribution_version=distribution_version,
            )
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        with suppress(FileNotFoundError, subprocess.CalledProcessError):
            applications.extend(
                parse_rpm(
                    run(
                        [
                            "rpm",
                            "-qa",
                            "--qf",
                            "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\t%{SOURCERPM}\\n",
                        ]
                    ),
                    distribution=distribution,
                    distribution_version=distribution_version,
                )
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
