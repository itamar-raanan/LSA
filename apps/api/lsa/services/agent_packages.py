from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


AGENT_VERSION = "0.4.2"
PACKAGE_ID = "linux-universal"
PACKAGE_FILENAME = f"lsa-agent-{AGENT_VERSION}-linux-universal.tar.gz"
PACKAGE_ROOT = f"lsa-agent-{AGENT_VERSION}"

NATIVE_PACKAGE_SPECS = (
    (
        "linux-deb",
        f"lsa-agent_{AGENT_VERSION}_all.deb",
        "application/vnd.debian.binary-package",
        "Debian 13 / Ubuntu 24.04+",
        "deb",
    ),
    (
        "linux-rpm",
        f"lsa-agent-{AGENT_VERSION}-1.noarch.rpm",
        "application/x-rpm",
        "RHEL / Rocky / AlmaLinux 9+",
        "rpm",
    ),
)

INSTALL_SCRIPT = r'''#!/bin/sh
set -eu

usage() {
  echo "Usage: sudo ./install.sh --platform-url https://lsa.example.com:8444 --token lsa_enroll_..." >&2
  exit 2
}

PLATFORM_URL=""
ENROLLMENT_TOKEN=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform-url) [ "$#" -ge 2 ] || usage; PLATFORM_URL="$2"; shift 2 ;;
    --token) [ "$#" -ge 2 ] || usage; ENROLLMENT_TOKEN="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run this installer as root." >&2; exit 1; }
[ -n "$PLATFORM_URL" ] && [ -n "$ENROLLMENT_TOKEN" ] || usage
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR=/opt/lsa-agent
CONFIG_DIR=/etc/lsa-agent

python3 "$SOURCE_DIR/agent/integrity.py" verify --root "$SOURCE_DIR" --manifest "$SOURCE_DIR/integrity-manifest.json"
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 "$CONFIG_DIR"
install -d -m 0755 /usr/lib/systemd/system /usr/sbin
rm -rf "$INSTALL_DIR/agent" "$INSTALL_DIR/scanner"
cp -R "$SOURCE_DIR/agent" "$INSTALL_DIR/agent"
cp -R "$SOURCE_DIR/scanner" "$INSTALL_DIR/scanner"
cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"
cp "$SOURCE_DIR/integrity-manifest.json" "$INSTALL_DIR/integrity-manifest.json"

install -m 0644 "$SOURCE_DIR/agent/lsa-agent.service" /usr/lib/systemd/system/lsa-agent.service
install -m 0755 "$SOURCE_DIR/agent/lsa-agent-enroll" /usr/sbin/lsa-agent-enroll
/usr/sbin/lsa-agent-enroll --platform-url "$PLATFORM_URL" --token "$ENROLLMENT_TOKEN"
'''


@dataclass(frozen=True)
class AgentPackage:
    package_id: str
    version: str
    filename: str
    content_type: str
    operating_system: str
    architecture: str
    package_format: str
    release_channel: str
    audit_only: bool
    data: bytes
    sha256: str

    @property
    def size_bytes(self) -> int:
        return len(self.data)


def _source_root() -> Path:
    configured = os.environ.get("LSA_SOURCE_ROOT")
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[4]


def _native_package_root() -> Path:
    configured = os.environ.get("LSA_AGENT_PACKAGE_DIR")
    if configured:
        return Path(configured).resolve()
    return _source_root() / "dist" / "agents"


def _package_files(source_root: Path) -> list[tuple[Path, str, int]]:
    selected: list[tuple[Path, str, int]] = []
    for directory in ("agent", "scanner"):
        root = source_root / directory
        if not root.is_dir():
            raise RuntimeError(f"Agent package source is missing: {root}")
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(source_root)
            if not path.is_file() or path.is_symlink():
                continue
            if "__pycache__" in relative.parts or "tests" in relative.parts:
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            mode = 0o755 if path.name in {"lsa_agent.py"} else 0o644
            selected.append((path, f"{PACKAGE_ROOT}/{relative.as_posix()}", mode))
    return selected


def _add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    archive.addfile(info, io.BytesIO(data))


def _integrity_manifest(source_root: Path) -> bytes:
    files = {
        path.relative_to(source_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path, _, _ in _package_files(source_root)
    }
    files["requirements.txt"] = hashlib.sha256(
        (source_root / "agent" / "requirements.txt").read_bytes()
    ).hexdigest()
    return (
        json.dumps(
            {"algorithm": "sha256", "files": files, "manifest_version": 1},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


@lru_cache(maxsize=1)
def linux_agent_package() -> AgentPackage:
    source_root = _source_root()
    output = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as archive,
    ):
        for path, name, mode in _package_files(_source_root()):
            _add_bytes(archive, name, path.read_bytes(), mode)
        _add_bytes(
            archive,
            f"{PACKAGE_ROOT}/requirements.txt",
            (source_root / "agent" / "requirements.txt").read_bytes(),
            0o644,
        )
        _add_bytes(
            archive,
            f"{PACKAGE_ROOT}/integrity-manifest.json",
            _integrity_manifest(source_root),
            0o644,
        )
        _add_bytes(
            archive,
            f"{PACKAGE_ROOT}/VERSION",
            f"{AGENT_VERSION}\n".encode(),
            0o644,
        )
        _add_bytes(
            archive,
            f"{PACKAGE_ROOT}/install.sh",
            INSTALL_SCRIPT.encode(),
            0o755,
        )
    data = output.getvalue()
    return AgentPackage(
        package_id=PACKAGE_ID,
        version=AGENT_VERSION,
        filename=PACKAGE_FILENAME,
        content_type="application/gzip",
        operating_system="Linux (Debian, Ubuntu, RHEL)",
        architecture="x86_64 / arm64",
        package_format="tar.gz",
        release_channel="stable",
        audit_only=True,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )


@lru_cache(maxsize=1)
def native_agent_packages() -> tuple[AgentPackage, ...]:
    root = _native_package_root()
    packages: list[AgentPackage] = []
    for package_id, filename, content_type, operating_system, package_format in NATIVE_PACKAGE_SPECS:
        path = root / filename
        if not path.is_file():
            continue
        data = path.read_bytes()
        packages.append(
            AgentPackage(
                package_id=package_id,
                version=AGENT_VERSION,
                filename=filename,
                content_type=content_type,
                operating_system=operating_system,
                architecture="noarch",
                package_format=package_format,
                release_channel="stable",
                audit_only=True,
                data=data,
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    return tuple(packages)


def agent_packages() -> tuple[AgentPackage, ...]:
    return (*native_agent_packages(), linux_agent_package())


def get_agent_package(package_id: str) -> AgentPackage | None:
    return next((package for package in agent_packages() if package.package_id == package_id), None)
