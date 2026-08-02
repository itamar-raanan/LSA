from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


AGENT_VERSION = "0.1.0"
PACKAGE_ID = "linux-universal"
PACKAGE_FILENAME = f"lsa-agent-{AGENT_VERSION}-linux-universal.tar.gz"
PACKAGE_ROOT = f"lsa-agent-{AGENT_VERSION}"

REQUIREMENTS = """ansible-core>=2.18,<3
cryptography>=45,<47
httpx>=0.28,<1
"""

INSTALL_SCRIPT = r'''#!/bin/sh
set -eu

usage() {
  echo "Usage: sudo ./install.sh --platform-url https://lsa.example.com:8443 --token lsa_enroll_... [--ca-bundle /path/to/ca.pem]" >&2
  exit 2
}

PLATFORM_URL=""
ENROLLMENT_TOKEN=""
CA_BUNDLE=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform-url) [ "$#" -ge 2 ] || usage; PLATFORM_URL="$2"; shift 2 ;;
    --token) [ "$#" -ge 2 ] || usage; ENROLLMENT_TOKEN="$2"; shift 2 ;;
    --ca-bundle) [ "$#" -ge 2 ] || usage; CA_BUNDLE="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run this installer as root." >&2; exit 1; }
[ -n "$PLATFORM_URL" ] && [ -n "$ENROLLMENT_TOKEN" ] || usage
if [ -z "$CA_BUNDLE" ]; then
  for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
    if [ -f "$candidate" ]; then CA_BUNDLE="$candidate"; break; fi
  done
fi
[ -f "$CA_BUNDLE" ] || { echo "A readable system or private CA bundle is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3.11 or newer is required." >&2; exit 1; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "Python 3.11 or newer is required." >&2
  exit 1
}

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR=/opt/lsa-agent
CONFIG_DIR=/etc/lsa-agent

install -d -m 0755 "$INSTALL_DIR" "$CONFIG_DIR"
rm -rf "$INSTALL_DIR/agent" "$INSTALL_DIR/scanner"
cp -R "$SOURCE_DIR/agent" "$INSTALL_DIR/agent"
cp -R "$SOURCE_DIR/scanner" "$INSTALL_DIR/scanner"
cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --disable-pip-version-check --no-cache-dir -r "$INSTALL_DIR/requirements.txt"

python3 - "$CONFIG_DIR/config.json" "$PLATFORM_URL" "$CA_BUNDLE" <<'PY'
import json
import sys

path, platform_url, ca_bundle = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "platform_url": platform_url.rstrip("/"),
            "scanner_dir": "/opt/lsa-agent/scanner",
            "state_dir": "/var/lib/lsa-agent",
            "ansible_playbook": "/opt/lsa-agent/venv/bin/ansible-playbook",
            "ca_bundle": ca_bundle,
            "tags": {},
        },
        handle,
        indent=2,
    )
    handle.write("\n")
PY
chmod 0600 "$CONFIG_DIR/config.json"

install -m 0644 "$SOURCE_DIR/agent/lsa-agent.service" /etc/systemd/system/lsa-agent.service
systemctl daemon-reload
"$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent/lsa_agent.py" \
  --config "$CONFIG_DIR/config.json" enroll --token "$ENROLLMENT_TOKEN"
systemctl enable --now lsa-agent.service

echo "LSA agent installed, enrolled, and started."
'''


@dataclass(frozen=True)
class AgentPackage:
    package_id: str
    version: str
    filename: str
    content_type: str
    operating_system: str
    architecture: str
    data: bytes
    sha256: str

    @property
    def size_bytes(self) -> int:
        return len(self.data)


def _source_root() -> Path:
    configured = os.environ.get("LSA_SOURCE_ROOT")
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[4]


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


@lru_cache(maxsize=1)
def linux_agent_package() -> AgentPackage:
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
            REQUIREMENTS.encode(),
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
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def get_agent_package(package_id: str) -> AgentPackage | None:
    package = linux_agent_package()
    return package if package.package_id == package_id else None
