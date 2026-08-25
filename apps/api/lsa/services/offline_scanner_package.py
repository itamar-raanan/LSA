from __future__ import annotations

import hashlib
import io
import os
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


SCANNER_VERSION = "0.6.1"
PACKAGE_ROOT = f"lsa-offline-scanner-{SCANNER_VERSION}"
PACKAGE_FILENAME = f"{PACKAGE_ROOT}.zip"

INVENTORY_TEMPLATE = """[linux]
# Replace these values with the target host and the persistent host ID from LSA.
linux-host-01 ansible_host=192.0.2.10 ansible_user=admin lsa_host_id=00000000-0000-4000-8000-000000000000

[linux:vars]
# Offline mode never contacts the LSA platform while collecting evidence.
lsa_delivery_mode=offline
lsa_profile=production_server

# Production deployments require a registered signing key. Keep the private key
# outside this directory and never commit it to source control.
lsa_signing_key_file=/secure/path/lsa-signing-key.pem
lsa_signing_key_id=REPLACE_WITH_SIGNING_KEY_ID_FROM_LSA
"""

RUN_SCRIPT = r'''#!/bin/sh
set -eu

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INVENTORY_FILE=${LSA_INVENTORY_FILE:-"$PACKAGE_DIR/inventory.ini"}

command -v ansible-playbook >/dev/null 2>&1 || {
  echo "ansible-playbook is required on the controller." >&2
  exit 1
}

[ -f "$INVENTORY_FILE" ] || {
  echo "Inventory not found: $INVENTORY_FILE" >&2
  echo "Edit inventory.ini or set LSA_INVENTORY_FILE." >&2
  exit 1
}

cd "$PACKAGE_DIR/scanner"
ansible-playbook -i "$INVENTORY_FILE" playbooks/scan.yml \
  -e lsa_delivery_mode=offline "$@"

echo
echo "Offline collection completed. Report bundles are under:"
echo "  $PACKAGE_DIR/scanner/reports/<inventory-host>/"
'''

README = f"""# LSA Offline Scanner {SCANNER_VERSION}

This package collects read-only Linux security posture and application inventory
without requiring the target host or Ansible controller to connect to LSA.

## What You Need

- An Ansible controller with Python 3 and `ansible-playbook`.
- SSH and privilege-escalation access from that controller to the Linux host.
- The persistent Host ID and host-scoped ingestion token created in LSA.
- For production: an Ed25519 signing key registered in LSA.

The ingestion token and private signing key are secrets. They are intentionally not
included in this ZIP. The token is entered only when importing the completed report.

## Step 1 — Install The Ansible Requirement

From this package directory, install the declared collection from your approved
Ansible Galaxy source or internal mirror:

```bash
ansible-galaxy collection install -r scanner/requirements.yml
```

## Step 2 — Create And Register A Signing Key

Generate the controller key once. The command prints the public key and fingerprint:

```bash
python3 scanner/scripts/generate_signing_key.py /secure/path/lsa-signing-key.pem
chmod 600 /secure/path/lsa-signing-key.pem
```

In LSA, open Administration → Credentials And Trust → Signing Keys. Register only
the printed public key. Copy the returned Signing Key ID into `inventory.ini`.

## Step 3 — Configure The Inventory

Edit `inventory.ini` and replace:

- `ansible_host` and `ansible_user` with the target connection values.
- `lsa_host_id` with the persistent Host ID created in LSA.
- `lsa_profile` if the host is not a production server.
- `lsa_signing_key_file` with the controller-only private key path.
- `lsa_signing_key_id` with the ID shown by LSA after registration.

Supported deployment profiles are `production_server`, `minimal_server`, `router`,
and `container`.

## Step 4 — Run The Read-Only Scan

```bash
chmod +x run-offline.sh
./run-offline.sh
```

Ansible may prompt for SSH or become credentials according to your inventory and
controller configuration. Extra Ansible arguments can be appended, for example:

```bash
./run-offline.sh --ask-become-pass --limit linux-host-01
```

## Step 5 — Locate The Report Bundle

The completed portable ZIP is written under:

```text
scanner/reports/<inventory-host>/lsa-report-*.zip
```

Do not extract or modify that ZIP. LSA validates its manifest, checksums, signature,
signing-key scope, Host ID, and machine identity during import.

## Step 6 — Import Into LSA

Open Evidence Intake in LSA, choose the generated `lsa-report-*.zip`, enter the
host-scoped ingestion token, and select Import Report. After acceptance, open the
host record to review findings, applications, scores, and retained evidence.

## Safety Boundary

The scanner reads posture and inventory. It does not apply remediation, change
configuration, restart services, or install software on the target host.
"""


@dataclass(frozen=True)
class OfflineScannerPackage:
    version: str
    filename: str
    data: bytes
    sha256: str

    @property
    def size_bytes(self) -> int:
        return len(self.data)


def _source_root() -> Path:
    configured = os.environ.get("LSA_SOURCE_ROOT")
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[4]


def _scanner_files(source_root: Path) -> list[tuple[str, bytes, int]]:
    scanner_root = source_root / "scanner"
    if not scanner_root.is_dir():
        raise RuntimeError(f"Offline scanner source is missing: {scanner_root}")
    selected: list[tuple[str, bytes, int]] = []
    for path in sorted(scanner_root.rglob("*")):
        relative = path.relative_to(scanner_root)
        if not path.is_file() or path.is_symlink():
            continue
        if "__pycache__" in relative.parts or "tests" in relative.parts or "reports" in relative.parts:
            continue
        if path.suffix in {".pyc", ".pyo"} or path.name == "inventory.example.ini":
            continue
        mode = 0o755 if path.name in {"generate_signing_key.py", "submit_bundle.py"} else 0o644
        selected.append((f"scanner/{relative.as_posix()}", path.read_bytes(), mode))
    return selected


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(f"{PACKAGE_ROOT}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (mode & 0xFFFF) << 16
    info.create_system = 3
    return info


@lru_cache(maxsize=1)
def offline_scanner_package() -> OfflineScannerPackage:
    files = [
        ("README.md", README.encode(), 0o644),
        ("inventory.ini", INVENTORY_TEMPLATE.encode(), 0o600),
        ("run-offline.sh", RUN_SCRIPT.encode(), 0o755),
        *_scanner_files(_source_root()),
    ]
    checksums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data, _ in files
    ).encode()
    files.append(("checksums.sha256", checksums, 0o644))

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data, mode in files:
            archive.writestr(_zip_info(name, mode), data)
    data = output.getvalue()
    return OfflineScannerPackage(
        version=SCANNER_VERSION,
        filename=PACKAGE_FILENAME,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )
