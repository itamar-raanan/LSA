import base64
import json
import os
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from scanner.scripts.build_bundle import build
from scanner.scripts.generate_signing_key import generate


def test_bundle_contains_portable_artifacts(tmp_path: Path):
    fixture = Path("tests/fixtures/report.json")
    bundle_path = build(fixture, tmp_path)
    with zipfile.ZipFile(bundle_path) as bundle:
        names = set(bundle.namelist())
        assert {"manifest.json", "report.json", "report.html", "report.csv", "checksums.sha256"} <= names
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["report_id"] == "0191d6ab-3e3e-7a55-9b70-54a32d536abd"


def test_bundle_signature_covers_exact_manifest_bytes(tmp_path: Path):
    key_path = tmp_path / "controller.pem"
    metadata = generate(key_path)
    assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"

    bundle_path = build(
        Path("tests/fixtures/report.json"),
        tmp_path,
        key_path,
        "registered-key-id",
    )
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    with zipfile.ZipFile(bundle_path) as bundle:
        manifest_bytes = bundle.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        assert manifest["signature"] == {
            "algorithm": "ed25519",
            "key_id": "registered-key-id",
        }
        private_key.public_key().verify(
            base64.b64decode(bundle.read("signature.sig"), validate=True),
            manifest_bytes,
        )
    assert len(base64.b64decode(metadata["public_key"], validate=True)) == 32
