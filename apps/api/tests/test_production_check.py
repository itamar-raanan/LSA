import base64
import io
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.production_check import EXAMPLE_ENCRYPTION_KEY, validate
from deploy.smoke_test import bundle_bytes


def production_values() -> dict[str, str]:
    return {
        "LSA_POSTGRES_PASSWORD": "database-password-0123456789",
        "LSA_S3_ACCESS_KEY": "internal-object-access",
        "LSA_S3_SECRET_KEY": "internal-object-secret-012345678901",
        "LSA_SESSION_SECRET": "session-secret-012345678901234567890",
        "LSA_SETTINGS_ENCRYPTION_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "LSA_BOOTSTRAP_PASSWORD": "administrator-password-012345",
        "LSA_BOOTSTRAP_EMAIL": "security-admin@internal.example",
        "LSA_SEED_DEMO": "false",
        "LSA_REQUIRE_SIGNED_BUNDLES": "true",
        "LSA_AGENT_NETWORK_SCOPE": "internal",
        "LSA_AGENT_FIREWALL_ACKNOWLEDGED": "true",
        "LSA_MANAGEMENT_TLS_INSTALLED": "true",
        "LSA_VOLUME_ENCRYPTION_ACKNOWLEDGED": "true",
        "LSA_BACKUP_RESTORE_DRILL_ACKNOWLEDGED": "true",
        "LSA_TLS_HOST": "lsa.internal",
        "LSA_AGENT_PUBLIC_URL": "https://lsa.internal:8444",
        "LSA_S3_SERVER_SIDE_ENCRYPTION": "none",
    }


def test_production_check_accepts_explicit_internal_profile():
    errors, warnings = validate(production_values())
    assert errors == []
    assert warnings == ["Object-level encryption is disabled; encrypted host storage is required"]


def test_production_check_rejects_placeholders_and_unacknowledged_internal_boundary():
    values = production_values()
    values.update(
        LSA_POSTGRES_PASSWORD="replace-with-password",
        LSA_SETTINGS_ENCRYPTION_KEY=EXAMPLE_ENCRYPTION_KEY,
        LSA_REQUIRE_SIGNED_BUNDLES="false",
        LSA_AGENT_NETWORK_SCOPE="internet",
        LSA_AGENT_FIREWALL_ACKNOWLEDGED="false",
        LSA_TLS_HOST="localhost",
        LSA_AGENT_PUBLIC_URL="https://localhost:8444",
    )
    errors, _ = validate(values)
    assert len(errors) == 7
    assert all("replace-with-password" not in error for error in errors)


def test_staging_check_defers_only_tls_installation_and_restore_drill():
    values = production_values()
    values["LSA_MANAGEMENT_TLS_INSTALLED"] = "false"
    values["LSA_BACKUP_RESTORE_DRILL_ACKNOWLEDGED"] = "false"
    errors, warnings = validate(values, release=False)
    assert errors == []
    assert any("LSA_MANAGEMENT_TLS_INSTALLED" in warning for warning in warnings)
    assert any("LSA_BACKUP_RESTORE_DRILL_ACKNOWLEDGED" in warning for warning in warnings)


def test_production_smoke_bundle_is_signed_when_a_key_is_available():
    key = Ed25519PrivateKey.generate()
    bundle = bundle_bytes(Path("tests/fixtures/report.json"), key, "acceptance-key")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        signature = base64.b64decode(archive.read("signature.sig"), validate=True)
        key.public_key().verify(signature, manifest_bytes)
        assert manifest["signature"] == {
            "algorithm": "ed25519",
            "key_id": "acceptance-key",
        }
