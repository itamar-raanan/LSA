import hashlib
import io
import json
import uuid
import zipfile
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lsa.config import Settings, get_settings
from lsa.database import SessionLocal
from lsa.main import app
from lsa.models import Report, Tenant
from lsa.models import IngestionToken
from lsa.seed import DEMO_TOKEN, bootstrap
from lsa.security import hash_ingestion_token
from sqlalchemy import select
from scanner.scripts.build_bundle import build


def report_payload() -> dict:
    hostname = "test-web-01"
    return {
        "schema_version": "1.0",
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(UTC).isoformat(),
        "scanner": {"name": "Linux Security Auditor", "version": "0.1.0"},
        "host": {
            "host_id": str(uuid.uuid4()),
            "hostname": hostname,
            "fqdn": f"{hostname}.example.test",
            "machine_id_hash": f"sha256:{hashlib.sha256(hostname.encode()).hexdigest()}",
            "operating_system": "Debian GNU/Linux",
            "os_family": "debian",
            "os_version": "13",
            "kernel": "6.12.0",
            "architecture": "x86_64",
            "system_info": {
                "cpu_model": "Test CPU",
                "cpu_cores": 4,
                "memory_mb": 8192,
                "uptime_seconds": 3600,
                "virtualization_type": "kvm",
                "virtualization_role": "guest",
                "system_vendor": "Test Vendor",
                "product_name": "Test VM",
                "timezone": "UTC",
            },
            "tags": {"environment": "test"},
        },
        "scan": {"profile": "cis_level1_server", "modules": ["cis"]},
        "summary": {"pass": 12, "fail": 1, "manual": 0, "not_applicable": 2, "error": 0},
        "findings": [
            {
                "control_id": "CIS-DEBIAN13-1.1.1",
                "module": "cis",
                "category": "filesystem",
                "title": "Disable an unused filesystem module",
                "severity": "medium",
                "status": "fail",
                "expected": "module disabled",
                "actual": "module enabled",
            }
        ],
    }


def login(client) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@lsa.local", "password": "test-password"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def register_signing_key(client, tmp_path: Path, host_id: str | None = None) -> tuple[Path, dict]:
    private_key = Ed25519PrivateKey.generate()
    private_key_path = tmp_path / f"{uuid.uuid4()}.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    response = client.post(
        "/api/v1/signing-keys",
        headers={"Authorization": f"Bearer {login(client)}"},
        json={
            "name": "test controller",
            "public_key": b64encode(public_key).decode(),
            "host_id": host_id,
        },
    )
    assert response.status_code == 201, response.text
    return private_key_path, response.json()


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_production_bootstrap_does_not_create_demo_token():
    with SessionLocal() as db:
        bootstrap(
            db,
            Settings(
                environment="production",
                bootstrap_password="production-test-password",
                seed_demo=False,
            ),
        )
        token = db.scalar(
            select(IngestionToken).where(
                IngestionToken.token_hash == hash_ingestion_token(DEMO_TOKEN)
            )
        )
        assert token is None


def test_readiness_checks_database(client):
    assert client.get("/ready").json() == {
        "status": "ready",
        "database": "connected",
        "evidence_vault": "connected",
    }


def test_ingest_and_read_fleet(client):
    payload = report_payload()
    response = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        json=payload,
    )
    assert response.status_code == 202
    assert response.json()["new_findings"] == 1

    user_token = login(client)
    headers = {"Authorization": f"Bearer {user_token}"}
    hosts = client.get("/api/v1/hosts", headers=headers)
    assert hosts.status_code == 200
    assert hosts.json()[0]["hostname"] == "test-web-01"
    assert hosts.json()[0]["system_info"]["cpu_cores"] == 4
    dashboard = client.get("/api/v1/dashboard", headers=headers)
    assert dashboard.json()["total_hosts"] == 1


def test_duplicate_report_rejected(client):
    payload = report_payload()
    headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=headers, json=payload).status_code == 202
    assert client.post("/api/v1/ingest/reports", headers=headers, json=payload).status_code == 409


def test_ingestion_requires_token(client):
    assert client.post("/api/v1/ingest/reports", json=report_payload()).status_code == 401


def test_signature_policy_closes_raw_json_ingestion(client):
    app.dependency_overrides[get_settings] = lambda: Settings(require_signed_bundles=True)
    try:
        response = client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=report_payload(),
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)
    assert response.status_code == 422
    assert response.json()["detail"] == "Signed bundle required"


def test_admin_can_enroll_host_and_issue_scoped_token(client):
    session = login(client)
    headers = {"Authorization": f"Bearer {session}"}
    host_response = client.post(
        "/api/v1/hosts",
        headers=headers,
        json={
            "hostname": "enrolled-web-02",
            "fqdn": "enrolled-web-02.example.test",
            "os_family": "debian",
            "os_version": "13",
            "ip_addresses": ["10.40.8.22"],
            "tags": {"environment": "test", "owner": "platform"},
        },
    )
    assert host_response.status_code == 201
    host_id = host_response.json()["id"]

    token_response = client.post(
        "/api/v1/ingestion-tokens",
        headers=headers,
        json={"name": "enrolled-web-02", "host_id": host_id},
    )
    assert token_response.status_code == 201
    raw_token = token_response.json()["token"]
    assert raw_token.startswith("lsa_ingest_")

    payload = report_payload()
    payload["host"]["host_id"] = host_id
    payload["host"]["hostname"] = "enrolled-web-02"
    ingest = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {raw_token}"},
        json=payload,
    )
    assert ingest.status_code == 202

    tokens = client.get("/api/v1/ingestion-tokens", headers=headers).json()
    created = next(item for item in tokens if item["id"] == token_response.json()["id"])
    assert created["last_used_at"] is not None


def test_enrolled_host_rejects_machine_identity_change(client):
    session = login(client)
    headers = {"Authorization": f"Bearer {session}"}
    host_id = client.post(
        "/api/v1/hosts",
        headers=headers,
        json={"hostname": "identity-node", "os_family": "debian", "os_version": "13"},
    ).json()["id"]
    raw_token = client.post(
        "/api/v1/ingestion-tokens",
        headers=headers,
        json={"name": "identity-node", "host_id": host_id},
    ).json()["token"]
    ingest_headers = {"Authorization": f"Bearer {raw_token}"}
    first = report_payload()
    first["host"]["host_id"] = host_id
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=first).status_code == 202

    second = report_payload()
    second["host"]["host_id"] = host_id
    second["host"]["machine_id_hash"] = f"sha256:{'f' * 64}"
    response = client.post("/api/v1/ingest/reports", headers=ingest_headers, json=second)
    assert response.status_code == 409
    assert response.json()["detail"] == "Machine identity does not match the enrolled host"


def test_admin_soft_deletes_host_and_preserves_report_history(client):
    payload = report_payload()
    ingested = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        json=payload,
    )
    host_id = ingested.json()["host_id"]
    session_headers = {"Authorization": f"Bearer {login(client)}"}
    deleted = client.delete(f"/api/v1/hosts/{host_id}", headers=session_headers)
    assert deleted.status_code == 204
    assert client.get("/api/v1/hosts", headers=session_headers).json() == []
    assert client.get(f"/api/v1/hosts/{host_id}", headers=session_headers).status_code == 404
    with SessionLocal() as db:
        report = db.get(Report, str(payload["report_id"]))
        assert report is not None

    payload["report_id"] = str(uuid.uuid4())
    repeated = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        json=payload,
    )
    assert repeated.status_code == 410


def test_revoked_token_cannot_submit(client):
    session = login(client)
    headers = {"Authorization": f"Bearer {session}"}
    created = client.post(
        "/api/v1/ingestion-tokens",
        headers=headers,
        json={"name": "temporary controller"},
    ).json()
    assert client.delete(
        f"/api/v1/ingestion-tokens/{created['id']}", headers=headers
    ).status_code == 204
    response = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {created['token']}"},
        json=report_payload(),
    )
    assert response.status_code == 401

    repeated = client.delete(
        f"/api/v1/ingestion-tokens/{created['id']}", headers=headers
    )
    assert repeated.status_code == 409
    assert repeated.json()["detail"] == "Ingestion token is already revoked"


def test_token_expiry_must_be_in_the_future(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    response = client.post(
        "/api/v1/ingestion-tokens",
        headers=headers,
        json={
            "name": "already expired",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Token expiry must be in the future"


def test_offline_bundle_verifies_all_checksums(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    assert response.status_code == 202
    assert response.json()["findings_imported"] == 1

    session_headers = {"Authorization": f"Bearer {login(client)}"}
    history = client.get(
        f"/api/v1/hosts/{response.json()['host_id']}/reports", headers=session_headers
    ).json()
    assert history[0]["artifact_available"] is True
    assert history[0]["artifact_size_bytes"] == bundle_path.stat().st_size
    download = client.get(
        f"/api/v1/reports/{response.json()['report_id']}/artifact",
        headers=session_headers,
    )
    assert download.status_code == 200
    assert download.content == bundle_path.read_bytes()
    assert download.headers["x-lsa-artifact-sha256"] == hashlib.sha256(download.content).hexdigest()


def test_evidence_download_rejects_vault_tampering(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    report_id = response.json()["report_id"]
    with SessionLocal() as db:
        report = db.get(Report, report_id)
        object_path = Path("/tmp/lsa-test-artifacts") / report.artifact_object_key
        object_path.write_bytes(b"tampered evidence")
    download = client.get(
        f"/api/v1/reports/{report_id}/artifact",
        headers={"Authorization": f"Bearer {login(client)}"},
    )
    assert download.status_code == 409
    assert download.json()["detail"] == "Evidence integrity verification failed"


def test_evidence_retention_blocks_early_deletion(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    report_id = response.json()["report_id"]
    session_headers = {"Authorization": f"Bearer {login(client)}"}
    blocked = client.delete(f"/api/v1/reports/{report_id}/artifact", headers=session_headers)
    assert blocked.status_code == 409
    assert blocked.json()["detail"] == "Evidence retention period has not expired"

    with SessionLocal() as db:
        report = db.get(Report, report_id)
        report.artifact_retention_until = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    assert client.delete(
        f"/api/v1/reports/{report_id}/artifact", headers=session_headers
    ).status_code == 204
    assert client.get(
        f"/api/v1/reports/{report_id}/artifact", headers=session_headers
    ).status_code == 404


def test_expired_evidence_policy_purge(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    report_id = response.json()["report_id"]
    with SessionLocal() as db:
        report = db.get(Report, report_id)
        report.artifact_retention_until = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    session_headers = {"Authorization": f"Bearer {login(client)}"}
    purge = client.post("/api/v1/artifacts/purge-expired", headers=session_headers)
    assert purge.status_code == 200
    assert purge.json() == {"deleted": 1}
    assert client.get(
        f"/api/v1/reports/{report_id}/artifact", headers=session_headers
    ).status_code == 404


def test_evidence_download_is_tenant_isolated(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    report_id = response.json()["report_id"]
    with SessionLocal() as db:
        other_tenant = Tenant(name="Another tenant", slug="another-tenant")
        db.add(other_tenant)
        db.flush()
        report = db.get(Report, report_id)
        report.tenant_id = other_tenant.id
        db.commit()
    response = client.get(
        f"/api/v1/reports/{report_id}/artifact",
        headers={"Authorization": f"Bearer {login(client)}"},
    )
    assert response.status_code == 404


def test_offline_bundle_rejects_tampered_declared_file(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    output = io.BytesIO()
    with zipfile.ZipFile(bundle_path) as source, zipfile.ZipFile(output, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "metadata/host.json":
                host = json.loads(data)
                host["hostname"] = "tampered-host"
                data = json.dumps(host).encode()
            target.writestr(name, data)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": ("tampered.zip", output.getvalue(), "application/zip")},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Checksum mismatch: metadata/host.json"


def test_signed_bundle_records_verified_provenance(client, tmp_path: Path):
    private_key_path, registered = register_signing_key(client, tmp_path)
    bundle_path = build(
        Path("tests/fixtures/report.json"),
        tmp_path,
        private_key_path,
        registered["id"],
    )
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    assert response.status_code == 202, response.text
    history = client.get(
        f"/api/v1/hosts/{response.json()['host_id']}/reports",
        headers={"Authorization": f"Bearer {login(client)}"},
    ).json()
    assert history[0]["signature_verified"] is True
    assert history[0]["signing_key_id"] == registered["id"]


def test_signed_bundle_rejects_cryptographic_tampering(client, tmp_path: Path):
    private_key_path, registered = register_signing_key(client, tmp_path)
    bundle_path = build(
        Path("tests/fixtures/report.json"), tmp_path, private_key_path, registered["id"]
    )
    output = io.BytesIO()
    with zipfile.ZipFile(bundle_path) as source:
        files = {name: source.read(name) for name in source.namelist()}
    signature = bytearray(files["signature.sig"])
    signature[0] = ord("A") if signature[0] != ord("A") else ord("B")
    files["signature.sig"] = bytes(signature)
    checksum_lines = []
    for line in files["checksums.sha256"].decode().splitlines():
        digest, _, name = line.partition("  ")
        checksum_lines.append(f"{hashlib.sha256(files[name]).hexdigest() if name == 'signature.sig' else digest}  {name}\n")
    files["checksums.sha256"] = "".join(checksum_lines).encode()
    with zipfile.ZipFile(output, "w") as target:
        for name, data in files.items():
            target.writestr(name, data)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": ("tampered-signature.zip", output.getvalue(), "application/zip")},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Bundle signature verification failed"


def test_revoked_signing_key_cannot_submit_bundle(client, tmp_path: Path):
    private_key_path, registered = register_signing_key(client, tmp_path)
    headers = {"Authorization": f"Bearer {login(client)}"}
    assert client.delete(f"/api/v1/signing-keys/{registered['id']}", headers=headers).status_code == 204
    bundle_path = build(
        Path("tests/fixtures/report.json"), tmp_path, private_key_path, registered["id"]
    )
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Signing key is revoked"


def test_host_scoped_signing_key_rejects_another_host(client, tmp_path: Path):
    admin_headers = {"Authorization": f"Bearer {login(client)}"}
    host = client.post(
        "/api/v1/hosts",
        headers=admin_headers,
        json={"hostname": "scoped-host", "os_family": "debian", "os_version": "13"},
    ).json()
    private_key_path, registered = register_signing_key(client, tmp_path, host["id"])
    bundle_path = build(
        Path("tests/fixtures/report.json"), tmp_path, private_key_path, registered["id"]
    )
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Signing key cannot sign for this host"


def test_report_history_compares_new_and_resolved_findings(client):
    first = report_payload()
    first_time = datetime.now(UTC) - timedelta(minutes=5)
    first["generated_at"] = first_time.isoformat()
    headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=headers, json=first).status_code == 202

    second = report_payload()
    second["host"] = first["host"]
    second["generated_at"] = (first_time + timedelta(minutes=3)).isoformat()
    second["findings"][0]["control_id"] = "CIS-DEBIAN13-4.2.7"
    second["findings"][0]["title"] = "Ensure SSH root login is disabled"
    assert client.post("/api/v1/ingest/reports", headers=headers, json=second).status_code == 202

    session_headers = {"Authorization": f"Bearer {login(client)}"}
    history = client.get(
        f"/api/v1/hosts/{first['host']['host_id']}/reports", headers=session_headers
    )
    assert history.status_code == 200
    assert len(history.json()) == 2
    comparison = client.get(
        f"/api/v1/reports/{second['report_id']}/compare", headers=session_headers
    )
    assert comparison.status_code == 200
    assert [item["control_id"] for item in comparison.json()["new"]] == [
        "CIS-DEBIAN13-4.2.7"
    ]
    assert [item["control_id"] for item in comparison.json()["resolved"]] == [
        "CIS-DEBIAN13-1.1.1"
    ]
