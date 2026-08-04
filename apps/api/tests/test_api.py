import hashlib
import io
import json
import tarfile
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
        "applications": [
            {
                "kind": "package",
                "name": "openssl",
                "version": "3.0.14-1",
                "architecture": "amd64",
                "source": "dpkg",
                "status": "installed",
                "enabled": None,
                "running": None,
            },
            {
                "kind": "service",
                "name": "ssh.service",
                "version": None,
                "architecture": None,
                "source": "systemd",
                "description": "OpenBSD Secure Shell server",
                "status": "active",
                "enabled": True,
                "running": True,
            },
        ],
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


def test_admin_can_download_versioned_agent_package(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    listed = client.get("/api/v1/agent-packages", headers=headers)
    assert listed.status_code == 200, listed.text
    packages = listed.json()
    assert len(packages) == 1
    package = packages[0]
    assert package["id"] == "linux-universal"
    assert package["filename"].endswith("-linux-universal.tar.gz")
    assert package["operating_system"] == "Linux (Debian, Ubuntu, RHEL)"
    assert package["package_format"] == "tar.gz"
    assert package["release_channel"] == "stable"
    assert package["audit_only"] is True

    downloaded = client.get(
        f"/api/v1/agent-packages/{package['id']}/download", headers=headers
    )
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.headers["content-disposition"] == (
        f'attachment; filename="{package["filename"]}"'
    )
    assert hashlib.sha256(downloaded.content).hexdigest() == package["sha256"]
    assert downloaded.headers["x-lsa-agent-sha256"] == package["sha256"]

    with tarfile.open(fileobj=io.BytesIO(downloaded.content), mode="r:gz") as archive:
        names = set(archive.getnames())
        root = f"lsa-agent-{package['version']}"
        assert f"{root}/install.sh" in names
        assert f"{root}/agent/lsa_agent.py" in names
        assert f"{root}/agent/lsa-agent-enroll" in names
        assert f"{root}/agent/lsa-agent.service" in names
        assert f"{root}/scanner/playbooks/scan.yml" in names
        assert f"{root}/scanner/library/lsa_application_inventory.py" in names
        assert f"{root}/scanner/roles/lsa_report/tasks/main.yml" in names
        assert archive.getmember(f"{root}/install.sh").mode == 0o755


def test_agent_package_download_requires_admin_session(client):
    response = client.get("/api/v1/agent-packages/linux-universal/download")
    assert response.status_code == 401


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


def test_agent_enrollment_and_signed_policy_poll(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    policies = client.get("/api/v1/agent-policies", headers=headers)
    assert policies.status_code == 200
    monitor = next(policy for policy in policies.json() if policy["name"] == "Monitor (Audit Only)")
    assert monitor["default_mode"] == "audit"

    groups = client.get("/api/v1/agent-groups", headers=headers)
    assert groups.status_code == 200
    group = groups.json()[0]
    token_response = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=headers,
        json={
            "name": "test enrollment",
            "group_id": group["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert token_response.status_code == 201, token_response.text

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    enrollment = client.post(
        "/api/v1/agent/enroll",
        headers={"Authorization": f"Bearer {token_response.json()['token']}"},
        json={
            "name": "test-agent-01",
            "public_key": b64encode(public_key).decode(),
            "agent_version": "0.1.0",
            "capabilities": ["audit"],
            "hostname": "test-agent-01",
            "fqdn": "test-agent-01.example.test",
            "machine_id_hash": f"sha256:{hashlib.sha256(b'test-agent-01').hexdigest()}",
            "operating_system": "Debian GNU/Linux",
            "os_family": "debian",
            "os_version": "13",
            "kernel": "6.12.0",
            "architecture": "x86_64",
            "ip_addresses": ["192.0.2.10"],
            "system_info": {"cpu_cores": 4},
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    agent_id = enrollment.json()["agent_id"]

    timestamp = str(int(datetime.now(UTC).timestamp()))
    body_hash = hashlib.sha256(b"").hexdigest()
    signed = f"GET\n/api/v1/agent/policy\n{timestamp}\n{body_hash}".encode()
    policy = client.get(
        "/api/v1/agent/policy",
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(signed)).decode(),
        },
    )
    assert policy.status_code == 200, policy.text
    assert policy.json()["policy_name"] == "Monitor (Audit Only)"
    assert policy.json()["enforcement_enabled"] is False

    heartbeat_body = json.dumps(
        {"agent_version": "0.1.1", "capabilities": ["audit"], "policy_version": 1},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    heartbeat_message = (
        f"POST\n/api/v1/agent/heartbeat\n{timestamp}\n"
        f"{hashlib.sha256(heartbeat_body).hexdigest()}"
    ).encode()
    heartbeat = client.post(
        "/api/v1/agent/heartbeat",
        content=heartbeat_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(heartbeat_message)).decode(),
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["policy_version"] == 1

    agents = client.get("/api/v1/agents", headers=headers)
    assert agents.status_code == 200
    assert agents.json()[0]["hostname"] == "test-agent-01"

    queued = client.post(
        "/api/v1/agents/actions/run-audit",
        headers=headers,
        json={"agent_ids": [agent_id]},
    )
    assert queued.status_code == 202, queued.text
    assert queued.json()[0]["status"] == "queued"

    task_path = "/api/v1/agent/tasks/next"
    timestamp = str(int(datetime.now(UTC).timestamp()))
    task_message = f"GET\n{task_path}\n{timestamp}\n{hashlib.sha256(b'').hexdigest()}".encode()
    claimed = client.get(
        task_path,
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(task_message)).decode(),
        },
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["status"] == "dispatched"

    completion_path = f"/api/v1/agent/tasks/{claimed.json()['id']}/complete"
    completion_body = json.dumps(
        {"status": "completed", "result": {"policy_version": 1}, "error": None},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    completion_message = (
        f"POST\n{completion_path}\n{timestamp}\n{hashlib.sha256(completion_body).hexdigest()}"
    ).encode()
    completed = client.post(
        completion_path,
        content=completion_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(completion_message)).decode(),
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"
    assert client.get(task_path, headers={
        "X-LSA-Agent-ID": agent_id,
        "X-LSA-Agent-Timestamp": timestamp,
        "X-LSA-Agent-Signature": b64encode(private_key.sign(
            f"GET\n{task_path}\n{timestamp}\n{hashlib.sha256(b'').hexdigest()}".encode()
        )).decode(),
    }).json() is None


def test_policy_updates_are_immutable_versions(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    created = client.post(
        "/api/v1/agent-policies",
        headers=headers,
        json={
            "name": "Database baseline",
            "default_mode": "audit",
            "control_modes": {"CIS-DEBIAN13-1.1.1": "disabled"},
            "settings": {"schedule_minutes": 30},
        },
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    updated = client.put(
        f"/api/v1/agent-policies/{policy_id}",
        headers=headers,
        json={
            "description": "Second version",
            "default_mode": "audit",
            "control_modes": {"CIS-DEBIAN13-1.1.1": "manual"},
            "settings": {"schedule_minutes": 45},
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2
    assert updated.json()["control_modes"]["CIS-DEBIAN13-1.1.1"] == "manual"

    history = client.get(f"/api/v1/agent-policies/{policy_id}/versions", headers=headers)
    assert history.status_code == 200, history.text
    assert [item["version"] for item in history.json()] == [2, 1]

    restored = client.post(
        f"/api/v1/agent-policies/{policy_id}/restore",
        headers=headers,
        json={"version": 1},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["version"] == 3
    assert restored.json()["control_modes"]["CIS-DEBIAN13-1.1.1"] == "disabled"


def test_control_catalog_is_available_before_first_report(client):
    response = client.get(
        "/api/v1/control-catalog",
        headers={"Authorization": f"Bearer {login(client)}"},
    )

    assert response.status_code == 200
    assert len(response.json()) == 432
    assert len({item["control_id"] for item in response.json()}) == 432


def test_unused_agent_enrollment_token_can_be_revoked(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    group = client.get("/api/v1/agent-groups", headers=headers).json()[0]
    created = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=headers,
        json={
            "name": "temporary enrollment",
            "group_id": group["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 201

    listed = client.get("/api/v1/agent-enrollment-tokens", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["token_prefix"] == created.json()["token_prefix"]
    assert "token" not in listed.json()[0]

    revoked = client.delete(
        f"/api/v1/agent-enrollment-tokens/{created.json()['id']}", headers=headers
    )
    assert revoked.status_code == 204


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
    assert hosts.json()[0]["application_count"] == 2
    applications = client.get(
        f"/api/v1/hosts/{payload['host']['host_id']}/applications", headers=headers
    )
    assert applications.status_code == 200
    assert [(item["kind"], item["name"]) for item in applications.json()] == [
        ("package", "openssl"),
        ("service", "ssh.service"),
    ]
    dashboard = client.get("/api/v1/dashboard", headers=headers)
    assert dashboard.json()["total_hosts"] == 1


def test_application_inventory_tracks_versions_and_removals(client):
    first = report_payload()
    ingest_headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=first).status_code == 202

    second = report_payload()
    second["host"]["host_id"] = first["host"]["host_id"]
    second["host"]["machine_id_hash"] = first["host"]["machine_id_hash"]
    second["applications"] = [{**first["applications"][0], "version": "3.0.15-1"}]
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=second).status_code == 202

    headers = {"Authorization": f"Bearer {login(client)}"}
    active = client.get(
        f"/api/v1/hosts/{first['host']['host_id']}/applications", headers=headers
    ).json()
    assert [(item["name"], item["version"]) for item in active] == [("openssl", "3.0.15-1")]
    history = client.get(
        f"/api/v1/hosts/{first['host']['host_id']}/applications?include_removed=true",
        headers=headers,
    ).json()
    assert len(history) == 3
    assert len([item for item in history if item["removed_at"] is not None]) == 2


def test_application_estate_summary_and_host_correlation(client):
    first = report_payload()
    second = report_payload()
    second["host"]["hostname"] = "test-db-02"
    second["host"]["fqdn"] = "test-db-02.example.test"
    second["host"]["machine_id_hash"] = f"sha256:{hashlib.sha256(b'test-db-02').hexdigest()}"
    second["host"]["tags"] = {"environment": "production"}
    second["applications"][0]["version"] = "3.0.15-1"
    ingest_headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=first).status_code == 202
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=second).status_code == 202

    headers = {"Authorization": f"Bearer {login(client)}"}
    response = client.get("/api/v1/applications", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["metrics"] == {
        "unique_applications": 2,
        "package_count": 1,
        "service_count": 1,
        "installation_count": 4,
        "reporting_hosts": 2,
        "version_drift_count": 1,
    }
    openssl = next(item for item in body["applications"] if item["name"] == "openssl")
    assert openssl["host_count"] == 2
    assert openssl["version_count"] == 2

    correlation = client.get(
        "/api/v1/applications/correlation",
        params={"name": "openssl", "kind": "package", "source": "dpkg"},
        headers=headers,
    )
    assert correlation.status_code == 200, correlation.text
    assert [(item["hostname"], item["version"]) for item in correlation.json()] == [
        ("test-web-01", "3.0.14-1"),
        ("test-db-02", "3.0.15-1"),
    ]
    assert correlation.json()[1]["environment"] == "production"


def test_legacy_report_without_inventory_does_not_remove_existing_applications(client):
    first = report_payload()
    ingest_headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=first).status_code == 202
    second = report_payload()
    second["host"]["host_id"] = first["host"]["host_id"]
    second["host"]["machine_id_hash"] = first["host"]["machine_id_hash"]
    second.pop("applications")
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=second).status_code == 202
    headers = {"Authorization": f"Bearer {login(client)}"}
    applications = client.get(
        f"/api/v1/hosts/{first['host']['host_id']}/applications", headers=headers
    ).json()
    assert len(applications) == 2


def test_findings_default_limit_covers_expanded_scanner_catalog(client):
    payload = report_payload()
    template = payload["findings"][0]
    payload["findings"] = [
        {
            **template,
            "control_id": f"CIS-DEBIAN13-TEST-{index:03}",
            "title": f"Expanded audit control {index}",
        }
        for index in range(250)
    ]
    payload["summary"] = {
        "pass": 0,
        "fail": 250,
        "manual": 0,
        "not_applicable": 0,
        "error": 0,
    }
    response = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        json=payload,
    )
    assert response.status_code == 202

    findings = client.get(
        "/api/v1/findings",
        headers={"Authorization": f"Bearer {login(client)}"},
    )
    assert findings.status_code == 200
    assert len(findings.json()) == 250


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
