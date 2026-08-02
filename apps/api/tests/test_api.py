import hashlib
import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lsa.seed import DEMO_TOKEN
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


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


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
    dashboard = client.get("/api/v1/dashboard", headers=headers)
    assert dashboard.json()["total_hosts"] == 1


def test_duplicate_report_rejected(client):
    payload = report_payload()
    headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=headers, json=payload).status_code == 202
    assert client.post("/api/v1/ingest/reports", headers=headers, json=payload).status_code == 409


def test_ingestion_requires_token(client):
    assert client.post("/api/v1/ingest/reports", json=report_payload()).status_code == 401


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


def test_offline_bundle_verifies_all_checksums(client, tmp_path: Path):
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path)
    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )
    assert response.status_code == 202
    assert response.json()["findings_imported"] == 1


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
