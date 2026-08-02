import hashlib
import uuid
from datetime import UTC, datetime

from lsa.seed import DEMO_TOKEN


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

