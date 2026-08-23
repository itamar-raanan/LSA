import hashlib
import io
import json
import tarfile
import uuid
import zipfile
from base64 import b64decode, b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from lsa.config import Settings, get_settings
from lsa.database import SessionLocal
from lsa.main import app
from lsa.models import (
    AgentGroup,
    AgentPolicy,
    AgentTask,
    AuditEvent,
    Host,
    IngestionToken,
    LinuxAgent,
    PlatformCommandSigningKey,
    RemediationChangeSet,
    RemediationPlan,
    Report,
    SigningKey,
    Tenant,
    User,
    now_utc,
)
from lsa.seed import DEMO_TOKEN, bootstrap
from lsa.security import hash_ingestion_token, hash_password
from lsa.schemas import RemediationValidationReceiptSubmission
from lsa.services.platform_command_trust import active_platform_command_key
from lsa.services.remediation_receipts import checkpoint_journal_digest, verify_validation_receipt
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
                "source_package": "openssl",
                "source_version": "3.0.14-1",
                "purl": "pkg:deb/debian/openssl@3.0.14-1?arch=amd64&distro=debian-13",
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
                "remediation_summary": "Disable the module in /etc/modprobe.d/example.conf.",
                "remediation_commands": ["printf 'install example /bin/false\\n' > /etc/modprobe.d/example.conf"],
                "verification_commands": ["modprobe --showconfig | grep example"],
                "service_restart": True,
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
    connectivity = client.get("/api/v1/agent-connectivity", headers=headers)
    assert connectivity.status_code == 200, connectivity.text
    connectivity_data = connectivity.json()
    assert connectivity_data["public_url"] == "https://localhost:8444"
    assert connectivity_data["platform_trust"]["algorithm"] == "Ed25519"
    assert len(connectivity_data["platform_trust"]["fingerprint"]) == 64
    assert len(b64decode(connectivity_data["platform_trust"]["public_key"])) == 32

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

    downloaded = client.get(f"/api/v1/agent-packages/{package['id']}/download", headers=headers)
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.headers["content-disposition"] == (f'attachment; filename="{package["filename"]}"')
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
        install_script = archive.extractfile(f"{root}/install.sh").read().decode()
        assert "--platform-command-key" in install_script


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
    enrollment_data = enrollment.json()
    agent_id = enrollment_data["agent_id"]
    trust = enrollment_data["platform_trust"]
    envelope = enrollment_data["platform_envelope"]
    Ed25519PublicKey.from_public_bytes(b64decode(trust["public_key"])).verify(
        b64decode(enrollment_data["platform_signature"]),
        json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(),
    )
    assert envelope["kind"] == "agent-enrollment"
    assert envelope["agent_id"] == agent_id
    assert envelope["payload"]["execution_enabled"] is False
    assert envelope["payload"]["agent_identity_fingerprint"] == hashlib.sha256(public_key).hexdigest()
    assert token_response.json()["platform_trust"] == trust

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

    # An upgraded agent can request signed responses before its new capability
    # has been persisted by a heartbeat. Once attested, signed control is sticky.
    timestamp = str(int(datetime.now(UTC).timestamp()))
    signed = f"GET\n/api/v1/agent/policy\n{timestamp}\n{body_hash}".encode()
    upgraded_policy = client.get(
        "/api/v1/agent/policy",
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(signed)).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert upgraded_policy.status_code == 200, upgraded_policy.text
    assert upgraded_policy.json()["platform_envelope"]["kind"] == "agent-policy"

    heartbeat_path = "/api/v1/agent/heartbeat"
    heartbeat_payload = {
        "agent_version": "0.5.0",
        "capabilities": ["audit", "signed-platform-control-v1"],
        "policy_version": 1,
    }
    heartbeat_body = json.dumps(heartbeat_payload, separators=(",", ":")).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    heartbeat_message = (
        f"POST\n{heartbeat_path}\n{timestamp}\n{hashlib.sha256(heartbeat_body).hexdigest()}"
    ).encode()
    heartbeat = client.post(
        heartbeat_path,
        content=heartbeat_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(heartbeat_message)).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["platform_envelope"]["kind"] == "agent-heartbeat"

    timestamp = str(int(datetime.now(UTC).timestamp()))
    signed = f"GET\n/api/v1/agent/policy\n{timestamp}\n{body_hash}".encode()
    sticky_policy = client.get(
        "/api/v1/agent/policy",
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(signed)).decode(),
        },
    )
    assert sticky_policy.status_code == 200, sticky_policy.text
    assert sticky_policy.json()["platform_envelope"]["kind"] == "agent-policy"


def test_new_agent_receives_signed_monotonic_control_responses(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    group = client.get("/api/v1/agent-groups", headers=headers).json()[0]
    token_response = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=headers,
        json={
            "name": "signed control enrollment",
            "group_id": group["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    enrollment = client.post(
        "/api/v1/agent/enroll",
        headers={"Authorization": f"Bearer {token_response.json()['token']}"},
        json={
            "name": "signed-control-agent",
            "public_key": b64encode(public_key).decode(),
            "agent_version": "0.6.0",
            "capabilities": ["audit", "signed-platform-control-v1", "platform-key-rotation-v1"],
            "hostname": "signed-control-agent",
            "machine_id_hash": f"sha256:{hashlib.sha256(b'signed-control-agent').hexdigest()}",
            "operating_system": "Debian GNU/Linux",
            "os_family": "debian",
            "os_version": "13",
            "kernel": "6.12.0",
            "architecture": "x86_64",
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    enrollment_data = enrollment.json()
    assert enrollment_data["platform_envelope"]["payload"]["signed_control_required"] is True
    agent_id = enrollment_data["agent_id"]
    platform_public_key = Ed25519PublicKey.from_public_bytes(
        b64decode(enrollment_data["platform_trust"]["public_key"])
    )

    def agent_headers(method: str, path: str, body: bytes = b""):
        timestamp = str(int(datetime.now(UTC).timestamp()))
        message = f"{method}\n{path}\n{timestamp}\n{hashlib.sha256(body).hexdigest()}".encode()
        return {
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(private_key.sign(message)).decode(),
        }

    sequence = 1
    for path, kind in (
        ("/api/v1/agent/policy", "agent-policy"),
        ("/api/v1/agent/tasks/next", "agent-task"),
    ):
        response = client.get(path, headers=agent_headers("GET", path))
        assert response.status_code == 200, response.text
        result = response.json()
        envelope = result["platform_envelope"]
        platform_public_key.verify(
            b64decode(result["platform_signature"]),
            json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(),
        )
        assert envelope["kind"] == kind
        assert envelope["agent_id"] == agent_id
        assert envelope["payload"]["execution_enabled"] is False
        assert envelope["sequence"] == sequence + 1
        sequence = envelope["sequence"]
    assert result["platform_envelope"]["payload"]["task"] is None

    heartbeat_path = "/api/v1/agent/heartbeat"
    heartbeat_payload = {
        "agent_version": "0.6.0",
        "capabilities": ["audit", "signed-platform-control-v1", "platform-key-rotation-v1"],
        "policy_version": 1,
    }
    heartbeat_body = json.dumps(heartbeat_payload, separators=(",", ":")).encode()
    heartbeat = client.post(
        heartbeat_path,
        headers={
            **agent_headers("POST", heartbeat_path, heartbeat_body),
            "Content-Type": "application/json",
        },
        content=heartbeat_body,
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["platform_envelope"]["kind"] == "agent-heartbeat"
    assert heartbeat.json()["platform_envelope"]["sequence"] == sequence + 1

    agents = client.get("/api/v1/agents", headers=headers)
    assert agents.status_code == 200
    assert agents.json()[0]["hostname"] == "signed-control-agent"

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
    claimed_task = claimed.json()["platform_envelope"]["payload"]["task"]
    assert claimed_task["status"] == "dispatched"

    completion_path = f"/api/v1/agent/tasks/{claimed_task['id']}/complete"
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
    assert completed.json()["platform_envelope"]["payload"]["task"]["status"] == "completed"
    empty = client.get(task_path, headers=agent_headers("GET", task_path))
    assert empty.json()["platform_envelope"]["payload"]["task"] is None


def test_platform_command_key_rotation_waits_for_agent_acknowledgement(client):
    admin_headers = {"Authorization": f"Bearer {login(client)}"}
    group = client.get("/api/v1/agent-groups", headers=admin_headers).json()[0]
    enrollment_token = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=admin_headers,
        json={
            "name": "rotation enrollment",
            "group_id": group["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    ).json()
    reusable_token = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=admin_headers,
        json={
            "name": "rotation automation",
            "group_id": group["id"],
            "token_type": "reusable",
            "max_uses": 10,
            "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        },
    ).json()
    agent_key = Ed25519PrivateKey.generate()
    agent_public = agent_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    enrollment = client.post(
        "/api/v1/agent/enroll",
        headers={"Authorization": f"Bearer {enrollment_token['token']}"},
        json={
            "name": "rotation-agent",
            "public_key": b64encode(agent_public).decode(),
            "agent_version": "0.6.0",
            "capabilities": ["audit", "signed-platform-control-v1", "platform-key-rotation-v1"],
            "hostname": "rotation-agent",
            "machine_id_hash": f"sha256:{hashlib.sha256(b'rotation-agent').hexdigest()}",
            "operating_system": "Debian GNU/Linux",
            "os_family": "debian",
            "os_version": "13",
            "kernel": "6.12.0",
            "architecture": "x86_64",
        },
    ).json()
    agent_id = enrollment["agent_id"]
    current_public = Ed25519PublicKey.from_public_bytes(
        b64decode(enrollment["platform_trust"]["public_key"])
    )

    def signed_headers(method: str, path: str, body: bytes = b""):
        timestamp = str(int(datetime.now(UTC).timestamp()))
        message = f"{method}\n{path}\n{timestamp}\n{hashlib.sha256(body).hexdigest()}".encode()
        return {
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(agent_key.sign(message)).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        }

    staged = client.post("/api/v1/platform-command-key-rotation", headers=admin_headers)
    assert staged.status_code == 201, staged.text
    rotation = staged.json()
    assert rotation["status"] == "staged"
    assert rotation["eligible_agents"] == 1
    assert rotation["acknowledged_agents"] == 0
    assert rotation["blocking_agents"] == 1

    blocked = client.post(
        "/api/v1/platform-command-key-rotation/activate", headers=admin_headers
    )
    assert blocked.status_code == 409

    policy_path = "/api/v1/agent/policy"
    policy = client.get(policy_path, headers=signed_headers("GET", policy_path)).json()
    envelope = policy["platform_envelope"]
    current_public.verify(
        b64decode(policy["platform_signature"]),
        json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(),
    )
    proposal = envelope["payload"]["platform_key_rotation"]
    assert proposal["phase"] == "staged"
    assert proposal["proposal"]["next_key"]["fingerprint"] == rotation["next_key"]["fingerprint"]

    heartbeat_path = "/api/v1/agent/heartbeat"
    heartbeat_payload = {
        "agent_version": "0.6.0",
        "capabilities": ["audit", "signed-platform-control-v1", "platform-key-rotation-v1"],
        "policy_version": 1,
        "platform_key_ack_fingerprint": rotation["next_key"]["fingerprint"],
    }
    heartbeat_body = json.dumps(heartbeat_payload, separators=(",", ":")).encode()
    heartbeat = client.post(
        heartbeat_path,
        content=heartbeat_body,
        headers={
            **signed_headers("POST", heartbeat_path, heartbeat_body),
            "Content-Type": "application/json",
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    readiness = client.get("/api/v1/agent-connectivity", headers=admin_headers).json()
    assert readiness["key_rotation"]["status"] == "ready"
    assert readiness["key_rotation"]["acknowledged_agents"] == 1

    activated = client.post(
        "/api/v1/platform-command-key-rotation/activate", headers=admin_headers
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["platform_trust"]["fingerprint"] == rotation["next_key"]["fingerprint"]

    new_policy = client.get(policy_path, headers=signed_headers("GET", policy_path)).json()
    next_public = Ed25519PublicKey.from_public_bytes(b64decode(rotation["next_key"]["public_key"]))
    next_public.verify(
        b64decode(new_policy["platform_signature"]),
        json.dumps(
            new_policy["platform_envelope"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode(),
    )
    assert new_policy["platform_envelope"]["payload"]["platform_key_rotation"]["phase"] == "activated"
    tokens = client.get("/api/v1/agent-enrollment-tokens", headers=admin_headers).json()
    retired_token = next(token for token in tokens if token["id"] == reusable_token["id"])
    assert retired_token["revoked_at"] is not None


def test_platform_command_key_rotation_can_be_aborted_before_activation(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    initial = client.get("/api/v1/agent-connectivity", headers=headers).json()
    staged = client.post("/api/v1/platform-command-key-rotation", headers=headers)
    assert staged.status_code == 201, staged.text
    assert staged.json()["status"] == "ready"
    assert staged.json()["current_key"]["fingerprint"] == initial["platform_trust"]["fingerprint"]

    aborted = client.delete("/api/v1/platform-command-key-rotation", headers=headers)
    assert aborted.status_code == 204, aborted.text
    connectivity = client.get("/api/v1/agent-connectivity", headers=headers).json()
    assert connectivity["platform_trust"]["fingerprint"] == initial["platform_trust"]["fingerprint"]
    assert connectivity["key_rotation"] is None


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

    revoked = client.delete(f"/api/v1/agent-enrollment-tokens/{created.json()['id']}", headers=headers)
    assert revoked.status_code == 204


def test_reusable_tenant_enrollment_token_tracks_and_limits_host_enrollments(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    group = client.get("/api/v1/agent-groups", headers=headers).json()[0]
    created = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=headers,
        json={
            "name": "tenant automation",
            "group_id": group["id"],
            "token_type": "reusable",
            "max_uses": 2,
            "expires_at": (datetime.now(UTC) + timedelta(days=90)).isoformat(),
        },
    )
    assert created.status_code == 201, created.text
    token_data = created.json()
    assert token_data["token"].startswith("lsa_tenant_enroll_")
    assert token_data["token_type"] == "reusable"
    assert token_data["max_uses"] == 2

    duplicate = client.post(
        "/api/v1/agent-enrollment-tokens",
        headers=headers,
        json={
            "name": "second tenant token",
            "group_id": group["id"],
            "token_type": "reusable",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
    )
    assert duplicate.status_code == 409

    def enroll(index: int):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return client.post(
            "/api/v1/agent/enroll",
            headers={"Authorization": f"Bearer {token_data['token']}"},
            json={
                "name": f"tenant-agent-{index}",
                "public_key": b64encode(public_key).decode(),
                "agent_version": "0.4.4",
                "capabilities": ["audit"],
                "hostname": f"tenant-agent-{index}",
                "machine_id_hash": f"sha256:{hashlib.sha256(f'tenant-agent-{index}'.encode()).hexdigest()}",
                "operating_system": "Debian GNU/Linux",
                "os_family": "debian",
                "os_version": "13",
                "kernel": "6.12.0",
                "architecture": "x86_64",
            },
        )

    assert enroll(1).status_code == 201
    assert enroll(2).status_code == 201
    exhausted = enroll(3)
    assert exhausted.status_code == 401
    assert "exhausted" in exhausted.json()["detail"]

    listed = client.get("/api/v1/agent-enrollment-tokens", headers=headers)
    reusable = next(item for item in listed.json() if item["id"] == token_data["id"])
    assert reusable["use_count"] == 2
    assert reusable["last_used_at"] is not None
    assert reusable["used_at"] is None

    revoked = client.delete(
        f"/api/v1/agent-enrollment-tokens/{token_data['id']}", headers=headers
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
        token = db.scalar(select(IngestionToken).where(IngestionToken.token_hash == hash_ingestion_token(DEMO_TOKEN)))
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
    applications = client.get(f"/api/v1/hosts/{payload['host']['host_id']}/applications", headers=headers)
    assert applications.status_code == 200
    assert [(item["kind"], item["name"]) for item in applications.json()] == [
        ("package", "openssl"),
        ("service", "ssh.service"),
    ]
    assert applications.json()[0]["source_package"] == "openssl"
    assert applications.json()[0]["source_version"] == "3.0.14-1"
    assert applications.json()[0]["purl"].startswith("pkg:deb/debian/openssl@")
    dashboard = client.get("/api/v1/dashboard", headers=headers)
    assert dashboard.json()["total_hosts"] == 1
    finding = client.get("/api/v1/findings", headers=headers).json()[0]
    assert finding["verification_commands"] == ["modprobe --showconfig | grep example"]
    assert finding["service_restart"] is True


def test_remediation_plan_review_lifecycle_is_non_executable(client):
    payload = report_payload()
    assert (
        client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=payload,
        ).status_code
        == 202
    )
    headers = {"Authorization": f"Bearer {login(client)}"}
    finding = client.get("/api/v1/findings", headers=headers).json()[0]

    created = client.post(
        "/api/v1/remediation-plans",
        headers=headers,
        json={"finding_id": finding["id"], "rationale": "Prepare a reviewed maintenance change."},
    )
    assert created.status_code == 201, created.text
    plan = created.json()
    assert plan["status"] == "pending_approval"
    assert plan["current_state"] == "module enabled"
    assert plan["required_state"] == "module disabled"
    assert plan["remediation_summary"].startswith("Disable the module")
    assert plan["affected_paths"] == ["/etc/modprobe.d/example.conf"]
    assert plan["source_is_current"] is True
    assert plan["finding_still_open"] is True
    assert plan["execution_enabled"] is False
    assert plan["execution_status"] == "not_supported"
    assert "cannot change hosts" in plan["execution_reason"]

    duplicate = client.post("/api/v1/remediation-plans", headers=headers, json={"finding_id": finding["id"]})
    assert duplicate.status_code == 409

    filtered = client.get(
        "/api/v1/remediation-plans",
        params={"status": "pending_approval", "host_id": plan["host_id"]},
        headers=headers,
    )
    assert filtered.status_code == 200
    assert [item["id"] for item in filtered.json()] == [plan["id"]]

    approved = client.post(f"/api/v1/remediation-plans/{plan['id']}/approve", headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["version"] == 2
    assert approved.json()["approved_by_name"] == "Security Administrator"
    assert approved.json()["execution_enabled"] is False
    assert client.post(f"/api/v1/remediation-plans/{plan['id']}/approve", headers=headers).status_code == 409

    canceled = client.post(
        f"/api/v1/remediation-plans/{plan['id']}/cancel",
        headers=headers,
        json={"reason": "Maintenance window changed."},
    )
    assert canceled.status_code == 200
    assert canceled.json()["status"] == "canceled"
    assert canceled.json()["version"] == 3
    assert canceled.json()["cancellation_reason"] == "Maintenance window changed."

    replacement = client.post("/api/v1/remediation-plans", headers=headers, json={"finding_id": finding["id"]})
    assert replacement.status_code == 201
    rejected = client.post(
        f"/api/v1/remediation-plans/{replacement.json()['id']}/reject",
        headers=headers,
        json={"reason": "The proposed change needs application-owner review."},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["rejection_reason"].startswith("The proposed change")

    with SessionLocal() as db:
        actions = list(
            db.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.target_type == "remediation_plan")
                .order_by(AuditEvent.created_at)
            ).all()
        )
    assert actions == [
        "remediation_plan.requested",
        "remediation_plan.approved",
        "remediation_plan.canceled",
        "remediation_plan.requested",
        "remediation_plan.rejected",
    ]


def test_remediation_plan_rejects_stale_approval_and_requires_admin_for_changes(client):
    payload = report_payload()
    ingest_headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=payload).status_code == 202
    token = login(client)
    headers = {"Authorization": f"Bearer {token}"}
    finding = client.get("/api/v1/findings", headers=headers).json()[0]
    created = client.post("/api/v1/remediation-plans", headers=headers, json={"finding_id": finding["id"]})
    assert created.status_code == 201
    plan_id = created.json()["id"]

    newer = report_payload()
    newer["host"]["host_id"] = payload["host"]["host_id"]
    newer["host"]["machine_id_hash"] = payload["host"]["machine_id_hash"]
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=newer).status_code == 202

    stale = client.get(f"/api/v1/remediation-plans/{plan_id}", headers=headers)
    assert stale.status_code == 200
    assert stale.json()["source_is_current"] is False
    assert stale.json()["finding_still_open"] is True
    approval = client.post(f"/api/v1/remediation-plans/{plan_id}/approve", headers=headers)
    assert approval.status_code == 409
    assert "stale" in approval.json()["detail"].lower()

    with SessionLocal() as db:
        other_tenant = Tenant(name="Other Tenant", slug="other-tenant")
        db.add(other_tenant)
        db.flush()
        db.add(
            User(
                tenant_id=other_tenant.id,
                email="admin@other.test",
                display_name="Other Administrator",
                password_hash=hash_password("other-password"),
                role="admin",
            )
        )
        db.commit()
    other_login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@other.test", "password": "other-password"},
    )
    assert other_login.status_code == 200
    other_headers = {"Authorization": f"Bearer {other_login.json()['access_token']}"}
    assert client.get("/api/v1/remediation-plans", headers=other_headers).json() == []
    assert client.get(f"/api/v1/remediation-plans/{plan_id}", headers=other_headers).status_code == 404
    assert (
        client.post(
            "/api/v1/remediation-plans",
            headers=other_headers,
            json={"finding_id": finding["id"]},
        ).status_code
        == 404
    )

    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == "admin@lsa.local"))
        assert admin is not None
        admin.role = "analyst"
        db.commit()
    assert client.get("/api/v1/remediation-plans", headers=headers).status_code == 200
    forbidden = client.post(
        f"/api/v1/remediation-plans/{plan_id}/cancel",
        headers=headers,
        json={"reason": "Analysts cannot mutate plans."},
    )
    assert forbidden.status_code == 403


def test_remediation_action_catalog_is_authenticated_filterable_and_non_executable(client):
    assert client.get("/api/v1/remediation-actions").status_code == 401
    headers = {"Authorization": f"Bearer {login(client)}"}

    listed = client.get("/api/v1/remediation-actions", headers=headers)
    assert listed.status_code == 200, listed.text
    assert len(listed.json()) == 4
    assert all(action["execution_enabled"] is False for action in listed.json())
    assert all(action["execution_status"] == "catalog_only" for action in listed.json())

    filtered = client.get(
        "/api/v1/remediation-actions",
        params={
            "control_id": "CIS-DEBIAN13-5.1.21",
            "os_family": "debian",
            "os_version": "13",
        },
        headers=headers,
    )
    assert filtered.status_code == 200
    assert [action["action_id"] for action in filtered.json()] == ["linux.ssh.permit-root-login.disabled"]
    action = filtered.json()[0]
    assert action["operations"][0] == {
        "kind": "config_setting",
        "resource": "openssh_server",
        "path": "/etc/ssh/sshd_config.d/90-lsa-hardening.conf",
        "format": "sshd_config",
        "key": "PermitRootLogin",
        "value_from": "desired_value",
        "backup_required": True,
    }
    assert action["rollback"][0]["kind"] == "restore_backup"
    assert client.get("/api/v1/remediation-actions", params={"os_family": "debian"}, headers=headers).status_code == 422
    assert client.get("/api/v1/remediation-actions/linux.missing", headers=headers).status_code == 404


def test_remediation_plan_snapshots_matching_declarative_action(client):
    payload = report_payload()
    payload["findings"][0].update(
        {
            "control_id": "CIS-DEBIAN13-5.1.21",
            "module": "cis_debian13",
            "category": "ssh",
            "title": "Ensure sshd PermitRootLogin is disabled",
            "severity": "high",
            "expected": "permitrootlogin is no",
            "actual": "permitrootlogin yes",
            "remediation_summary": "Disable direct root login after validating sudo access.",
            "remediation_commands": [],
            "verification_commands": [],
            "service_restart": True,
        }
    )
    assert (
        client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=payload,
        ).status_code
        == 202
    )
    headers = {"Authorization": f"Bearer {login(client)}"}
    finding = client.get("/api/v1/findings", headers=headers).json()[0]

    created = client.post(
        "/api/v1/remediation-plans",
        headers=headers,
        json={"finding_id": finding["id"]},
    )
    assert created.status_code == 201, created.text
    plan = created.json()
    assert plan["action_catalog_status"] == "matched"
    assert plan["action"]["action_id"] == "linux.ssh.permit-root-login.disabled"
    assert plan["action"]["version"] == 1
    assert len(plan["action"]["digest"]) == 64
    assert plan["action"]["execution_enabled"] is False
    assert any(condition["kind"] == "manual_confirmation" for condition in plan["action"]["preconditions"])

    with SessionLocal() as db:
        stored = db.get(RemediationPlan, plan["id"])
        assert stored is not None
        assert stored.action_id == plan["action"]["action_id"]
        assert stored.action_version == plan["action"]["version"]
        assert stored.action_digest == plan["action"]["digest"]
        assert stored.action_snapshot == plan["action"]

    approved = client.post(f"/api/v1/remediation-plans/{plan['id']}/approve", headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["action"]["digest"] == plan["action"]["digest"]


def test_remediation_plan_marks_cataloged_action_unsupported_for_host_os(client):
    payload = report_payload()
    payload["host"]["os_version"] = "14"
    payload["findings"][0]["control_id"] = "CIS-DEBIAN13-5.1.21"
    assert (
        client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=payload,
        ).status_code
        == 202
    )
    headers = {"Authorization": f"Bearer {login(client)}"}
    finding = client.get("/api/v1/findings", headers=headers).json()[0]

    created = client.post(
        "/api/v1/remediation-plans",
        headers=headers,
        json={"finding_id": finding["id"]},
    )
    assert created.status_code == 201, created.text
    assert created.json()["action_catalog_status"] == "unsupported_system"
    assert created.json()["action"] is None


def test_legacy_validation_receipt_signature_shape_remains_verifiable():
    key = Ed25519PrivateKey.generate()
    public_key = b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    receipt = {
        "schema_version": "1.0",
        "kind": "remediation-validation-receipt",
        "validation_id": "validation-legacy",
        "change_set_id": "change-set-legacy",
        "contract_digest": "a" * 64,
        "agent_id": "agent-legacy",
        "host_id": "host-legacy",
        "status": "blocked",
        "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
        "changes_applied": False,
        "agent_version": "0.8.0",
        "agent_integrity_digest": f"sha256:{'b' * 64}",
        "action_results": [],
        "error": "Legacy preflight was blocked",
    }
    signature = b64encode(
        key.sign(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    ).decode()
    submission = RemediationValidationReceiptSubmission.model_validate(
        {"receipt": receipt, "signature": signature}
    )
    preserved = submission.receipt.model_dump(mode="json", exclude_unset=True)

    assert "recovery_plan" not in preserved
    assert verify_validation_receipt(public_key, preserved, signature) is True


def test_signed_change_set_requires_readiness_and_four_eyes(client):
    change_agent_private_key = Ed25519PrivateKey.generate()
    change_agent_public_key = change_agent_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = report_payload()
    payload["findings"][0].update(
        {
            "control_id": "CIS-DEBIAN13-5.1.21",
            "module": "cis_debian13",
            "category": "ssh",
            "title": "Ensure sshd PermitRootLogin is disabled",
            "severity": "high",
            "expected": "permitrootlogin is no",
            "actual": "permitrootlogin yes",
            "remediation_summary": "Disable direct root login after validating sudo access.",
            "remediation_commands": [],
            "verification_commands": [],
            "service_restart": True,
        }
    )
    assert (
        client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=payload,
        ).status_code
        == 202
    )
    owner_headers = {"Authorization": f"Bearer {login(client)}"}
    finding = client.get("/api/v1/findings", headers=owner_headers).json()[0]
    plan = client.post(
        "/api/v1/remediation-plans",
        headers=owner_headers,
        json={"finding_id": finding["id"]},
    ).json()
    approved = client.post(
        f"/api/v1/remediation-plans/{plan['id']}/approve",
        headers=owner_headers,
    )
    assert approved.status_code == 200, approved.text

    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "default"))
        host = db.get(Host, payload["host"]["host_id"])
        policy = db.scalar(
            select(AgentPolicy).where(
                AgentPolicy.tenant_id == tenant.id,
                AgentPolicy.name == "Remediation (Approval Required)",
            )
        )
        group = db.scalar(select(AgentGroup).where(AgentGroup.tenant_id == tenant.id))
        group.policy_id = policy.id
        ingestion_token = IngestionToken(
            tenant_id=tenant.id,
            host_id=host.id,
            name="Change-set test agent",
            token_prefix="lsa_test_change",
            token_hash=hash_ingestion_token("lsa-change-set-test-token"),
        )
        signing_key = SigningKey(
            tenant_id=tenant.id,
            host_id=host.id,
            name="Change-set test agent",
            public_key=b64encode(change_agent_public_key).decode(),
            fingerprint=hashlib.sha256(change_agent_public_key).hexdigest(),
        )
        reviewer = User(
            tenant_id=tenant.id,
            email="reviewer@lsa.local",
            display_name="Independent Reviewer",
            password_hash=hash_password("reviewer-password"),
            role="admin",
        )
        db.add_all([ingestion_token, signing_key, reviewer])
        db.flush()
        platform_key, _ = active_platform_command_key(db, tenant.id)
        db.add(
            LinuxAgent(
                tenant_id=tenant.id,
                host_id=host.id,
                group_id=group.id,
                ingestion_token_id=ingestion_token.id,
                signing_key_id=signing_key.id,
                name=host.hostname,
                public_key=signing_key.public_key,
                fingerprint=signing_key.fingerprint,
                agent_version="0.10.0",
                capabilities=[
                    "audit",
                    "signed-change-set-planning-v1",
                    "remediation-contract-validation-v1",
                    "remediation-dry-run-v1",
                    "remediation-recovery-planning-v1",
                    "remediation-checkpoint-v1",
                    "signed-platform-control-v1",
                ],
                capabilities_attested_at=now_utc(),
                last_seen_at=now_utc(),
                platform_command_key_id=platform_key.id,
                platform_command_key_fingerprint=platform_key.fingerprint,
            )
        )
        db.commit()

    window_start = datetime.now(UTC) + timedelta(hours=1)
    created = client.post(
        "/api/v1/remediation-change-sets",
        headers=owner_headers,
        json={
            "plan_ids": [plan["id"]],
            "canary_host_ids": [plan["host_id"]],
            "maintenance_window_start": window_start.isoformat(),
            "maintenance_window_end": (window_start + timedelta(hours=2)).isoformat(),
            "batch_size": 1,
            "batch_interval_minutes": 15,
        },
    )
    assert created.status_code == 201, created.text
    change_set = created.json()
    assert change_set["status"] == "pending_authorization"
    assert change_set["execution_enabled"] is False
    assert change_set["signature"] is None
    assert change_set["targets"][0]["rollout_phase"] == "canary"
    assert change_set["targets"][0]["capability_attested"] is True
    pending_preview = client.get(
        f"/api/v1/remediation-change-sets/{change_set['id']}"
        f"/execution-contract-preview/{change_set['targets'][0]['agent_id']}",
        headers=owner_headers,
    )
    assert pending_preview.status_code == 409
    assert {gate["code"]: gate["status"] for gate in change_set["gates"]} == {
        "action_integrity": "passed",
        "evidence_freshness": "passed",
        "policy_authorization": "passed",
        "agent_attestation": "passed",
        "canary_scope": "passed",
        "rate_limit": "passed",
        "maintenance_window": "passed",
        "rollback_checkpoint": "passed",
        "four_eyes": "blocked",
    }

    with SessionLocal() as db:
        agent = db.scalar(select(LinuxAgent).where(LinuxAgent.host_id == plan["host_id"]))
        agent.capabilities_attested_at = now_utc() - timedelta(hours=1)
        agent.last_seen_at = agent.capabilities_attested_at
        agent_id = agent.id
        db.commit()
    policy_path = "/api/v1/agent/policy"
    timestamp = str(int(datetime.now(UTC).timestamp()))
    policy_message = f"GET\n{policy_path}\n{timestamp}\n{hashlib.sha256(b'').hexdigest()}".encode()
    assert client.get(
        policy_path,
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(policy_message)
            ).decode(),
        },
    ).status_code == 200
    after_poll = client.get(
        f"/api/v1/remediation-change-sets/{change_set['id']}", headers=owner_headers
    ).json()
    assert next(
        gate for gate in after_poll["gates"] if gate["code"] == "agent_attestation"
    )["status"] == "blocked"

    heartbeat_body = json.dumps(
        {
            "agent_version": "0.10.0",
            "capabilities": [
                "audit",
                "signed-change-set-planning-v1",
                "remediation-contract-validation-v1",
                "remediation-dry-run-v1",
                "remediation-recovery-planning-v1",
                "remediation-checkpoint-v1",
                "signed-platform-control-v1",
            ],
            "policy_version": 1,
        },
        separators=(",", ":"),
    ).encode()
    heartbeat_path = "/api/v1/agent/heartbeat"
    timestamp = str(int(datetime.now(UTC).timestamp()))
    heartbeat_message = (
        f"POST\n{heartbeat_path}\n{timestamp}\n{hashlib.sha256(heartbeat_body).hexdigest()}"
    ).encode()
    assert client.post(
        heartbeat_path,
        content=heartbeat_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(heartbeat_message)
            ).decode(),
        },
    ).status_code == 200
    same_actor = client.post(
        f"/api/v1/remediation-change-sets/{change_set['id']}/authorize",
        headers=owner_headers,
    )
    assert same_actor.status_code == 409

    with SessionLocal() as db:
        stored = db.get(RemediationChangeSet, change_set["id"])
        stored.batch_size = 2
        db.commit()

    reviewer_login = client.post(
        "/api/v1/auth/login",
        json={"email": "reviewer@lsa.local", "password": "reviewer-password"},
    )
    reviewer_headers = {"Authorization": f"Bearer {reviewer_login.json()['access_token']}"}
    drifted = client.post(
        f"/api/v1/remediation-change-sets/{change_set['id']}/authorize",
        headers=reviewer_headers,
    )
    assert drifted.status_code == 409
    assert "operational columns do not match" in drifted.json()["detail"]
    with SessionLocal() as db:
        stored = db.get(RemediationChangeSet, change_set["id"])
        stored.batch_size = 1
        db.commit()

    past_payload = json.loads(json.dumps(change_set["payload"]))
    past_start = datetime.now(UTC) - timedelta(minutes=5)
    past_end = datetime.now(UTC) + timedelta(hours=1)
    past_payload["maintenance_window"] = {
        "start": past_start.isoformat(),
        "end": past_end.isoformat(),
    }
    with SessionLocal() as db:
        stored = db.get(RemediationChangeSet, change_set["id"])
        stored.payload = past_payload
        stored.digest = hashlib.sha256(
            json.dumps(past_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        stored.maintenance_window_start = past_start
        stored.maintenance_window_end = past_end
        db.commit()
    started_window = client.post(
        f"/api/v1/remediation-change-sets/{change_set['id']}/authorize",
        headers=reviewer_headers,
    )
    assert started_window.status_code == 409
    assert "maintenance window" in started_window.json()["detail"]
    with SessionLocal() as db:
        stored = db.get(RemediationChangeSet, change_set["id"])
        stored.payload = change_set["payload"]
        stored.digest = change_set["digest"]
        stored.maintenance_window_start = datetime.fromisoformat(
            change_set["maintenance_window_start"]
        )
        stored.maintenance_window_end = datetime.fromisoformat(change_set["maintenance_window_end"])
        db.commit()
    authorized = client.post(
        f"/api/v1/remediation-change-sets/{change_set['id']}/authorize",
        headers=reviewer_headers,
    )
    assert authorized.status_code == 200, authorized.text
    signed = authorized.json()
    assert signed["status"] == "authorized"
    assert signed["authorized_by_name"] == "Independent Reviewer"
    assert len(signed["digest"]) == 64
    assert signed["signature"]
    assert signed["signing_key_fingerprint"]
    assert all(gate["status"] == "passed" for gate in signed["gates"])
    canonical_payload = json.dumps(
        signed["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert hashlib.sha256(canonical_payload).hexdigest() == signed["digest"]
    Ed25519PublicKey.from_public_bytes(b64decode(signed["signing_public_key"])).verify(
        b64decode(signed["signature"]), canonical_payload
    )
    preview = client.get(
        f"/api/v1/remediation-change-sets/{change_set['id']}"
        f"/execution-contract-preview/{agent_id}",
        headers=reviewer_headers,
    )
    assert preview.status_code == 200, preview.text
    contract = preview.json()
    assert contract["mode"] == "validate_only"
    assert contract["execution_enabled"] is False
    assert contract["dispatch_enabled"] is False
    assert contract["target"] in contract["change_set"]["payload"]["targets"]
    assert len(contract["actions"]) == 1
    assert contract["actions"][0]["action_digest"] == signed["payload"]["plans"][0][
        "action_digest"
    ]
    with SessionLocal() as db:
        agent = db.get(LinuxAgent, agent_id)
        platform_key = db.get(PlatformCommandSigningKey, agent.platform_command_key_id)
    endorsement_bytes = json.dumps(
        contract["platform_endorsement"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    Ed25519PublicKey.from_public_bytes(b64decode(platform_key.public_key)).verify(
        b64decode(contract["platform_endorsement_signature"]), endorsement_bytes
    )
    queued_validation = client.post(
        f"/api/v1/remediation-change-sets/{change_set['id']}/validation-jobs",
        headers=reviewer_headers,
        json={"agent_id": agent_id},
    )
    assert queued_validation.status_code == 202, queued_validation.text
    validation_job = queued_validation.json()
    assert validation_job["status"] == "queued"
    assert validation_job["execution_enabled"] is False
    assert validation_job["changes_applied"] is False
    assert validation_job["contract"] == contract

    validation_path = "/api/v1/agent/remediation-validations/next"
    timestamp = str(int(datetime.now(UTC).timestamp()))
    validation_message = (
        f"GET\n{validation_path}\n{timestamp}\n{hashlib.sha256(b'').hexdigest()}"
    ).encode()
    delivered = client.get(
        validation_path,
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(validation_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert delivered.status_code == 200, delivered.text
    delivered_payload = delivered.json()["platform_envelope"]["payload"]["validation"]
    assert delivered_payload["validation_id"] == validation_job["id"]
    assert delivered_payload["contract_digest"] == validation_job["contract_digest"]
    assert delivered_payload["contract"] == contract

    recovery_operation = contract["actions"][0]["action_snapshot"]["operations"][0]
    recovery_identity = {
        "action_digest": contract["actions"][0]["action_digest"],
        "operation_index": 0,
        "path": recovery_operation["path"],
        "plan_id": contract["actions"][0]["plan_id"],
        "rollback_index": 0,
    }
    checkpoint_id = hashlib.sha256(
        json.dumps(recovery_identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    recovery_plan = {
        "schema_version": "1.0",
        "kind": "remediation-recovery-plan",
        "status": "ready",
        "backup_before_write": True,
        "automatic_rollback_required": True,
        "stop_on_failure": True,
        "journal_state": "planned",
        "entries": [
            {
                "checkpoint_id": checkpoint_id,
                **recovery_identity,
                "source_state": "absent",
                "source_digest": None,
                "size_bytes": None,
                "mode": None,
                "uid": None,
                "gid": None,
                "status": "ready",
                "detail": "The reviewed path is absent and can be restored by removal",
                "backup_created": False,
            }
        ],
        "rollback_order": [checkpoint_id],
        "execution_enabled": False,
        "changes_applied": False,
    }
    receipt = {
        "schema_version": "1.0",
        "kind": "remediation-validation-receipt",
        "validation_id": validation_job["id"],
        "change_set_id": change_set["id"],
        "contract_digest": validation_job["contract_digest"],
        "agent_id": agent_id,
        "host_id": plan["host_id"],
        "status": "ready",
        "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
        "changes_applied": False,
        "agent_version": "0.10.0",
        "agent_integrity_digest": f"sha256:{'a' * 64}",
        "action_results": [
            {
                "plan_id": item["plan_id"],
                "action_digest": item["action_digest"],
                "status": "ready",
                "checks": [
                    {
                        "code": "test_read_only_preflight",
                        "status": "passed",
                        "detail": "Read-only preflight completed without applying changes",
                    }
                ],
            }
            for item in contract["actions"]
        ],
        "recovery_plan": recovery_plan,
        "error": None,
    }
    receipt_signature = b64encode(
        change_agent_private_key.sign(
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        )
    ).decode()
    receipt_path = (
        f"/api/v1/agent/remediation-validations/{validation_job['id']}/receipt"
    )
    rejected_body = json.dumps(
        {"receipt": receipt, "signature": b64encode(b"0" * 64).decode()},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    rejected_message = (
        f"POST\n{receipt_path}\n{timestamp}\n{hashlib.sha256(rejected_body).hexdigest()}"
    ).encode()
    rejected_receipt = client.post(
        receipt_path,
        content=rejected_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(rejected_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert rejected_receipt.status_code == 409
    tampered_receipt = json.loads(json.dumps(receipt))
    tampered_receipt["recovery_plan"]["rollback_order"] = []
    tampered_signature = b64encode(
        change_agent_private_key.sign(
            json.dumps(
                tampered_receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        )
    ).decode()
    tampered_body = json.dumps(
        {"receipt": tampered_receipt, "signature": tampered_signature},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    tampered_message = (
        f"POST\n{receipt_path}\n{timestamp}\n{hashlib.sha256(tampered_body).hexdigest()}"
    ).encode()
    tampered_response = client.post(
        receipt_path,
        content=tampered_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(tampered_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert tampered_response.status_code == 409
    assert tampered_response.json()["detail"] == "Recovery plan binding is invalid"
    receipt_body = json.dumps(
        {"receipt": receipt, "signature": receipt_signature},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    receipt_message = (
        f"POST\n{receipt_path}\n{timestamp}\n{hashlib.sha256(receipt_body).hexdigest()}"
    ).encode()
    accepted_receipt = client.post(
        receipt_path,
        content=receipt_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(receipt_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert accepted_receipt.status_code == 200, accepted_receipt.text
    receipt_payload = accepted_receipt.json()["platform_envelope"]["payload"]
    assert receipt_payload["accepted"] is True
    assert receipt_payload["status"] == "ready"
    stored_validations = client.get(
        f"/api/v1/remediation-change-sets/{change_set['id']}/validation-jobs",
        headers=reviewer_headers,
    )
    assert stored_validations.status_code == 200
    assert stored_validations.json()[0]["receipt"] == receipt
    assert stored_validations.json()[0]["receipt_signature"] == receipt_signature
    queued_checkpoint = client.post(
        f"/api/v1/remediation-change-sets/{change_set['id']}/checkpoint-jobs",
        headers=reviewer_headers,
        json={"validation_job_id": validation_job["id"]},
    )
    assert queued_checkpoint.status_code == 202, queued_checkpoint.text
    checkpoint_job = queued_checkpoint.json()
    assert checkpoint_job["status"] == "queued"
    assert checkpoint_job["execution_enabled"] is False
    checkpoint_path = "/api/v1/agent/remediation-checkpoints/next"
    timestamp = str(int(datetime.now(UTC).timestamp()))
    checkpoint_message = (
        f"GET\n{checkpoint_path}\n{timestamp}\n{hashlib.sha256(b'').hexdigest()}"
    ).encode()
    checkpoint_delivery = client.get(
        checkpoint_path,
        headers={
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(checkpoint_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert checkpoint_delivery.status_code == 200, checkpoint_delivery.text
    checkpoint_payload = checkpoint_delivery.json()["platform_envelope"]["payload"]["checkpoint"]
    assert checkpoint_payload["checkpoint_job_id"] == checkpoint_job["id"]
    assert checkpoint_payload["recovery_plan"] == recovery_plan
    checkpoint_receipt = {
        "schema_version": "1.0",
        "kind": "remediation-checkpoint-receipt",
        "checkpoint_job_id": checkpoint_job["id"],
        "validation_id": validation_job["id"],
        "change_set_id": change_set["id"],
        "contract_digest": validation_job["contract_digest"],
        "agent_id": agent_id,
        "host_id": plan["host_id"],
        "status": "ready",
        "journal_state": "checkpointed",
        "journal_digest": "0" * 64,
        "storage_scope": "agent_local_encrypted",
        "encryption": "AES-256-GCM",
        "prepared_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "agent_version": "0.10.0",
        "agent_integrity_digest": f"sha256:{'a' * 64}",
        "checkpoint_results": [
            {
                "checkpoint_id": checkpoint_id,
                "source_state": "absent",
                "status": "ready",
                "backup_created": False,
                "encrypted_blob_digest": None,
                "encrypted_size_bytes": None,
                "error": None,
            }
        ],
        "error": None,
        "execution_enabled": False,
        "changes_applied": False,
    }
    checkpoint_receipt["journal_digest"] = checkpoint_journal_digest(
        checkpoint_job_id=checkpoint_job["id"],
        validation_id=validation_job["id"],
        contract_digest=validation_job["contract_digest"],
        recovery_plan=recovery_plan,
        state="checkpointed",
        checkpoint_results=checkpoint_receipt["checkpoint_results"],
        error=None,
    )
    checkpoint_signature = b64encode(
        change_agent_private_key.sign(
            json.dumps(
                checkpoint_receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        )
    ).decode()
    checkpoint_receipt_path = (
        f"/api/v1/agent/remediation-checkpoints/{checkpoint_job['id']}/receipt"
    )
    invalid_journal_receipt = {**checkpoint_receipt, "journal_digest": "0" * 64}
    invalid_journal_signature = b64encode(
        change_agent_private_key.sign(
            json.dumps(
                invalid_journal_receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        )
    ).decode()
    invalid_journal_body = json.dumps(
        {"receipt": invalid_journal_receipt, "signature": invalid_journal_signature},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    invalid_journal_message = (
        f"POST\n{checkpoint_receipt_path}\n{timestamp}\n"
        f"{hashlib.sha256(invalid_journal_body).hexdigest()}"
    ).encode()
    invalid_journal_response = client.post(
        checkpoint_receipt_path,
        content=invalid_journal_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(invalid_journal_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert invalid_journal_response.status_code == 409
    assert invalid_journal_response.json()["detail"] == "Checkpoint journal digest is invalid"
    checkpoint_body = json.dumps(
        {"receipt": checkpoint_receipt, "signature": checkpoint_signature},
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(datetime.now(UTC).timestamp()))
    checkpoint_receipt_message = (
        f"POST\n{checkpoint_receipt_path}\n{timestamp}\n"
        f"{hashlib.sha256(checkpoint_body).hexdigest()}"
    ).encode()
    accepted_checkpoint = client.post(
        checkpoint_receipt_path,
        content=checkpoint_body,
        headers={
            "Content-Type": "application/json",
            "X-LSA-Agent-ID": agent_id,
            "X-LSA-Agent-Timestamp": timestamp,
            "X-LSA-Agent-Signature": b64encode(
                change_agent_private_key.sign(checkpoint_receipt_message)
            ).decode(),
            "X-LSA-Platform-Control": "signed-v1",
        },
    )
    assert accepted_checkpoint.status_code == 200, accepted_checkpoint.text
    stored_checkpoints = client.get(
        f"/api/v1/remediation-change-sets/{change_set['id']}/checkpoint-jobs",
        headers=reviewer_headers,
    )
    assert stored_checkpoints.status_code == 200
    assert stored_checkpoints.json()[0]["status"] == "ready"
    assert stored_checkpoints.json()[0]["receipt"] == checkpoint_receipt
    with SessionLocal() as db:
        assert db.scalar(select(AgentTask)) is None
        events = db.scalars(select(AuditEvent).where(AuditEvent.target_id == change_set["id"])).all()
        assert {event.action for event in events} == {
            "remediation_change_set.requested",
            "remediation_change_set.authorized",
        }
        db.get(Host, plan["host_id"]).hostname = "renamed-after-signing"
        group = db.scalar(select(AgentGroup).where(AgentGroup.tenant_id == tenant.id))
        policy = db.get(AgentPolicy, group.policy_id)
        group.name = "Renamed Group"
        policy.name = "Renamed Policy"
        db.commit()
    retained_snapshot = client.get(
        f"/api/v1/remediation-change-sets/{change_set['id']}", headers=reviewer_headers
    ).json()
    assert retained_snapshot["targets"][0]["hostname"] == payload["host"]["hostname"]
    assert retained_snapshot["targets"][0]["group_name"] != "Renamed Group"
    assert retained_snapshot["targets"][0]["policy_name"] != "Renamed Policy"



def test_change_set_authorization_blocks_missing_agent_capability(client):
    payload = report_payload()
    payload["findings"][0]["control_id"] = "CIS-DEBIAN13-5.1.21"
    assert (
        client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=payload,
        ).status_code
        == 202
    )
    headers = {"Authorization": f"Bearer {login(client)}"}
    finding = client.get("/api/v1/findings", headers=headers).json()[0]
    plan = client.post("/api/v1/remediation-plans", headers=headers, json={"finding_id": finding["id"]}).json()
    assert client.post(f"/api/v1/remediation-plans/{plan['id']}/approve", headers=headers).status_code == 200

    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "default"))
        policy = db.scalar(select(AgentPolicy).where(AgentPolicy.name == "Remediation (Approval Required)"))
        group = db.scalar(select(AgentGroup).where(AgentGroup.tenant_id == tenant.id))
        group.policy_id = policy.id
        token = IngestionToken(
            tenant_id=tenant.id,
            host_id=plan["host_id"],
            name="Audit-only test agent",
            token_prefix="lsa_audit_only",
            token_hash=hash_ingestion_token("lsa-audit-only-test-token"),
        )
        key = SigningKey(
            tenant_id=tenant.id,
            host_id=plan["host_id"],
            name="Audit-only test agent",
            public_key=b64encode(b"b" * 32).decode(),
            fingerprint=hashlib.sha256(b"b" * 32).hexdigest(),
        )
        db.add_all([token, key])
        db.flush()
        db.add(
            LinuxAgent(
                tenant_id=tenant.id,
                host_id=plan["host_id"],
                group_id=group.id,
                ingestion_token_id=token.id,
                signing_key_id=key.id,
                name="audit-only",
                public_key=key.public_key,
                fingerprint=key.fingerprint,
                capabilities=["audit"],
                capabilities_attested_at=now_utc(),
                last_seen_at=now_utc(),
            )
        )
        db.commit()

    start = datetime.now(UTC) + timedelta(hours=1)
    created = client.post(
        "/api/v1/remediation-change-sets",
        headers=headers,
        json={
            "plan_ids": [plan["id"]],
            "canary_host_ids": [plan["host_id"]],
            "maintenance_window_start": start.isoformat(),
            "maintenance_window_end": (start + timedelta(hours=1)).isoformat(),
        },
    )
    assert created.status_code == 201, created.text
    gates = {gate["code"]: gate for gate in created.json()["gates"]}
    assert gates["agent_attestation"]["status"] == "blocked"


def test_application_inventory_tracks_versions_and_removals(client):
    first = report_payload()
    ingest_headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=first).status_code == 202

    second = report_payload()
    second["host"]["host_id"] = first["host"]["host_id"]
    second["host"]["machine_id_hash"] = first["host"]["machine_id_hash"]
    second["applications"] = [
        {
            **first["applications"][0],
            "version": "3.0.15-1",
            "source_version": "3.0.15-1",
            "purl": "pkg:deb/debian/openssl@3.0.15-1?arch=amd64&distro=debian-13",
        }
    ]
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=second).status_code == 202

    headers = {"Authorization": f"Bearer {login(client)}"}
    active = client.get(f"/api/v1/hosts/{first['host']['host_id']}/applications", headers=headers).json()
    assert [(item["name"], item["version"]) for item in active] == [("openssl", "3.0.15-1")]
    history = client.get(
        f"/api/v1/hosts/{first['host']['host_id']}/applications?include_removed=true",
        headers=headers,
    ).json()
    assert len(history) == 3
    assert len([item for item in history if item["removed_at"] is not None]) == 2


def test_application_estate_summary_and_host_correlation(client):
    first = report_payload()
    first["applications"][0]["source_package"] = "openssl-source"
    second = report_payload()
    second["host"]["hostname"] = "test-db-02"
    second["host"]["fqdn"] = "test-db-02.example.test"
    second["host"]["machine_id_hash"] = f"sha256:{hashlib.sha256(b'test-db-02').hexdigest()}"
    second["host"]["tags"] = {"environment": "production"}
    second["applications"][0]["version"] = "3.0.15-1"
    second["applications"][0]["source_package"] = "openssl-source"
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
    source_search = client.get("/api/v1/applications", params={"search": "openssl-source"}, headers=headers).json()
    assert [item["name"] for item in source_search["applications"]] == ["openssl"]

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


def test_data_workspaces_page_filter_sort_and_preserve_aggregate_facets(client):
    first = report_payload()
    second = report_payload()
    second["host"]["hostname"] = "critical-db-02"
    second["host"]["fqdn"] = "critical-db-02.example.test"
    second["host"]["machine_id_hash"] = f"sha256:{hashlib.sha256(b'critical-db-02').hexdigest()}"
    second["summary"]["security_score"] = 35
    second["findings"][0]["severity"] = "critical"
    second["findings"][0]["title"] = "Critical database hardening gap"
    ingest_headers = {"Authorization": f"Bearer {DEMO_TOKEN}"}
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=first).status_code == 202
    assert client.post("/api/v1/ingest/reports", headers=ingest_headers, json=second).status_code == 202
    headers = {"Authorization": f"Bearer {login(client)}"}

    hosts = client.get(
        "/api/v1/hosts",
        params={"page": 1, "page_size": 1, "sort": "asset", "direction": "desc"},
        headers=headers,
    )
    assert hosts.status_code == 200, hosts.text
    assert hosts.headers["X-Total-Count"] == "2"
    assert hosts.headers["X-Page"] == "1"
    assert len(hosts.json()) == 1
    critical_hosts = client.get(
        "/api/v1/hosts", params={"risk": "critical", "page": 1, "page_size": 10}, headers=headers
    )
    assert [item["hostname"] for item in critical_hosts.json()] == ["critical-db-02"]
    host_facets = client.get("/api/v1/hosts/facets", headers=headers).json()
    assert host_facets["total"] == 2
    assert host_facets["critical"] == 1

    category = first["findings"][0]["category"]
    findings = client.get(
        "/api/v1/findings",
        params={
            "category": category,
            "search": "database",
            "page": 1,
            "page_size": 1,
            "sort": "severity",
        },
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.headers["X-Total-Count"] == "1"
    assert findings.json()[0]["severity"] == "critical"
    finding_facets = client.get("/api/v1/findings/facets", headers=headers).json()
    category_facet = next(item for item in finding_facets["categories"] if item["category"] == category)
    assert finding_facets["total"] == 2
    assert finding_facets["critical"] == 1
    assert category_facet["count"] == 2
    assert category_facet["critical"] == 1
    detail = client.get(f"/api/v1/findings/{findings.json()[0]['id']}", headers=headers)
    assert detail.status_code == 200

    applications = client.get(
        "/api/v1/applications",
        params={"page": 1, "page_size": 1, "sort": "application", "direction": "asc"},
        headers=headers,
    )
    assert applications.status_code == 200, applications.text
    assert applications.headers["X-Total-Count"] == "2"
    assert len(applications.json()["applications"]) == 1
    assert applications.json()["metrics"]["unique_applications"] == 2


def test_offline_vulnerability_snapshot_correlates_packages_and_kev(client):
    payload = report_payload()
    assert (
        client.post(
            "/api/v1/ingest/reports",
            headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
            json=payload,
        ).status_code
        == 202
    )
    snapshot = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "packages": [
            {
                "purl": payload["applications"][0]["purl"],
                "vulnerabilities": [
                    {
                        "id": "DSA-9999-1",
                        "aliases": ["CVE-2026-1234"],
                        "summary": "OpenSSL memory safety issue",
                        "details": "A crafted input can cause memory corruption.",
                        "published": "2026-07-01T00:00:00Z",
                        "modified": "2026-08-01T00:00:00Z",
                        "database_specific": {"severity": "HIGH", "cvss_score": 8.1},
                        "affected": [
                            {
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "3.0.15-1"},
                                        ],
                                    }
                                ]
                            }
                        ],
                        "references": [{"type": "ADVISORY", "url": "https://example.test/DSA-9999-1"}],
                    },
                    {
                        "id": "GHSA-test-duplicate",
                        "aliases": ["CVE-2026-1234"],
                        "summary": "Duplicate upstream advisory for the same CVE",
                        "database_specific": {"severity": "HIGH"},
                        "references": [{"type": "WEB", "url": "javascript:alert(1)"}],
                    },
                ],
            }
        ],
        "kev_catalog": {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1234",
                    "vendorProject": "OpenSSL",
                    "product": "OpenSSL",
                    "dateAdded": "2026-08-02",
                    "dueDate": "2026-08-15",
                    "requiredAction": "Apply vendor updates.",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        },
    }
    headers = {"Authorization": f"Bearer {login(client)}"}
    imported = client.post(
        "/api/v1/vulnerabilities/import",
        headers=headers,
        files={"file": ("vulnerabilities.json", json.dumps(snapshot), "application/json")},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json() == {
        "packages_imported": 1,
        "vulnerabilities_found": 1,
        "matches_found": 1,
    }

    summary = client.get("/api/v1/vulnerabilities/summary", headers=headers).json()
    assert summary["vulnerability_count"] == 1
    assert summary["exposure_count"] == 1
    assert summary["affected_hosts"] == 1
    assert summary["known_exploited"] == 1
    assert summary["severity_counts"]["high"] == 1
    assert summary["last_sync"]["trigger"] == "offline"

    application_vulnerabilities = client.get(
        "/api/v1/applications/vulnerabilities",
        params={"name": "openssl", "kind": "package", "source": "dpkg"},
        headers=headers,
    ).json()
    assert application_vulnerabilities[0]["cve_id"] == "CVE-2026-1234"
    assert application_vulnerabilities[0]["known_exploited"] is True
    assert application_vulnerabilities[0]["fixed_versions"] == ["3.0.15-1"]
    assert set(application_vulnerabilities[0]["aliases"]) >= {
        "DSA-9999-1",
        "GHSA-test-duplicate",
        "CVE-2026-1234",
    }
    assert all(
        not reference.get("url", "").startswith("javascript:")
        for reference in application_vulnerabilities[0]["references"]
    )
    assert application_vulnerabilities[0]["affected_host_ids"] == [payload["host"]["host_id"]]
    estate = client.get("/api/v1/applications", headers=headers).json()
    openssl = next(item for item in estate["applications"] if item["name"] == "openssl")
    assert openssl["vulnerability_count"] == 1
    assert openssl["known_exploited_count"] == 1

    host_vulnerabilities = client.get(
        f"/api/v1/hosts/{payload['host']['host_id']}/vulnerabilities", headers=headers
    ).json()
    assert host_vulnerabilities[0]["application_name"] == "openssl"
    assert host_vulnerabilities[0]["installed_version"] == "3.0.14-1"
    assert host_vulnerabilities[0]["matched_purl"] == payload["applications"][0]["purl"]

    cleared = {
        **snapshot,
        "packages": [{"purl": payload["applications"][0]["purl"], "vulnerabilities": []}],
    }
    assert (
        client.post(
            "/api/v1/vulnerabilities/import",
            headers=headers,
            files={"file": ("cleared.json", json.dumps(cleared), "application/json")},
        ).status_code
        == 200
    )
    assert client.get("/api/v1/vulnerabilities/summary", headers=headers).json()["exposure_count"] == 0


def test_vulnerability_refresh_queue_is_idempotent(client):
    headers = {"Authorization": f"Bearer {login(client)}"}
    first = client.post("/api/v1/vulnerabilities/sync", headers=headers)
    second = client.post("/api/v1/vulnerabilities/sync", headers=headers)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["status"] == "queued"
    assert second.json()["id"] == first.json()["id"]


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
    applications = client.get(f"/api/v1/hosts/{first['host']['host_id']}/applications", headers=headers).json()
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
    assert client.delete(f"/api/v1/ingestion-tokens/{created['id']}", headers=headers).status_code == 204
    response = client.post(
        "/api/v1/ingest/reports",
        headers={"Authorization": f"Bearer {created['token']}"},
        json=report_payload(),
    )
    assert response.status_code == 401

    repeated = client.delete(f"/api/v1/ingestion-tokens/{created['id']}", headers=headers)
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
    history = client.get(f"/api/v1/hosts/{response.json()['host_id']}/reports", headers=session_headers).json()
    assert history[0]["artifact_available"] is True
    assert history[0]["artifact_size_bytes"] == bundle_path.stat().st_size
    download = client.get(
        f"/api/v1/reports/{response.json()['report_id']}/artifact",
        headers=session_headers,
    )
    assert download.status_code == 200
    assert download.content == bundle_path.read_bytes()
    assert download.headers["x-lsa-artifact-sha256"] == hashlib.sha256(download.content).hexdigest()


def test_bundle_schema_rejection_identifies_invalid_field_without_echoing_value(client, tmp_path: Path):
    payload = report_payload()
    invalid_name = "sensitive-package-name-" + ("x" * 300)
    payload["applications"][0]["name"] = invalid_name
    report_path = tmp_path / "invalid-report.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    bundle_path = build(report_path, tmp_path)

    response = client.post(
        "/api/v1/ingest/bundles",
        headers={"Authorization": f"Bearer {DEMO_TOKEN}"},
        files={"file": (bundle_path.name, bundle_path.read_bytes(), "application/zip")},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Invalid report.json"
    assert detail["errors"][0]["field"] == "applications.0.name"
    assert invalid_name not in response.text


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
    assert client.delete(f"/api/v1/reports/{report_id}/artifact", headers=session_headers).status_code == 204
    assert client.get(f"/api/v1/reports/{report_id}/artifact", headers=session_headers).status_code == 404


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
    assert client.get(f"/api/v1/reports/{report_id}/artifact", headers=session_headers).status_code == 404


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
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path, private_key_path, registered["id"])
    output = io.BytesIO()
    with zipfile.ZipFile(bundle_path) as source:
        files = {name: source.read(name) for name in source.namelist()}
    signature = bytearray(files["signature.sig"])
    signature[0] = ord("A") if signature[0] != ord("A") else ord("B")
    files["signature.sig"] = bytes(signature)
    checksum_lines = []
    for line in files["checksums.sha256"].decode().splitlines():
        digest, _, name = line.partition("  ")
        checksum_lines.append(
            f"{hashlib.sha256(files[name]).hexdigest() if name == 'signature.sig' else digest}  {name}\n"
        )
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
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path, private_key_path, registered["id"])
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
    bundle_path = build(Path("tests/fixtures/report.json"), tmp_path, private_key_path, registered["id"])
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
    history = client.get(f"/api/v1/hosts/{first['host']['host_id']}/reports", headers=session_headers)
    assert history.status_code == 200
    assert len(history.json()) == 2
    comparison = client.get(f"/api/v1/reports/{second['report_id']}/compare", headers=session_headers)
    assert comparison.status_code == 200
    assert [item["control_id"] for item in comparison.json()["new"]] == ["CIS-DEBIAN13-4.2.7"]
    assert [item["control_id"] for item in comparison.json()["resolved"]] == ["CIS-DEBIAN13-1.1.1"]
