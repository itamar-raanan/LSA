import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.integrity import build_manifest, verify_manifest, write_manifest
from agent.lsa_agent import (
    VERSION,
    _scan_due,
    accept_policy_version,
    http_client,
    platform_url,
    run_scanner,
    signed_headers,
)


def test_runtime_version_matches_packaging_release():
    assert Path("agent/VERSION").read_text(encoding="utf-8").strip() == VERSION


def test_platform_requires_https_by_default():
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        platform_url({"platform_url": "http://lsa.example.test:8444"})


def test_agent_http_client_disables_server_certificate_verification(monkeypatch):
    captured = {}

    class Client:
        pass

    def client_factory(**kwargs):
        captured.update(kwargs)
        return Client()

    monkeypatch.setattr("agent.lsa_agent.httpx.Client", client_factory)

    assert isinstance(
        http_client(
            {
                "platform_url": "https://lsa.example.test:8444",
                "ca_bundle": "/path/from/an/older/config.crt",
            }
        ),
        Client,
    )
    assert captured["verify"] is False


def test_agent_request_signature_covers_method_path_timestamp_and_body():
    key = Ed25519PrivateKey.generate()
    body = b'{"agent_version":"0.1.0"}'
    headers = signed_headers(key, "agent-id", "POST", "/api/v1/agent/heartbeat", body)
    message = (
        "POST\n/api/v1/agent/heartbeat\n"
        f"{headers['X-LSA-Agent-Timestamp']}\n{hashlib.sha256(body).hexdigest()}"
    ).encode()
    key.public_key().verify(base64.b64decode(headers["X-LSA-Agent-Signature"]), message)


def test_scan_schedule_treats_missing_and_expired_deadlines_as_due():
    assert _scan_due({}) is True
    assert _scan_due({"next_scan_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}) is True
    assert _scan_due({"next_scan_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()}) is False


def test_policy_version_cannot_roll_back():
    state = {"policy_version": 3, "highest_policy_version": 3}
    assert accept_policy_version(state, {"policy_version": 4}) == 4
    assert state["highest_policy_version"] == 4
    with pytest.raises(RuntimeError, match="policy rollback rejected"):
        accept_policy_version(state, {"policy_version": 3})


def test_scanner_uses_writable_ansible_runtime_paths_under_agent_state(tmp_path, monkeypatch):
    scanner_dir = tmp_path / "scanner"
    (scanner_dir / "playbooks").mkdir(parents=True)
    (scanner_dir / "playbooks" / "scan.yml").write_text("---\n", encoding="utf-8")
    (scanner_dir / "ansible.cfg").write_text("[defaults]\n", encoding="utf-8")
    state_dir = tmp_path / "state"
    key_path = tmp_path / "agent-signing-key.pem"

    def fake_run(command, *, cwd, env, check):
        assert cwd == scanner_dir
        assert check is True
        assert command[0] == "/opt/lsa-agent/venv/bin/ansible-playbook"
        assert env["ANSIBLE_CONFIG"] == str(scanner_dir / "ansible.cfg")

        runtime_paths = (
            env["ANSIBLE_HOME"],
            env["ANSIBLE_LOCAL_TEMP"],
            env["ANSIBLE_REMOTE_TEMP"],
            env["ANSIBLE_REMOTE_TMP"],
        )
        assert env["ANSIBLE_REMOTE_TEMP"] == env["ANSIBLE_REMOTE_TMP"]
        for value in runtime_paths:
            path = Path(value)
            assert path.is_relative_to(state_dir)
            assert path.is_dir()
            assert path.stat().st_mode & 0o777 == 0o700

    monkeypatch.setattr("agent.lsa_agent.subprocess.run", fake_run)
    run_scanner(
        {
            "scanner_dir": str(scanner_dir),
            "state_dir": str(state_dir),
            "platform_url": "https://lsa.example.test:8444",
            "ansible_playbook": "/opt/lsa-agent/venv/bin/ansible-playbook",
        },
        {
            "host_id": "host-id",
            "ingestion_token": "ingestion-token",
            "signing_key_id": "signing-key-id",
        },
        key_path,
        {"enforcement_enabled": False, "settings": {}, "default_mode": "audit"},
    )


def test_runtime_manifest_detects_modified_managed_file(tmp_path):
    (tmp_path / "agent").mkdir()
    (tmp_path / "scanner").mkdir()
    runtime = tmp_path / "agent" / "runtime.py"
    runtime.write_text("safe = True\n", encoding="utf-8")
    (tmp_path / "scanner" / "control.yml").write_text("id: example\n", encoding="utf-8")
    manifest = tmp_path / "integrity-manifest.json"
    write_manifest(tmp_path, manifest)

    assert build_manifest(tmp_path)["files"]
    assert len(verify_manifest(tmp_path, manifest)) == 64
    runtime.write_text("safe = False\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="digest mismatch: agent/runtime.py"):
        verify_manifest(tmp_path, manifest)
