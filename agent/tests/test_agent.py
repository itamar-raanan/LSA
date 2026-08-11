import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.integrity import build_manifest, verify_manifest, write_manifest
from agent.lsa_agent import (
    AGENT_CAPABILITIES,
    VERSION,
    _scan_due,
    accept_policy_version,
    http_client,
    platform_url,
    run_scanner,
    signed_headers,
    verify_platform_envelope,
)


def test_runtime_version_matches_packaging_release():
    assert Path("agent/VERSION").read_text(encoding="utf-8").strip() == VERSION


def test_agent_attests_governance_planning_without_write_execution():
    assert "signed-change-set-planning-v1" in AGENT_CAPABILITIES
    assert all("execute" not in capability and "write" not in capability for capability in AGENT_CAPABILITIES)


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


def signed_platform_envelope(
    *,
    key: Ed25519PrivateKey | None = None,
    sequence: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    identity_fingerprint: str = "agent-fingerprint",
    execution_enabled: bool = False,
):
    key = key or Ed25519PrivateKey.generate()
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    current = datetime.now(UTC)
    envelope = {
        "schema_version": "1.0",
        "kind": "agent-enrollment",
        "key_id": "platform-key-1",
        "sequence": sequence,
        "issued_at": (issued_at or current).isoformat(),
        "expires_at": (expires_at or current + timedelta(minutes=5)).isoformat(),
        "agent_id": "agent-1",
        "payload": {
            "agent_id": "agent-1",
            "host_id": "host-1",
            "agent_identity_fingerprint": identity_fingerprint,
            "execution_enabled": execution_enabled,
        },
    }
    canonical = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    trust = {
        "key_id": "platform-key-1",
        "key_version": 1,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public_raw).decode(),
        "fingerprint": hashlib.sha256(public_raw).hexdigest(),
    }
    return envelope, base64.b64encode(key.sign(canonical)).decode(), trust, key.public_key(), public_raw


def test_platform_envelope_accepts_pinned_identity_and_records_sequence():
    envelope, signature, trust, key, raw = signed_platform_envelope()
    payload = verify_platform_envelope(
        envelope,
        signature,
        trust,
        key,
        raw,
        expected_kind="agent-enrollment",
        expected_identity_fingerprint="agent-fingerprint",
    )
    assert payload["platform_envelope_sequence"] == 1
    assert payload["platform_command_key_fingerprint"] == trust["fingerprint"]


def test_platform_envelope_rejects_a_different_pinned_platform_key():
    envelope, signature, trust, _, _ = signed_platform_envelope()
    other = Ed25519PrivateKey.generate()
    other_raw = other.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    with pytest.raises(RuntimeError, match="does not match the pinned key"):
        verify_platform_envelope(
            envelope,
            signature,
            trust,
            other.public_key(),
            other_raw,
            expected_kind="agent-enrollment",
            expected_identity_fingerprint="agent-fingerprint",
        )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("tamper", "signature is invalid"),
        ("expired", "expired"),
        ("future", "future"),
        ("replay", "replay or rollback"),
        ("identity", "another agent identity"),
        ("execution", "audit-only safety lock"),
    ],
)
def test_platform_envelope_rejects_untrusted_or_replayed_control_data(change, message):
    now = datetime.now(UTC)
    kwargs = {}
    state = None
    expected_identity = "agent-fingerprint"
    if change == "expired":
        kwargs = {"issued_at": now - timedelta(minutes=6), "expires_at": now - timedelta(minutes=1)}
    elif change == "future":
        kwargs = {"issued_at": now + timedelta(minutes=6), "expires_at": now + timedelta(minutes=9)}
    elif change == "replay":
        state = {"agent_id": "agent-1", "platform_envelope_sequence": 1}
    elif change == "identity":
        expected_identity = "different-agent"
    elif change == "execution":
        kwargs = {"execution_enabled": True}
    envelope, signature, trust, key, raw = signed_platform_envelope(**kwargs)
    if change == "tamper":
        envelope["payload"]["host_id"] = "attacker-host"
    with pytest.raises(RuntimeError, match=message):
        verify_platform_envelope(
            envelope,
            signature,
            trust,
            key,
            raw,
            expected_kind="agent-enrollment",
            expected_identity_fingerprint=expected_identity,
            state=state,
            now=now,
        )


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
