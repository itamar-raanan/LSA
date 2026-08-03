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
    platform_url,
    signed_headers,
)


def test_runtime_version_matches_packaging_release():
    assert Path("agent/VERSION").read_text(encoding="utf-8").strip() == VERSION


def test_platform_requires_https_by_default():
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        platform_url({"platform_url": "http://lsa.example.test:8443"})


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
