import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.lsa_agent import _scan_due, platform_url, signed_headers


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
