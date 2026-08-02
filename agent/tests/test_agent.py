import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.lsa_agent import platform_url, signed_headers


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
