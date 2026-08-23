"""Canonical verification for agent-signed remediation validation receipts."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_receipt(receipt: dict[str, Any]) -> bytes:
    return json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def verify_validation_receipt(public_key: str, receipt: dict[str, Any], signature: str) -> bool:
    try:
        public_raw = base64.b64decode(public_key, validate=True)
        signature_raw = base64.b64decode(signature, validate=True)
        if len(public_raw) != 32 or len(signature_raw) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw,
            canonical_receipt(receipt),
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False
