"""Canonical signing for non-executable remediation change-set envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.fernet import InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.config import get_settings
from lsa.models import PlatformChangeSigningKey
from lsa.security import decrypt_secret, encrypt_secret


class ChangeSetSigningError(RuntimeError):
    pass


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def payload_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(payload)).hexdigest()


def _private_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def active_change_signing_key(
    db: Session,
    tenant_id: str,
) -> tuple[PlatformChangeSigningKey, bool]:
    stored = db.scalar(
        select(PlatformChangeSigningKey)
        .where(
            PlatformChangeSigningKey.tenant_id == tenant_id,
            PlatformChangeSigningKey.revoked_at.is_(None),
        )
        .order_by(PlatformChangeSigningKey.created_at.desc())
    )
    if stored is not None:
        return stored, False

    settings = get_settings()
    private_key = Ed25519PrivateKey.generate()
    public_raw = _public_bytes(private_key.public_key())
    private_encoded = base64.b64encode(_private_bytes(private_key)).decode()
    stored = PlatformChangeSigningKey(
        tenant_id=tenant_id,
        name="Remediation Change-Set Authority",
        public_key=base64.b64encode(public_raw).decode(),
        private_key_ciphertext=encrypt_secret(
            private_encoded,
            settings.session_secret,
            settings.settings_encryption_key,
        ),
        fingerprint=hashlib.sha256(public_raw).hexdigest(),
    )
    db.add(stored)
    db.flush()
    return stored, True


def sign_change_set(
    key: PlatformChangeSigningKey,
    payload: dict[str, Any],
) -> str:
    if key.revoked_at is not None:
        raise ChangeSetSigningError("Change-set signing key is revoked")
    settings = get_settings()
    try:
        private_encoded = decrypt_secret(
            key.private_key_ciphertext,
            settings.session_secret,
            settings.settings_encryption_key,
        )
        private_raw = base64.b64decode(private_encoded, validate=True)
        if len(private_raw) != 32:
            raise ValueError
        private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
    except (InvalidToken, TypeError, ValueError) as exc:
        raise ChangeSetSigningError("Change-set signing key cannot be decrypted") from exc
    return base64.b64encode(private_key.sign(canonical_payload(payload))).decode()


def verify_change_set_signature(
    public_key: str,
    payload: dict[str, Any],
    signature: str,
) -> bool:
    try:
        public_raw = base64.b64decode(public_key, validate=True)
        signature_raw = base64.b64decode(signature, validate=True)
        if len(public_raw) != 32 or len(signature_raw) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw,
            canonical_payload(payload),
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False
