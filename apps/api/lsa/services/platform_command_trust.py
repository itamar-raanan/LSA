"""Tenant-scoped platform identity used to authenticate agent control envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from lsa.config import get_settings
from lsa.models import PlatformCommandSigningKey
from lsa.security import decrypt_secret, encrypt_secret


class PlatformCommandSigningError(RuntimeError):
    pass


def canonical_envelope(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def active_platform_command_key(
    db: Session, tenant_id: str
) -> tuple[PlatformCommandSigningKey, bool]:
    stored = db.scalar(
        select(PlatformCommandSigningKey)
        .where(
            PlatformCommandSigningKey.tenant_id == tenant_id,
            PlatformCommandSigningKey.revoked_at.is_(None),
            PlatformCommandSigningKey.status == "active",
        )
        .order_by(PlatformCommandSigningKey.key_version.desc())
    )
    if stored is not None:
        return stored, False

    latest_version = db.scalar(
        select(func.max(PlatformCommandSigningKey.key_version)).where(
            PlatformCommandSigningKey.tenant_id == tenant_id
        )
    )
    private_key = Ed25519PrivateKey.generate()
    public_raw = _public_bytes(private_key.public_key())
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    settings = get_settings()
    stored = PlatformCommandSigningKey(
        tenant_id=tenant_id,
        name="Platform Command Authority",
        key_version=(latest_version or 0) + 1,
        public_key=base64.b64encode(public_raw).decode(),
        private_key_ciphertext=encrypt_secret(
            base64.b64encode(private_raw).decode(),
            settings.session_secret,
            settings.settings_encryption_key,
        ),
        fingerprint=hashlib.sha256(public_raw).hexdigest(),
        status="active",
        activated_at=func.now(),
    )
    db.add(stored)
    db.flush()
    return stored, True


def create_staged_platform_command_key(
    db: Session, tenant_id: str, active_key: PlatformCommandSigningKey
) -> PlatformCommandSigningKey:
    existing = db.scalar(
        select(PlatformCommandSigningKey).where(
            PlatformCommandSigningKey.tenant_id == tenant_id,
            PlatformCommandSigningKey.status == "staged",
            PlatformCommandSigningKey.revoked_at.is_(None),
        )
    )
    if existing is not None:
        raise PlatformCommandSigningError("A platform command key rotation is already staged")
    latest_version = db.scalar(
        select(func.max(PlatformCommandSigningKey.key_version)).where(
            PlatformCommandSigningKey.tenant_id == tenant_id
        )
    )
    private_key = Ed25519PrivateKey.generate()
    public_raw = _public_bytes(private_key.public_key())
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    settings = get_settings()
    staged = PlatformCommandSigningKey(
        tenant_id=tenant_id,
        name="Platform Command Authority",
        key_version=(latest_version or 0) + 1,
        public_key=base64.b64encode(public_raw).decode(),
        private_key_ciphertext=encrypt_secret(
            base64.b64encode(private_raw).decode(),
            settings.session_secret,
            settings.settings_encryption_key,
        ),
        fingerprint=hashlib.sha256(public_raw).hexdigest(),
        status="staged",
        supersedes_key_id=active_key.id,
    )
    db.add(staged)
    db.flush()
    return staged


def platform_key_rotation_proof(
    active_key: PlatformCommandSigningKey, staged_key: PlatformCommandSigningKey
) -> dict[str, Any]:
    proposal = {
        "schema_version": "1.0",
        "kind": "platform-key-rotation",
        "previous_key_id": active_key.id,
        "next_key": platform_trust_descriptor(staged_key),
        "created_at": staged_key.created_at.isoformat(),
    }
    return {
        "phase": "staged",
        "proposal": proposal,
        "previous_key_signature": sign_platform_envelope(active_key, proposal),
        "next_key_signature": sign_platform_envelope(staged_key, proposal),
    }


def platform_trust_descriptor(key: PlatformCommandSigningKey) -> dict[str, Any]:
    return {
        "key_id": key.id,
        "key_version": key.key_version,
        "algorithm": "Ed25519",
        "public_key": key.public_key,
        "fingerprint": key.fingerprint,
    }


def sign_platform_envelope(key: PlatformCommandSigningKey, envelope: dict[str, Any]) -> str:
    if key.revoked_at is not None:
        raise PlatformCommandSigningError("Platform command signing key is revoked")
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
        raise PlatformCommandSigningError("Platform command signing key cannot be decrypted") from exc
    return base64.b64encode(private_key.sign(canonical_envelope(envelope))).decode()


def verify_platform_envelope(public_key: str, envelope: dict[str, Any], signature: str) -> bool:
    try:
        public_raw = base64.b64decode(public_key, validate=True)
        signature_raw = base64.b64decode(signature, validate=True)
        if len(public_raw) != 32 or len(signature_raw) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw, canonical_envelope(envelope)
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False
