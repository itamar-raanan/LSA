import secrets
import uuid
from base64 import b64decode
from binascii import Error as BinasciiError
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import AuditEvent, Host, IngestionToken, SigningKey, User, now_utc
from lsa.schemas import (
    HostCreate,
    HostResponse,
    SigningKeyCreate,
    SigningKeyResponse,
    TokenCreate,
    TokenCreated,
    TokenResponse,
)
from lsa.security import hash_ingestion_token


router = APIRouter(tags=["administration"])


def require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")


@router.post("/hosts", response_model=HostResponse, status_code=status.HTTP_201_CREATED)
def create_host(
    request: HostCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> HostResponse:
    require_admin(user)
    host_id = str(uuid.uuid4())
    host = Host(
        id=host_id,
        tenant_id=user.tenant_id,
        hostname=request.hostname,
        fqdn=request.fqdn,
        machine_id_hash=f"pending:{host_id}",
        operating_system=request.os_family.capitalize(),
        os_family=request.os_family,
        os_version=request.os_version,
        kernel="pending",
        architecture="pending",
        ip_addresses=request.ip_addresses,
        tags=request.tags,
    )
    db.add(host)
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="host.enrolled",
            target_type="host",
            target_id=host.id,
            details={"hostname": host.hostname},
        )
    )
    db.commit()
    return HostResponse(
        id=host.id,
        hostname=host.hostname,
        fqdn=host.fqdn,
        operating_system=host.operating_system,
        os_family=host.os_family,
        os_version=host.os_version,
        kernel=host.kernel,
        architecture=host.architecture,
        ip_addresses=host.ip_addresses,
        tags=host.tags,
        system_info=host.system_info or {},
        compliance_score=None,
        security_score=None,
        last_scan_at=None,
        application_count=0,
        finding_counts={severity: 0 for severity in ["critical", "high", "medium", "low", "info"]},
    )


@router.delete("/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(
    host_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    require_admin(user)
    host = db.get(Host, host_id)
    if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Host not found")
    deleted_at = now_utc()
    host.deleted_at = deleted_at
    for token in db.scalars(
        select(IngestionToken).where(
            IngestionToken.host_id == host.id, IngestionToken.revoked_at.is_(None)
        )
    ).all():
        token.revoked_at = deleted_at
    for key in db.scalars(
        select(SigningKey).where(SigningKey.host_id == host.id, SigningKey.revoked_at.is_(None))
    ).all():
        key.revoked_at = deleted_at
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="host.deleted",
            target_type="host",
            target_id=host.id,
            details={"hostname": host.hostname, "evidence_preserved": True},
        )
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/ingestion-tokens", response_model=TokenCreated, status_code=status.HTTP_201_CREATED)
def create_ingestion_token(
    request: TokenCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> TokenCreated:
    require_admin(user)
    expires_at = request.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=now_utc().tzinfo)
        if expires_at <= now_utc():
            raise HTTPException(status_code=422, detail="Token expiry must be in the future")
    if request.host_id:
        host = db.get(Host, request.host_id)
        if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
            raise HTTPException(status_code=404, detail="Host not found")
    raw_token = f"lsa_ingest_{secrets.token_urlsafe(32)}"
    token = IngestionToken(
        tenant_id=user.tenant_id,
        host_id=request.host_id,
        name=request.name,
        token_prefix=raw_token[:20],
        token_hash=hash_ingestion_token(raw_token),
        expires_at=expires_at,
    )
    db.add(token)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="ingestion_token.created",
            target_type="ingestion_token",
            target_id=token.id,
            details={"host_id": token.host_id, "name": token.name},
        )
    )
    db.commit()
    return TokenCreated(
        id=token.id,
        name=token.name,
        host_id=token.host_id,
        token=raw_token,
        token_prefix=token.token_prefix,
        expires_at=token.expires_at,
    )


@router.get("/ingestion-tokens", response_model=list[TokenResponse])
def list_ingestion_tokens(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[TokenResponse]:
    require_admin(user)
    tokens = db.scalars(
        select(IngestionToken)
        .where(IngestionToken.tenant_id == user.tenant_id)
        .order_by(IngestionToken.created_at.desc())
    ).all()
    return [
        TokenResponse(
            id=token.id,
            name=token.name,
            host_id=token.host_id,
            token_prefix=token.token_prefix,
            expires_at=token.expires_at,
            last_used_at=token.last_used_at,
            revoked_at=token.revoked_at,
            created_at=token.created_at,
        )
        for token in tokens
    ]


@router.delete("/ingestion-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_ingestion_token(
    token_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    require_admin(user)
    token = db.get(IngestionToken, token_id)
    if token is None or token.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Ingestion token not found")
    if token.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Ingestion token is already revoked")
    token.revoked_at = now_utc()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="ingestion_token.revoked",
            target_type="ingestion_token",
            target_id=token.id,
            details={"name": token.name},
        )
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def signing_key_response(key: SigningKey) -> SigningKeyResponse:
    return SigningKeyResponse(
        id=key.id,
        name=key.name,
        host_id=key.host_id,
        public_key=key.public_key,
        fingerprint=key.fingerprint,
        expires_at=key.expires_at,
        revoked_at=key.revoked_at,
        created_at=key.created_at,
    )


@router.post("/signing-keys", response_model=SigningKeyResponse, status_code=status.HTTP_201_CREATED)
def create_signing_key(
    request: SigningKeyCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> SigningKeyResponse:
    require_admin(user)
    expires_at = request.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=now_utc().tzinfo)
        if expires_at <= now_utc():
            raise HTTPException(status_code=422, detail="Signing key expiry must be in the future")
    if request.host_id:
        host = db.get(Host, request.host_id)
        if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
            raise HTTPException(status_code=404, detail="Host not found")
    try:
        public_key_bytes = b64decode(request.public_key, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except (BinasciiError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Public key must be a base64 Ed25519 public key") from exc
    if len(public_key_bytes) != 32:
        raise HTTPException(status_code=422, detail="Public key must be a base64 Ed25519 public key")

    key = SigningKey(
        tenant_id=user.tenant_id,
        host_id=request.host_id,
        name=request.name,
        public_key=request.public_key,
        fingerprint=sha256(public_key_bytes).hexdigest(),
        expires_at=expires_at,
    )
    db.add(key)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Signing key is already registered") from exc
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="signing_key.created",
            target_type="signing_key",
            target_id=key.id,
            details={"host_id": key.host_id, "name": key.name, "fingerprint": key.fingerprint},
        )
    )
    db.commit()
    db.refresh(key)
    return signing_key_response(key)


@router.get("/signing-keys", response_model=list[SigningKeyResponse])
def list_signing_keys(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[SigningKeyResponse]:
    require_admin(user)
    keys = db.scalars(
        select(SigningKey)
        .where(SigningKey.tenant_id == user.tenant_id)
        .order_by(SigningKey.created_at.desc())
    ).all()
    return [signing_key_response(key) for key in keys]


@router.delete("/signing-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_signing_key(
    key_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    require_admin(user)
    key = db.get(SigningKey, key_id)
    if key is None or key.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Signing key not found")
    if key.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Signing key is already revoked")
    key.revoked_at = now_utc()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="signing_key.revoked",
            target_type="signing_key",
            target_id=key.id,
            details={"name": key.name, "fingerprint": key.fingerprint},
        )
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
