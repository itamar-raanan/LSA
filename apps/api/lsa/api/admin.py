import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import AuditEvent, Host, IngestionToken, User, now_utc
from lsa.schemas import HostCreate, HostResponse, TokenCreate, TokenCreated, TokenResponse
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
        compliance_score=None,
        security_score=None,
        last_scan_at=None,
        finding_counts={severity: 0 for severity in ["critical", "high", "medium", "low", "info"]},
    )


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
        if host is None or host.tenant_id != user.tenant_id:
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
