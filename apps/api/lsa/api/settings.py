from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import AuditEvent, IdentityProvider, TlsCertificate, User, UserSession, now_utc
from lsa.schemas import (
    IdentityProviderCreate,
    IdentityProviderResponse,
    IdentityProviderUpdate,
    TlsCertificateResponse,
    UserAdminResponse,
    UserCreate,
    UserRoleUpdate,
    UserStatusUpdate,
)
from lsa.security import encrypt_secret
from lsa.services.certificates import install_certificate
from lsa.services.identity import validate_identity_url


router = APIRouter(prefix="/settings", tags=["settings"])


def require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")


def audit(
    db: Session, user: User, action: str, target_type: str, target_id: str, details: dict
) -> None:
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
    )


def provider_response(provider: IdentityProvider) -> IdentityProviderResponse:
    return IdentityProviderResponse(
        id=provider.id,
        name=provider.name,
        provider_type=provider.provider_type,
        issuer_url=provider.issuer_url,
        client_id=provider.client_id,
        config=provider.config or {},
        is_enabled=provider.is_enabled,
        secret_configured=bool(provider.secret_ciphertext),
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


def validate_provider(request: IdentityProviderCreate, settings: Settings) -> None:
    if request.provider_type == "radius":
        if not request.config.get("host"):
            raise HTTPException(status_code=422, detail="RADIUS host is required")
    else:
        if not request.issuer_url or not request.client_id:
            raise HTTPException(
                status_code=422, detail="OIDC issuer URL and client ID are required"
            )
        validate_identity_url(request.issuer_url, settings.allow_private_identity_providers)


@router.get("/identity-providers", response_model=list[IdentityProviderResponse])
def list_providers(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    providers = db.scalars(
        select(IdentityProvider)
        .where(IdentityProvider.tenant_id == user.tenant_id)
        .order_by(IdentityProvider.name)
    ).all()
    return [provider_response(provider) for provider in providers]


@router.post("/identity-providers", response_model=IdentityProviderResponse, status_code=201)
def create_provider(
    request: IdentityProviderCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    require_admin(user)
    validate_provider(request, settings)
    if request.is_enabled and not request.secret:
        raise HTTPException(
            status_code=422, detail="A secret is required before enabling the provider"
        )
    provider = IdentityProvider(
        tenant_id=user.tenant_id,
        name=request.name,
        provider_type=request.provider_type,
        issuer_url=request.issuer_url.rstrip("/") if request.issuer_url else None,
        client_id=request.client_id,
        secret_ciphertext=encrypt_secret(
            request.secret, settings.session_secret, settings.settings_encryption_key
        )
        if request.secret
        else None,
        config=request.config,
        is_enabled=request.is_enabled,
    )
    db.add(provider)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="An identity provider with this name already exists"
        ) from exc
    audit(
        db,
        user,
        "identity_provider.created",
        "identity_provider",
        provider.id,
        {"type": provider.provider_type},
    )
    db.commit()
    db.refresh(provider)
    return provider_response(provider)


@router.put("/identity-providers/{provider_id}", response_model=IdentityProviderResponse)
def update_provider(
    provider_id: str,
    request: IdentityProviderUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    require_admin(user)
    provider = db.get(IdentityProvider, provider_id)
    if provider is None or provider.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Identity provider not found")
    validate_provider(request, settings)
    if provider.provider_type != request.provider_type and db.scalar(
        select(User).where(User.identity_provider_id == provider.id).limit(1)
    ):
        raise HTTPException(
            status_code=409, detail="Provider type cannot change after users are linked"
        )
    if request.is_enabled and not (request.secret or provider.secret_ciphertext):
        raise HTTPException(
            status_code=422, detail="A secret is required before enabling the provider"
        )
    provider.name, provider.provider_type = request.name, request.provider_type
    provider.issuer_url = request.issuer_url.rstrip("/") if request.issuer_url else None
    provider.client_id, provider.config, provider.is_enabled = (
        request.client_id,
        request.config,
        request.is_enabled,
    )
    provider.updated_at = now_utc()
    if request.secret:
        provider.secret_ciphertext = encrypt_secret(
            request.secret, settings.session_secret, settings.settings_encryption_key
        )
    audit(
        db,
        user,
        "identity_provider.updated",
        "identity_provider",
        provider.id,
        {"enabled": provider.is_enabled},
    )
    db.commit()
    return provider_response(provider)


@router.delete("/identity-providers/{provider_id}", status_code=204)
def delete_provider(
    provider_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    require_admin(user)
    provider = db.get(IdentityProvider, provider_id)
    if provider is None or provider.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Identity provider not found")
    if db.scalar(select(User).where(User.identity_provider_id == provider.id).limit(1)):
        raise HTTPException(status_code=409, detail="Disable this provider; it has linked users")
    audit(
        db,
        user,
        "identity_provider.deleted",
        "identity_provider",
        provider.id,
        {"name": provider.name},
    )
    db.delete(provider)
    db.commit()
    return Response(status_code=204)


def user_response(item: User, provider_name: str | None = None) -> UserAdminResponse:
    return UserAdminResponse(
        id=item.id,
        email=item.email,
        name=item.display_name,
        role=item.role,
        is_active=item.is_active,
        auth_source=item.auth_source,
        provider_name=provider_name,
        last_login_at=item.last_login_at,
        created_at=item.created_at,
    )


@router.get("/users", response_model=list[UserAdminResponse])
def list_users(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    providers = {
        item.id: item.name
        for item in db.scalars(
            select(IdentityProvider).where(IdentityProvider.tenant_id == user.tenant_id)
        ).all()
    }
    users = db.scalars(
        select(User).where(User.tenant_id == user.tenant_id).order_by(User.email)
    ).all()
    return [user_response(item, providers.get(item.identity_provider_id)) for item in users]


@router.post("/users", response_model=UserAdminResponse, status_code=201)
def create_user(
    request: UserCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    provider = db.get(IdentityProvider, request.provider_id)
    if provider is None or provider.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Identity provider not found")
    email = request.email.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=422, detail="A valid email address is required")
    subject = request.external_subject.strip()
    if provider.provider_type == "radius":
        subject = subject.casefold()
    target = User(
        tenant_id=user.tenant_id,
        email=email,
        display_name=request.display_name.strip(),
        password_hash=None,
        role=request.role,
        role_source="manual",
        auth_source=provider.provider_type,
        identity_provider_id=provider.id,
        external_subject=subject,
    )
    db.add(target)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="This email or provider identity is already registered"
        ) from exc
    audit(
        db,
        user,
        "user.preprovisioned",
        "user",
        target.id,
        {"provider_id": provider.id, "role": target.role},
    )
    db.commit()
    db.refresh(target)
    return user_response(target, provider.name)


@router.patch("/users/{user_id}/role", response_model=UserAdminResponse)
def update_user_role(
    user_id: str,
    request: UserRoleUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    target = db.get(User, user_id)
    if target is None or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == user.id and request.role != "admin":
        raise HTTPException(status_code=409, detail="You cannot remove your own administrator role")
    target.role = request.role
    target.role_source = "manual"
    audit(db, user, "user.role_changed", "user", target.id, {"role": request.role})
    db.commit()
    return user_response(target)


@router.patch("/users/{user_id}/status", response_model=UserAdminResponse)
def update_user_status(
    user_id: str,
    request: UserStatusUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    target = db.get(User, user_id)
    if target is None or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == user.id and not request.is_active:
        raise HTTPException(status_code=409, detail="You cannot disable your own account")
    target.is_active = request.is_active
    if not request.is_active:
        for session in db.scalars(
            select(UserSession).where(
                UserSession.user_id == target.id, UserSession.revoked_at.is_(None)
            )
        ).all():
            session.revoked_at = now_utc()
    audit(db, user, "user.status_changed", "user", target.id, {"active": request.is_active})
    db.commit()
    return user_response(target)


def tls_response(item: TlsCertificate) -> TlsCertificateResponse:
    return TlsCertificateResponse(
        id=item.id,
        fingerprint=item.fingerprint,
        subject=item.subject,
        issuer=item.issuer,
        hostnames=item.hostnames,
        not_valid_before=item.not_valid_before,
        not_valid_after=item.not_valid_after,
        is_active=item.is_active,
        created_at=item.created_at,
    )


@router.get("/tls-certificate", response_model=TlsCertificateResponse | None)
def current_tls_certificate(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    item = db.scalar(
        select(TlsCertificate).where(
            TlsCertificate.tenant_id == user.tenant_id, TlsCertificate.is_active.is_(True)
        )
    )
    return tls_response(item) if item else None


@router.post("/tls-certificate", response_model=TlsCertificateResponse, status_code=201)
async def upload_tls_certificate(
    certificate: UploadFile = File(...),
    private_key: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    require_admin(user)
    certificate_data = await certificate.read(1024 * 1024 + 1)
    private_key_data = await private_key.read(1024 * 1024 + 1)
    if len(certificate_data) > 1024 * 1024 or len(private_key_data) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="TLS files must each be 1 MiB or smaller")
    item = install_certificate(
        db, user.tenant_id, certificate_data, private_key_data, settings, user.id
    )
    audit(
        db,
        user,
        "tls_certificate.installed",
        "tls_certificate",
        item.id,
        {"fingerprint": item.fingerprint},
    )
    db.commit()
    db.refresh(item)
    return tls_response(item)
