import base64
import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import AuditEvent, AuthTransaction, IdentityProvider, User, UserSession, now_utc
from lsa.schemas import (
    LoginRequest,
    LoginResponse,
    OidcStartResponse,
    PublicIdentityProvider,
    RadiusLoginRequest,
)
from lsa.security import create_session_token, verify_password
from lsa.services.identity import (
    ensure_not_expired,
    exchange_oidc_code,
    fetch_discovery,
    jit_user,
    pkce_challenge,
    radius_authenticate,
    role_from_mapping,
)


router = APIRouter(prefix="/auth", tags=["authentication"])


def user_payload(user: User) -> dict[str, str]:
    return {"id": user.id, "email": user.email, "name": user.display_name, "role": user.role}


def issue_session(db: Session, user: User, settings: Settings) -> LoginResponse:
    session = UserSession(
        tenant_id=user.tenant_id,
        user_id=user.id,
        expires_at=now_utc() + timedelta(minutes=settings.session_ttl_minutes),
    )
    db.add(session)
    db.flush()
    token = create_session_token(
        user.id,
        user.tenant_id,
        user.role,
        settings.session_secret,
        settings.session_ttl_minutes,
        session.id,
    )
    return LoginResponse(access_token=token, user=user_payload(user))


def login_audit(db: Session, user: User, source: str) -> None:
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="session.created",
            target_type="user_session",
            target_id=user.id,
            details={"source": source},
        )
    )


@router.get("/providers", response_model=list[PublicIdentityProvider])
def public_providers(db: Session = Depends(get_db)) -> list[PublicIdentityProvider]:
    providers = db.scalars(
        select(IdentityProvider)
        .where(IdentityProvider.is_enabled.is_(True))
        .order_by(IdentityProvider.name)
    ).all()
    return [
        PublicIdentityProvider(id=item.id, name=item.name, provider_type=item.provider_type)
        for item in providers
    ]


@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    user = db.scalar(select(User).where(func.lower(User.email) == request.email.lower()))
    if (
        user is None
        or user.auth_source != "local"
        or not user.is_active
        or not user.password_hash
        or not verify_password(request.password, user.password_hash)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    user.last_login_at = now_utc()
    response = issue_session(db, user, settings)
    login_audit(db, user, "local-emergency")
    db.commit()
    return response


@router.post("/radius/login", response_model=LoginResponse)
def radius_login(
    request: RadiusLoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    provider = db.scalar(
        select(IdentityProvider).where(
            IdentityProvider.provider_type == "radius", IdentityProvider.is_enabled.is_(True)
        )
    )
    if provider is None:
        raise HTTPException(status_code=404, detail="RADIUS authentication is not enabled")
    subject, role = radius_authenticate(provider, request.username, request.password, settings)
    config = provider.config or {}
    domain = str(config.get("user_domain", "radius.local"))
    email = request.username if "@" in request.username else f"{request.username}@{domain}"
    user = jit_user(db, provider, subject, email, request.username, role)
    response = issue_session(db, user, settings)
    login_audit(db, user, "radius")
    db.commit()
    return response


@router.get("/oidc/{provider_id}/start", response_model=OidcStartResponse)
async def oidc_start(
    provider_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> OidcStartResponse:
    provider = db.get(IdentityProvider, provider_id)
    if provider is None or provider.provider_type == "radius" or not provider.is_enabled:
        raise HTTPException(status_code=404, detail="Identity provider not found")
    metadata = await fetch_discovery(provider, settings)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    redirect_uri = f"{settings.public_url.rstrip('/')}/api/v1/auth/oidc/callback"
    db.add(
        AuthTransaction(
            state_hash=hashlib.sha256(state.encode()).hexdigest(),
            provider_id=provider.id,
            nonce=nonce,
            code_verifier=verifier,
            redirect_uri=redirect_uri,
            expires_at=now_utc() + timedelta(minutes=10),
        )
    )
    db.commit()
    config = provider.config or {}
    scopes = str(config.get("scopes", "openid profile email"))
    params = urlencode(
        {
            "client_id": provider.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    return OidcStartResponse(authorization_url=f"{metadata['authorization_endpoint']}?{params}")


@router.get("/oidc/callback")
async def oidc_callback(
    code: str,
    state: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    transaction = db.scalar(
        select(AuthTransaction).where(
            AuthTransaction.state_hash == hashlib.sha256(state.encode()).hexdigest()
        )
    )
    if (
        transaction is None
        or transaction.used_at is not None
        or not ensure_not_expired(transaction.expires_at)
    ):
        raise HTTPException(
            status_code=401, detail="Authorization transaction is invalid or expired"
        )
    transaction.used_at = now_utc()
    db.commit()
    provider = db.get(IdentityProvider, transaction.provider_id)
    if provider is None or not provider.is_enabled:
        raise HTTPException(status_code=401, detail="Identity provider is disabled")
    metadata = await fetch_discovery(provider, settings)
    claims = await exchange_oidc_code(
        provider,
        metadata,
        code,
        transaction.redirect_uri,
        transaction.code_verifier,
        transaction.nonce,
        settings,
    )
    config = provider.config or {}
    email_claim = str(config.get("email_claim", "email"))
    name_claim = str(config.get("name_claim", "name"))
    groups_claim = str(config.get("groups_claim", "groups"))
    email = str(claims.get(email_claim) or claims.get("preferred_username") or "")
    if not email or "@" not in email:
        raise HTTPException(
            status_code=401, detail="Identity provider did not assert an email address"
        )
    role = role_from_mapping(
        claims.get(groups_claim),
        config.get("role_mapping"),
        str(config.get("default_role", "auditor")),
    )
    user = jit_user(
        db,
        provider,
        str(claims["sub"]),
        email,
        str(claims.get(name_claim) or email),
        role,
    )
    response = issue_session(db, user, settings)
    login_audit(db, user, provider.provider_type)
    db.commit()
    encoded_user = base64.urlsafe_b64encode(json.dumps(response.user).encode()).decode().rstrip("=")
    fragment = urlencode({"session": response.access_token, "user": encoded_user})
    return RedirectResponse(f"{settings.public_url.rstrip('/')}/login#{fragment}", status_code=303)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    sessions = db.scalars(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
    ).all()
    for session in sessions:
        session.revoked_at = now_utc()
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
