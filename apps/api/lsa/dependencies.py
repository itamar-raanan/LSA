from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.models import IngestionToken, User, UserSession, now_utc
from lsa.security import decode_session_token, hash_ingestion_token


bearer = HTTPBearer(auto_error=False)


@dataclass
class IngestionPrincipal:
    token_id: str
    tenant_id: str
    host_id: str | None


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )
    try:
        payload = decode_session_token(credentials.credentials, settings.session_secret)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session"
        ) from exc
    user = db.get(User, str(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    session_id = payload.get("sid")
    session = db.get(UserSession, str(session_id)) if session_id else None
    if session is None or session.user_id != user.id or session.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=now_utc().tzinfo)
    if expires_at <= now_utc():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    session.last_seen_at = now_utc()
    return user


def ingestion_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> IngestionPrincipal:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingestion token required"
        )
    token_hash = hash_ingestion_token(credentials.credentials)
    token = db.scalar(
        select(IngestionToken).where(
            IngestionToken.token_hash == token_hash, IngestionToken.revoked_at.is_(None)
        )
    )
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ingestion token"
        )
    if token.expires_at is not None:
        expires_at = token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=now_utc().tzinfo)
        if expires_at <= now_utc():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingestion token expired"
            )
    token.last_used_at = now_utc()
    return IngestionPrincipal(token.id, token.tenant_id, token.host_id)
