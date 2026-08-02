from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.models import User
from lsa.schemas import LoginRequest, LoginResponse
from lsa.security import create_session_token, verify_password


router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    user = db.scalar(select(User).where(func.lower(User.email) == request.email.lower()))
    if user is None or not user.is_active or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_session_token(
        user.id, user.tenant_id, user.role, settings.session_secret, settings.session_ttl_minutes
    )
    return LoginResponse(
        access_token=token,
        user={"id": user.id, "email": user.email, "name": user.display_name, "role": user.role},
    )

