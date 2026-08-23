from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.api.admin import require_admin
from lsa.dependencies import current_user
from lsa.models import (
    AgentEnrollmentToken,
    AuditEvent,
    LinuxAgent,
    PlatformCommandSigningKey,
    Tenant,
    User,
    now_utc,
)
from lsa.database import get_db
from lsa.config import Settings, get_settings
from lsa.schemas import (
    AgentConnectivityResponse,
    AgentPackageResponse,
    PlatformCommandKeyRotationResponse,
)
from lsa.services.agent_packages import AgentPackage, agent_packages, get_agent_package
from lsa.services.platform_command_trust import (
    PlatformCommandSigningError,
    active_platform_command_key,
    create_staged_platform_command_key,
    platform_trust_descriptor,
)


router = APIRouter(tags=["agent packages"])
PLATFORM_KEY_ROTATION_CAPABILITY = "platform-key-rotation-v1"


def _rotation_response(
    db: Session,
    tenant_id: str,
    current: PlatformCommandSigningKey,
    *,
    lock_agents: bool = False,
) -> PlatformCommandKeyRotationResponse | None:
    staged = db.scalar(
        select(PlatformCommandSigningKey).where(
            PlatformCommandSigningKey.tenant_id == tenant_id,
            PlatformCommandSigningKey.status == "staged",
            PlatformCommandSigningKey.revoked_at.is_(None),
        )
    )
    if staged is None:
        return None
    agent_query = select(LinuxAgent).where(
        LinuxAgent.tenant_id == tenant_id,
        LinuxAgent.revoked_at.is_(None),
    )
    if lock_agents:
        agent_query = agent_query.with_for_update()
    agents = db.scalars(agent_query).all()
    eligible = [
        agent
        for agent in agents
        if PLATFORM_KEY_ROTATION_CAPABILITY in (agent.capabilities or [])
    ]
    acknowledged = [
        agent
        for agent in eligible
        if agent.pending_platform_command_key_id == staged.id
        and agent.pending_platform_command_key_fingerprint == staged.fingerprint
        and agent.platform_command_key_acknowledged_at is not None
    ]
    blocking = len(agents) - len(acknowledged)
    return PlatformCommandKeyRotationResponse(
        status="ready" if blocking == 0 else "staged",
        current_key=platform_trust_descriptor(current),
        next_key=platform_trust_descriptor(staged),
        eligible_agents=len(eligible),
        acknowledged_agents=len(acknowledged),
        blocking_agents=blocking,
        staged_at=staged.created_at,
    )


def _lock_tenant(db: Session, tenant_id: str) -> None:
    if db.scalar(select(Tenant.id).where(Tenant.id == tenant_id).with_for_update()) is None:
        raise HTTPException(status_code=404, detail="Tenant not found")


@router.get("/agent-connectivity", response_model=AgentConnectivityResponse)
def agent_connectivity(
    user: User = Depends(current_user),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> AgentConnectivityResponse:
    require_admin(user)
    _lock_tenant(db, user.tenant_id)
    key, created = active_platform_command_key(db, user.tenant_id)
    if created:
        db.add(
            AuditEvent(
                tenant_id=user.tenant_id,
                actor_type="user",
                actor_id=user.id,
                action="platform_command_key.created",
                target_type="platform_command_signing_key",
                target_id=key.id,
                details={"key_version": key.key_version, "fingerprint": key.fingerprint},
            )
        )
        db.commit()
    return AgentConnectivityResponse(
        public_url=settings.agent_public_url.rstrip("/"),
        platform_trust=platform_trust_descriptor(key),
        key_rotation=_rotation_response(db, user.tenant_id, key),
    )


@router.post("/platform-command-key-rotation", response_model=PlatformCommandKeyRotationResponse, status_code=201)
def stage_platform_command_key_rotation(
    user: User = Depends(current_user), db: Session = Depends(get_db)
) -> PlatformCommandKeyRotationResponse:
    require_admin(user)
    _lock_tenant(db, user.tenant_id)
    current, _ = active_platform_command_key(db, user.tenant_id)
    try:
        staged = create_staged_platform_command_key(db, user.tenant_id, current)
    except PlatformCommandSigningError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    agents = db.scalars(
        select(LinuxAgent).where(
            LinuxAgent.tenant_id == user.tenant_id,
            LinuxAgent.revoked_at.is_(None),
        )
    ).all()
    for agent in agents:
        agent.pending_platform_command_key_id = staged.id
        agent.pending_platform_command_key_fingerprint = staged.fingerprint
        agent.platform_command_key_acknowledged_at = None
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="platform_command_key.rotation_staged",
            target_type="platform_command_signing_key",
            target_id=staged.id,
            details={
                "previous_key_id": current.id,
                "key_version": staged.key_version,
                "fingerprint": staged.fingerprint,
                "agent_count": len(agents),
            },
        )
    )
    db.commit()
    return _rotation_response(db, user.tenant_id, current)  # type: ignore[return-value]


@router.post("/platform-command-key-rotation/activate", response_model=AgentConnectivityResponse)
def activate_platform_command_key_rotation(
    user: User = Depends(current_user),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> AgentConnectivityResponse:
    require_admin(user)
    _lock_tenant(db, user.tenant_id)
    current, _ = active_platform_command_key(db, user.tenant_id)
    rotation = _rotation_response(db, user.tenant_id, current, lock_agents=True)
    if rotation is None:
        raise HTTPException(status_code=404, detail="No platform command key rotation is staged")
    if rotation.blocking_agents:
        raise HTTPException(
            status_code=409,
            detail=f"Rotation is blocked by {rotation.blocking_agents} agent(s) that have not acknowledged the new key",
        )
    staged = db.scalar(
        select(PlatformCommandSigningKey).where(
            PlatformCommandSigningKey.tenant_id == user.tenant_id,
            PlatformCommandSigningKey.status == "staged",
        )
    )
    if staged is None:
        raise HTTPException(status_code=404, detail="No platform command key rotation is staged")
    activated_at = now_utc()
    current.status = "retired"
    current.retired_at = activated_at
    staged.status = "active"
    staged.activated_at = activated_at
    agents = db.scalars(
        select(LinuxAgent).where(
            LinuxAgent.tenant_id == user.tenant_id,
            LinuxAgent.revoked_at.is_(None),
        )
    ).all()
    for agent in agents:
        agent.platform_command_key_id = staged.id
        agent.platform_command_key_fingerprint = staged.fingerprint
        agent.pending_platform_command_key_id = None
        agent.pending_platform_command_key_fingerprint = None
        agent.platform_command_key_acknowledged_at = None
    tokens = db.scalars(
        select(AgentEnrollmentToken).where(
            AgentEnrollmentToken.tenant_id == user.tenant_id,
            AgentEnrollmentToken.platform_command_key_id == current.id,
            AgentEnrollmentToken.revoked_at.is_(None),
        )
    ).all()
    for token in tokens:
        token.revoked_at = activated_at
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="platform_command_key.rotation_activated",
            target_type="platform_command_signing_key",
            target_id=staged.id,
            details={
                "previous_key_id": current.id,
                "key_version": staged.key_version,
                "agents_activated": len(agents),
                "enrollment_tokens_revoked": len(tokens),
            },
        )
    )
    db.commit()
    return AgentConnectivityResponse(
        public_url=settings.agent_public_url.rstrip("/"),
        platform_trust=platform_trust_descriptor(staged),
        key_rotation=None,
    )


@router.delete("/platform-command-key-rotation", status_code=204)
def abort_platform_command_key_rotation(
    user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    require_admin(user)
    _lock_tenant(db, user.tenant_id)
    staged = db.scalar(
        select(PlatformCommandSigningKey).where(
            PlatformCommandSigningKey.tenant_id == user.tenant_id,
            PlatformCommandSigningKey.status == "staged",
            PlatformCommandSigningKey.revoked_at.is_(None),
        )
    )
    if staged is None:
        raise HTTPException(status_code=404, detail="No platform command key rotation is staged")
    staged.status = "revoked"
    staged.revoked_at = now_utc()
    agents = db.scalars(
        select(LinuxAgent).where(
            LinuxAgent.tenant_id == user.tenant_id,
            LinuxAgent.pending_platform_command_key_id == staged.id,
        )
    ).all()
    for agent in agents:
        agent.pending_platform_command_key_id = None
        agent.pending_platform_command_key_fingerprint = None
        agent.platform_command_key_acknowledged_at = None
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="platform_command_key.rotation_aborted",
            target_type="platform_command_signing_key",
            target_id=staged.id,
            details={"agents_cleared": len(agents)},
        )
    )
    db.commit()
    return Response(status_code=204)


def _response(package: AgentPackage) -> AgentPackageResponse:
    return AgentPackageResponse(
        id=package.package_id,
        version=package.version,
        filename=package.filename,
        content_type=package.content_type,
        operating_system=package.operating_system,
        architecture=package.architecture,
        package_format=package.package_format,
        release_channel=package.release_channel,
        audit_only=package.audit_only,
        size_bytes=package.size_bytes,
        sha256=package.sha256,
    )


@router.get("/agent-packages", response_model=list[AgentPackageResponse])
def list_agent_packages(user: User = Depends(current_user)) -> list[AgentPackageResponse]:
    require_admin(user)
    return [_response(package) for package in agent_packages()]


@router.get("/agent-packages/{package_id}/download")
def download_agent_package(package_id: str, user: User = Depends(current_user)) -> Response:
    require_admin(user)
    package = get_agent_package(package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Agent package not found")
    return Response(
        content=package.data,
        media_type=package.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{package.filename}"',
            "Cache-Control": "private, max-age=3600",
            "X-LSA-Agent-SHA256": package.sha256,
            "X-Content-Type-Options": "nosniff",
        },
    )
