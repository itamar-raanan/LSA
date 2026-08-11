from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from lsa.api.admin import require_admin
from lsa.dependencies import current_user
from lsa.models import AuditEvent, User
from lsa.database import get_db
from lsa.config import Settings, get_settings
from lsa.schemas import AgentConnectivityResponse, AgentPackageResponse
from lsa.services.agent_packages import AgentPackage, agent_packages, get_agent_package
from lsa.services.platform_command_trust import active_platform_command_key, platform_trust_descriptor


router = APIRouter(tags=["agent packages"])


@router.get("/agent-connectivity", response_model=AgentConnectivityResponse)
def agent_connectivity(
    user: User = Depends(current_user),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> AgentConnectivityResponse:
    require_admin(user)
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
    )


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
