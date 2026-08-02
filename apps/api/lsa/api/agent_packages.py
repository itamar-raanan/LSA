from fastapi import APIRouter, Depends, HTTPException, Response

from lsa.api.admin import require_admin
from lsa.dependencies import current_user
from lsa.models import User
from lsa.schemas import AgentPackageResponse
from lsa.services.agent_packages import get_agent_package, linux_agent_package


router = APIRouter(tags=["agent packages"])


def _response() -> AgentPackageResponse:
    package = linux_agent_package()
    return AgentPackageResponse(
        id=package.package_id,
        version=package.version,
        filename=package.filename,
        content_type=package.content_type,
        operating_system=package.operating_system,
        architecture=package.architecture,
        size_bytes=package.size_bytes,
        sha256=package.sha256,
    )


@router.get("/agent-packages", response_model=list[AgentPackageResponse])
def list_agent_packages(user: User = Depends(current_user)) -> list[AgentPackageResponse]:
    require_admin(user)
    return [_response()]


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
