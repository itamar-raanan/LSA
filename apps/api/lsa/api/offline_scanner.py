from fastapi import APIRouter, Depends, Response

from lsa.dependencies import current_user
from lsa.models import User
from lsa.services.offline_scanner_package import offline_scanner_package


router = APIRouter(tags=["offline scanner"])


@router.get("/offline-scanner-package")
def scanner_package_metadata(user: User = Depends(current_user)) -> dict[str, object]:
    package = offline_scanner_package()
    return {
        "version": package.version,
        "filename": package.filename,
        "size_bytes": package.size_bytes,
        "sha256": package.sha256,
        "audit_only": True,
    }


@router.get("/offline-scanner-package/download")
def download_scanner_package(user: User = Depends(current_user)) -> Response:
    package = offline_scanner_package()
    return Response(
        content=package.data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{package.filename}"',
            "Cache-Control": "private, max-age=3600",
            "X-LSA-Scanner-SHA256": package.sha256,
            "X-Content-Type-Options": "nosniff",
        },
    )
