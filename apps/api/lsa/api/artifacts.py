import re
from datetime import UTC, datetime
from hashlib import sha256

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.api.admin import require_admin
from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import AuditEvent, Report, User, now_utc
from lsa.schemas import ArtifactPurgeResponse
from lsa.services.artifacts import (
    ArtifactNotFound,
    ArtifactStore,
    ArtifactStoreError,
    get_artifact_store,
)


router = APIRouter(tags=["evidence vault"])


def get_tenant_report(db: Session, report_id: str, user: User) -> Report:
    report = db.get(Report, report_id)
    if report is None or report.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def require_available_artifact(report: Report) -> str:
    if report.artifact_object_key is None or report.artifact_deleted_at is not None:
        raise HTTPException(status_code=404, detail="Report artifact is not available")
    return report.artifact_object_key


def normalized_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def safe_filename(value: str | None, report_id: str) -> str:
    fallback = f"lsa-report-{report_id}.zip"
    if not value:
        return fallback
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    return sanitized[:200] or fallback


@router.get("/reports/{report_id}/artifact")
def download_artifact(
    report_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    artifact_store: ArtifactStore = Depends(get_artifact_store),
) -> Response:
    report = get_tenant_report(db, report_id, user)
    object_key = require_available_artifact(report)
    try:
        data = artifact_store.get(object_key, report.artifact_object_version)
    except ArtifactNotFound as exc:
        raise HTTPException(status_code=409, detail="Evidence object is missing from the vault") from exc
    except ArtifactStoreError as exc:
        raise HTTPException(status_code=503, detail="Evidence vault is unavailable") from exc
    actual_checksum = sha256(data).hexdigest()
    if report.checksum is None or actual_checksum != report.checksum:
        db.add(
            AuditEvent(
                tenant_id=user.tenant_id,
                actor_type="user",
                actor_id=user.id,
                action="artifact.integrity_failed",
                target_type="report",
                target_id=report.id,
                details={"expected": report.checksum, "actual": actual_checksum},
            )
        )
        db.commit()
        raise HTTPException(status_code=409, detail="Evidence integrity verification failed")
    if report.artifact_size_bytes is not None and len(data) != report.artifact_size_bytes:
        raise HTTPException(status_code=409, detail="Evidence size verification failed")
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="artifact.downloaded",
            target_type="report",
            target_id=report.id,
            details={"checksum": actual_checksum, "size_bytes": len(data)},
        )
    )
    db.commit()
    filename = safe_filename(report.artifact_name, report.id)
    return Response(
        content=data,
        media_type=report.artifact_content_type or "application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-LSA-Artifact-SHA256": actual_checksum,
        },
    )


@router.delete("/reports/{report_id}/artifact", status_code=status.HTTP_204_NO_CONTENT)
def delete_artifact(
    report_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    artifact_store: ArtifactStore = Depends(get_artifact_store),
) -> Response:
    require_admin(user)
    report = get_tenant_report(db, report_id, user)
    object_key = require_available_artifact(report)
    if (
        report.artifact_retention_until is not None
        and normalized_utc(report.artifact_retention_until) > datetime.now(UTC)
    ):
        raise HTTPException(status_code=409, detail="Evidence retention period has not expired")
    try:
        artifact_store.delete(object_key, report.artifact_object_version)
    except ArtifactStoreError as exc:
        raise HTTPException(status_code=503, detail="Evidence vault is unavailable") from exc
    report.artifact_deleted_at = now_utc()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="artifact.deleted",
            target_type="report",
            target_id=report.id,
            details={"object_key": object_key, "reason": "manual retention-compliant deletion"},
        )
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/artifacts/purge-expired", response_model=ArtifactPurgeResponse)
def purge_expired_artifacts(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    artifact_store: ArtifactStore = Depends(get_artifact_store),
) -> ArtifactPurgeResponse:
    require_admin(user)
    now = datetime.now(UTC)
    reports = db.scalars(
        select(Report).where(
            Report.tenant_id == user.tenant_id,
            Report.artifact_object_key.is_not(None),
            Report.artifact_deleted_at.is_(None),
            Report.artifact_retention_until.is_not(None),
            Report.artifact_retention_until <= now,
        )
    ).all()
    deleted = 0
    for report in reports:
        try:
            artifact_store.delete(
                report.artifact_object_key or "",
                report.artifact_object_version,
            )
        except ArtifactStoreError as exc:
            db.rollback()
            raise HTTPException(status_code=503, detail="Evidence vault is unavailable") from exc
        report.artifact_deleted_at = now_utc()
        db.add(
            AuditEvent(
                tenant_id=user.tenant_id,
                actor_type="user",
                actor_id=user.id,
                action="artifact.deleted",
                target_type="report",
                target_id=report.id,
                details={"reason": "retention policy purge"},
            )
        )
        deleted += 1
    db.commit()
    return ArtifactPurgeResponse(deleted=deleted)
