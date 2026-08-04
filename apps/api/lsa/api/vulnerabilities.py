import json
from datetime import UTC, timedelta

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from lsa.config import Settings, get_settings
from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import (
    AuditEvent,
    Host,
    HostApplication,
    HostApplicationVulnerability,
    User,
    Vulnerability,
    VulnerabilitySyncRun,
    now_utc,
)
from lsa.schemas import (
    ApplicationVulnerabilityResponse,
    HostVulnerabilityResponse,
    VulnerabilitySnapshotImportResponse,
    VulnerabilitySummaryResponse,
    VulnerabilitySyncRunResponse,
)
from lsa.services.vulnerability_intelligence import import_snapshot


router = APIRouter(tags=["vulnerability intelligence"])


def reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")


def sync_response(run: VulnerabilitySyncRun) -> VulnerabilitySyncRunResponse:
    return VulnerabilitySyncRunResponse(
        id=run.id,
        status=run.status,
        trigger=run.trigger,
        packages_queried=run.packages_queried,
        vulnerabilities_found=run.vulnerabilities_found,
        matches_found=run.matches_found,
        error=run.error,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
    )


def base_vulnerability_response(
    vulnerability: Vulnerability,
    *,
    affected_hosts: int,
    affected_host_ids: list[str],
    affected_versions: list[str],
    fixed_versions: list[str] | None = None,
) -> dict:
    return {
        "id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "aliases": vulnerability.aliases or [],
        "summary": vulnerability.summary,
        "severity": vulnerability.severity,
        "cvss_score": vulnerability.cvss_score,
        "known_exploited": vulnerability.known_exploited,
        "fixed_versions": fixed_versions if fixed_versions is not None else vulnerability.fixed_versions or [],
        "affected_hosts": affected_hosts,
        "affected_host_ids": affected_host_ids,
        "affected_versions": affected_versions,
        "kev_due_date": vulnerability.kev_due_date,
        "kev_required_action": vulnerability.kev_required_action,
        "ransomware_use": vulnerability.ransomware_use,
        "published_at": vulnerability.published_at,
        "modified_at": vulnerability.modified_at,
        "references": vulnerability.references or [],
    }


@router.get("/vulnerabilities/summary", response_model=VulnerabilitySummaryResponse)
def vulnerability_summary(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> VulnerabilitySummaryResponse:
    filters = (
        HostApplicationVulnerability.tenant_id == user.tenant_id,
        HostApplicationVulnerability.resolved_at.is_(None),
        HostApplication.removed_at.is_(None),
        Host.deleted_at.is_(None),
    )
    summary_query = (
        select(
            func.count(func.distinct(Vulnerability.id)).label("vulnerability_count"),
            func.count(HostApplicationVulnerability.id).label("exposure_count"),
            func.count(func.distinct(Host.id)).label("affected_hosts"),
            func.count(func.distinct(HostApplication.id)).label("affected_applications"),
            func.sum(case((Vulnerability.known_exploited.is_(True), 1), else_=0)).label(
                "known_exploited"
            ),
        )
        .select_from(HostApplicationVulnerability)
        .join(
            Vulnerability,
            Vulnerability.id == HostApplicationVulnerability.vulnerability_id,
        )
        .join(
            HostApplication,
            HostApplication.id == HostApplicationVulnerability.host_application_id,
        )
        .join(Host, Host.id == HostApplication.host_id)
        .where(*filters)
    )
    summary = db.execute(summary_query).one()
    severity_counts = {
        severity: 0 for severity in ["critical", "high", "medium", "low", "info", "unknown"]
    }
    severity_counts.update(
        {
            severity: count
            for severity, count in db.execute(
                select(Vulnerability.severity, func.count(HostApplicationVulnerability.id))
                .select_from(HostApplicationVulnerability)
                .join(
                    Vulnerability,
                    Vulnerability.id == HostApplicationVulnerability.vulnerability_id,
                )
                .join(
                    HostApplication,
                    HostApplication.id == HostApplicationVulnerability.host_application_id,
                )
                .join(Host, Host.id == HostApplication.host_id)
                .where(*filters)
                .group_by(Vulnerability.severity)
            )
        }
    )
    latest = db.scalar(
        select(VulnerabilitySyncRun)
        .where(VulnerabilitySyncRun.tenant_id == user.tenant_id)
        .order_by(VulnerabilitySyncRun.created_at.desc())
        .limit(1)
    )
    intelligence_state = "never"
    if latest:
        if latest.status in {"queued", "running"}:
            intelligence_state = "refreshing"
        elif latest.status == "failed":
            intelligence_state = "failed"
        elif latest.completed_at:
            completed_at = latest.completed_at
            if completed_at.tzinfo is None:
                completed_at = completed_at.replace(tzinfo=UTC)
            stale_after = now_utc() - timedelta(hours=settings.vulnerability_refresh_hours * 2)
            intelligence_state = "stale" if completed_at < stale_after else "fresh"
    return VulnerabilitySummaryResponse(
        vulnerability_count=summary.vulnerability_count or 0,
        exposure_count=summary.exposure_count or 0,
        affected_hosts=summary.affected_hosts or 0,
        affected_applications=summary.affected_applications or 0,
        known_exploited=summary.known_exploited or 0,
        severity_counts=severity_counts,
        intelligence_state=intelligence_state,
        last_sync=sync_response(latest) if latest else None,
    )


@router.post(
    "/vulnerabilities/sync",
    response_model=VulnerabilitySyncRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def queue_vulnerability_sync(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> VulnerabilitySyncRunResponse:
    require_admin(user)
    pending = db.scalar(
        select(VulnerabilitySyncRun)
        .where(
            VulnerabilitySyncRun.tenant_id == user.tenant_id,
            VulnerabilitySyncRun.status.in_(["queued", "running"]),
        )
        .order_by(VulnerabilitySyncRun.created_at.desc())
        .limit(1)
    )
    if pending:
        return sync_response(pending)
    run = VulnerabilitySyncRun(
        tenant_id=user.tenant_id,
        trigger="manual",
        requested_by=user.id,
    )
    db.add(run)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="vulnerability.sync_queued",
            target_type="vulnerability_sync",
            target_id=run.id,
            details={},
        )
    )
    db.commit()
    return sync_response(run)


@router.get("/vulnerabilities/sync-runs", response_model=list[VulnerabilitySyncRunResponse])
def list_sync_runs(
    limit: int = 20,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[VulnerabilitySyncRunResponse]:
    runs = db.scalars(
        select(VulnerabilitySyncRun)
        .where(VulnerabilitySyncRun.tenant_id == user.tenant_id)
        .order_by(VulnerabilitySyncRun.created_at.desc())
        .limit(min(max(limit, 1), 100))
    ).all()
    return [sync_response(run) for run in runs]


@router.post(
    "/vulnerabilities/import",
    response_model=VulnerabilitySnapshotImportResponse,
)
async def upload_vulnerability_snapshot(
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> VulnerabilitySnapshotImportResponse:
    require_admin(user)
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Vulnerability snapshot is too large")
    try:
        snapshot = json.loads(data, parse_constant=reject_json_constant)
        if not isinstance(snapshot, dict):
            raise ValueError("Snapshot root must be a JSON object")
        packages, vulnerabilities, matches = import_snapshot(db, user.tenant_id, snapshot)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    run = VulnerabilitySyncRun(
        tenant_id=user.tenant_id,
        status="succeeded",
        trigger="offline",
        requested_by=user.id,
        packages_queried=packages,
        vulnerabilities_found=vulnerabilities,
        matches_found=matches,
        started_at=now_utc(),
        completed_at=now_utc(),
    )
    db.add(run)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="vulnerability.snapshot_imported",
            target_type="vulnerability_sync",
            target_id=run.id,
            details={"filename": file.filename, "packages": packages, "matches": matches},
        )
    )
    db.commit()
    return VulnerabilitySnapshotImportResponse(
        packages_imported=packages,
        vulnerabilities_found=vulnerabilities,
        matches_found=matches,
    )


@router.get(
    "/applications/vulnerabilities",
    response_model=list[ApplicationVulnerabilityResponse],
)
def application_vulnerabilities(
    name: str,
    kind: str,
    source: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[ApplicationVulnerabilityResponse]:
    rows = db.execute(
        select(HostApplicationVulnerability, Vulnerability, HostApplication, Host)
        .join(
            HostApplicationVulnerability,
            HostApplicationVulnerability.vulnerability_id == Vulnerability.id,
        )
        .join(
            HostApplication,
            HostApplication.id == HostApplicationVulnerability.host_application_id,
        )
        .join(Host, Host.id == HostApplication.host_id)
        .where(
            HostApplicationVulnerability.tenant_id == user.tenant_id,
            HostApplicationVulnerability.resolved_at.is_(None),
            HostApplication.removed_at.is_(None),
            Host.deleted_at.is_(None),
            HostApplication.name == name,
            HostApplication.kind == kind,
            HostApplication.source == source,
        )
    ).all()
    grouped: dict[str, tuple[Vulnerability, set[str], set[str], set[str]]] = {}
    for match, vulnerability, application, host in rows:
        if vulnerability.id not in grouped:
            grouped[vulnerability.id] = (vulnerability, set(), set(), set())
        grouped[vulnerability.id][1].add(host.id)
        if application.version:
            grouped[vulnerability.id][2].add(application.version)
        grouped[vulnerability.id][3].update(match.fixed_versions or [])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    values = sorted(
        grouped.values(),
        key=lambda value: (
            not value[0].known_exploited,
            order.get(value[0].severity, 6),
            value[0].id,
        ),
    )
    return [
        ApplicationVulnerabilityResponse(
            **base_vulnerability_response(
                vulnerability,
                affected_hosts=len(host_ids),
                affected_host_ids=sorted(host_ids),
                affected_versions=sorted(versions),
                fixed_versions=sorted(fixed_versions),
            )
        )
        for vulnerability, host_ids, versions, fixed_versions in values
    ]


@router.get(
    "/hosts/{host_id}/vulnerabilities",
    response_model=list[HostVulnerabilityResponse],
)
def host_vulnerabilities(
    host_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[HostVulnerabilityResponse]:
    host = db.get(Host, host_id)
    if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Host not found")
    rows = db.execute(
        select(HostApplicationVulnerability, Vulnerability, HostApplication)
        .join(
            Vulnerability,
            Vulnerability.id == HostApplicationVulnerability.vulnerability_id,
        )
        .join(
            HostApplication,
            HostApplication.id == HostApplicationVulnerability.host_application_id,
        )
        .where(
            HostApplicationVulnerability.tenant_id == user.tenant_id,
            HostApplicationVulnerability.resolved_at.is_(None),
            HostApplication.host_id == host_id,
            HostApplication.removed_at.is_(None),
        )
    ).all()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    rows.sort(
        key=lambda row: (
            not row[1].known_exploited,
            order.get(row[1].severity, 6),
            row[1].id,
        )
    )
    return [
        HostVulnerabilityResponse(
            **base_vulnerability_response(
                vulnerability,
                affected_hosts=1,
                affected_host_ids=[host_id],
                affected_versions=[application.version] if application.version else [],
                fixed_versions=match.fixed_versions or [],
            ),
            application_id=application.id,
            application_name=application.name,
            installed_version=application.version,
            source_package=application.source_package,
            matched_purl=match.matched_purl,
            detected_at=match.detected_at,
            last_seen_at=match.last_seen_at,
        )
        for match, vulnerability, application in rows
    ]
