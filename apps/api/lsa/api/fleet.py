from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import (
    Finding,
    FindingStatus,
    Host,
    HostApplication,
    HostApplicationVulnerability,
    Report,
    User,
    Vulnerability,
)
from lsa.schemas import (
    ApplicationResponse,
    ApplicationEstateItem,
    ApplicationEstateMetrics,
    ApplicationEstateResponse,
    ApplicationHostCorrelation,
    DashboardResponse,
    FindingDelta,
    FindingResponse,
    HostResponse,
    ReportComparison,
    ReportResponse,
)


router = APIRouter(tags=["fleet"])


def latest_report_ids(db: Session, tenant_id: str) -> list[str]:
    rows = db.execute(
        select(Report.host_id, func.max(Report.generated_at))
        .where(Report.tenant_id == tenant_id)
        .group_by(Report.host_id)
    ).all()
    ids: list[str] = []
    for host_id, generated_at in rows:
        report_id = db.scalar(
            select(Report.id).where(
                Report.host_id == host_id, Report.generated_at == generated_at
            ).limit(1)
        )
        if report_id:
            ids.append(report_id)
    return ids


def serialize_host(db: Session, host: Host) -> HostResponse:
    report_id = db.scalar(
        select(Report.id)
        .where(Report.host_id == host.id)
        .order_by(Report.generated_at.desc())
        .limit(1)
    )
    counts = {severity: 0 for severity in ["critical", "high", "medium", "low", "info"]}
    if report_id:
        rows = db.execute(
            select(Finding.severity, func.count(Finding.id)).where(
                Finding.report_id == report_id,
                Finding.status.in_([FindingStatus.failed, FindingStatus.error]),
            ).group_by(Finding.severity)
        ).all()
        counts.update({severity.value: count for severity, count in rows})
    application_count = db.scalar(
        select(func.count(HostApplication.id)).where(
            HostApplication.host_id == host.id, HostApplication.removed_at.is_(None)
        )
    ) or 0
    return HostResponse(
        id=host.id,
        hostname=host.hostname,
        fqdn=host.fqdn,
        operating_system=host.operating_system,
        os_family=host.os_family,
        os_version=host.os_version,
        kernel=host.kernel,
        architecture=host.architecture,
        ip_addresses=host.ip_addresses or [],
        tags=host.tags or {},
        system_info=host.system_info or {},
        compliance_score=host.compliance_score,
        security_score=host.security_score,
        last_scan_at=host.last_scan_at,
        application_count=application_count,
        finding_counts=counts,
    )


@router.get("/hosts", response_model=list[HostResponse])
def list_hosts(
    search: str | None = None,
    os_family: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[HostResponse]:
    query = select(Host).where(Host.tenant_id == user.tenant_id, Host.deleted_at.is_(None))
    if search:
        query = query.where(Host.hostname.ilike(f"%{search}%"))
    if os_family:
        query = query.where(Host.os_family == os_family)
    hosts = db.scalars(query.order_by(Host.security_score.asc().nulls_last(), Host.hostname)).all()
    return [serialize_host(db, host) for host in hosts]


@router.get("/applications", response_model=ApplicationEstateResponse)
def list_estate_applications(
    search: str | None = None,
    kind: str | None = Query(default=None, pattern="^(package|service)$"),
    limit: int = Query(default=500, ge=1, le=2000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ApplicationEstateResponse:
    active_filters = (
        HostApplication.tenant_id == user.tenant_id,
        HostApplication.removed_at.is_(None),
        Host.deleted_at.is_(None),
    )
    grouped = (
        select(
            HostApplication.kind.label("kind"),
            HostApplication.name.label("name"),
            HostApplication.source.label("source"),
            func.count(func.distinct(HostApplication.version)).label("version_count"),
        )
        .join(Host, Host.id == HostApplication.host_id)
        .where(*active_filters)
        .group_by(HostApplication.kind, HostApplication.name, HostApplication.source)
        .subquery()
    )
    metric_row = db.execute(
        select(
            func.count().label("unique_applications"),
            func.sum(case((grouped.c.kind == "package", 1), else_=0)).label("package_count"),
            func.sum(case((grouped.c.kind == "service", 1), else_=0)).label("service_count"),
            func.sum(case((grouped.c.version_count > 1, 1), else_=0)).label("version_drift_count"),
        ).select_from(grouped)
    ).one()
    installation_count, reporting_hosts = db.execute(
        select(
            func.count(HostApplication.id),
            func.count(func.distinct(HostApplication.host_id)),
        )
        .join(Host, Host.id == HostApplication.host_id)
        .where(*active_filters)
    ).one()

    vulnerability_grouped = (
        select(
            HostApplication.kind.label("kind"),
            HostApplication.name.label("name"),
            HostApplication.source.label("source"),
            func.count(func.distinct(Vulnerability.id)).label("vulnerability_count"),
            func.count(
                func.distinct(case((Vulnerability.known_exploited.is_(True), Vulnerability.id)))
            ).label("known_exploited_count"),
        )
        .join(
            HostApplicationVulnerability,
            HostApplicationVulnerability.host_application_id == HostApplication.id,
        )
        .join(Vulnerability, Vulnerability.id == HostApplicationVulnerability.vulnerability_id)
        .where(
            HostApplication.tenant_id == user.tenant_id,
            HostApplication.removed_at.is_(None),
            HostApplicationVulnerability.resolved_at.is_(None),
        )
        .group_by(HostApplication.kind, HostApplication.name, HostApplication.source)
        .subquery()
    )

    query = (
        select(
            HostApplication.kind,
            HostApplication.name,
            HostApplication.source,
            func.max(HostApplication.publisher).label("publisher"),
            func.max(HostApplication.description).label("description"),
            func.count(func.distinct(HostApplication.host_id)).label("host_count"),
            func.count(func.distinct(HostApplication.version)).label("version_count"),
            func.sum(case((HostApplication.running.is_(True), 1), else_=0)).label("running_host_count"),
            func.sum(case((HostApplication.enabled.is_(True), 1), else_=0)).label("enabled_host_count"),
            func.coalesce(vulnerability_grouped.c.vulnerability_count, 0).label(
                "vulnerability_count"
            ),
            func.coalesce(vulnerability_grouped.c.known_exploited_count, 0).label(
                "known_exploited_count"
            ),
            func.min(HostApplication.first_seen_at).label("first_seen_at"),
            func.max(HostApplication.last_seen_at).label("last_seen_at"),
        )
        .join(Host, Host.id == HostApplication.host_id)
        .outerjoin(
            vulnerability_grouped,
            (vulnerability_grouped.c.kind == HostApplication.kind)
            & (vulnerability_grouped.c.name == HostApplication.name)
            & (vulnerability_grouped.c.source == HostApplication.source),
        )
        .where(*active_filters)
    )
    if kind:
        query = query.where(HostApplication.kind == kind)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                HostApplication.name.ilike(pattern),
                HostApplication.source_package.ilike(pattern),
                HostApplication.version.ilike(pattern),
                HostApplication.publisher.ilike(pattern),
                HostApplication.description.ilike(pattern),
            )
        )
    query = query.group_by(
        HostApplication.kind,
        HostApplication.name,
        HostApplication.source,
        vulnerability_grouped.c.vulnerability_count,
        vulnerability_grouped.c.known_exploited_count,
    ).order_by(func.count(func.distinct(HostApplication.host_id)).desc(), HostApplication.name).limit(limit)
    applications = [
        ApplicationEstateItem(
            kind=row.kind,
            name=row.name,
            source=row.source,
            publisher=row.publisher,
            description=row.description,
            host_count=row.host_count,
            version_count=row.version_count,
            running_host_count=row.running_host_count or 0,
            enabled_host_count=row.enabled_host_count or 0,
            vulnerability_count=row.vulnerability_count or 0,
            known_exploited_count=row.known_exploited_count or 0,
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        )
        for row in db.execute(query)
    ]
    return ApplicationEstateResponse(
        metrics=ApplicationEstateMetrics(
            unique_applications=metric_row.unique_applications or 0,
            package_count=metric_row.package_count or 0,
            service_count=metric_row.service_count or 0,
            installation_count=installation_count or 0,
            reporting_hosts=reporting_hosts or 0,
            version_drift_count=metric_row.version_drift_count or 0,
        ),
        applications=applications,
    )


@router.get("/applications/correlation", response_model=list[ApplicationHostCorrelation])
def application_host_correlation(
    name: str = Query(min_length=1, max_length=300),
    kind: str = Query(pattern="^(package|service)$"),
    source: str = Query(pattern="^(dpkg|rpm|systemd)$"),
    limit: int = Query(default=2000, ge=1, le=10000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[ApplicationHostCorrelation]:
    rows = db.execute(
        select(HostApplication, Host)
        .join(Host, Host.id == HostApplication.host_id)
        .where(
            HostApplication.tenant_id == user.tenant_id,
            HostApplication.removed_at.is_(None),
            Host.deleted_at.is_(None),
            HostApplication.name == name,
            HostApplication.kind == kind,
            HostApplication.source == source,
        )
        .order_by(HostApplication.version, Host.hostname)
        .limit(limit)
    ).all()
    return [
        ApplicationHostCorrelation(
            application_id=application.id,
            host_id=host.id,
            hostname=host.hostname,
            fqdn=host.fqdn,
            os_family=host.os_family,
            os_version=host.os_version,
            environment=(host.tags or {}).get("environment"),
            security_score=host.security_score,
            compliance_score=host.compliance_score,
            version=application.version,
            architecture=application.architecture,
            status=application.status,
            enabled=application.enabled,
            running=application.running,
            first_seen_at=application.first_seen_at,
            last_seen_at=application.last_seen_at,
        )
        for application, host in rows
    ]


@router.get("/hosts/{host_id}", response_model=HostResponse)
def get_host(
    host_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> HostResponse:
    host = db.get(Host, host_id)
    if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Host not found")
    return serialize_host(db, host)


@router.get("/hosts/{host_id}/applications", response_model=list[ApplicationResponse])
def list_host_applications(
    host_id: str,
    search: str | None = None,
    kind: str | None = Query(default=None, pattern="^(package|service)$"),
    include_removed: bool = False,
    limit: int = Query(default=5000, ge=1, le=20000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[ApplicationResponse]:
    host = db.get(Host, host_id)
    if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Host not found")
    query = select(HostApplication).where(HostApplication.host_id == host_id)
    if not include_removed:
        query = query.where(HostApplication.removed_at.is_(None))
    if kind:
        query = query.where(HostApplication.kind == kind)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                HostApplication.name.ilike(pattern),
                HostApplication.source_package.ilike(pattern),
                HostApplication.version.ilike(pattern),
            )
        )
    applications = db.scalars(
        query.order_by(HostApplication.kind, HostApplication.name, HostApplication.version).limit(limit)
    ).all()
    return [
        ApplicationResponse(
            id=item.id,
            host_id=item.host_id,
            kind=item.kind,
            name=item.name,
            version=item.version,
            architecture=item.architecture,
            source=item.source,
            source_package=item.source_package,
            source_version=item.source_version,
            purl=item.purl,
            publisher=item.publisher,
            description=item.description,
            status=item.status,
            enabled=item.enabled,
            running=item.running,
            first_seen_at=item.first_seen_at,
            last_seen_at=item.last_seen_at,
            removed_at=item.removed_at,
        )
        for item in applications
    ]


def serialize_report(db: Session, report: Report) -> ReportResponse:
    counts = {severity: 0 for severity in ["critical", "high", "medium", "low", "info"]}
    rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(
            Finding.report_id == report.id,
            Finding.status.in_([FindingStatus.failed, FindingStatus.error]),
        )
        .group_by(Finding.severity)
    ).all()
    counts.update({severity.value: count for severity, count in rows})
    return ReportResponse(
        id=report.id,
        host_id=report.host_id,
        generated_at=report.generated_at,
        received_at=report.received_at,
        scanner_version=report.scanner_version,
        profile=report.profile,
        modules=report.modules,
        summary=report.summary,
        compliance_score=report.compliance_score,
        security_score=report.security_score,
        artifact_name=report.artifact_name,
        artifact_size_bytes=report.artifact_size_bytes,
        artifact_stored_at=report.artifact_stored_at,
        artifact_retention_until=report.artifact_retention_until,
        artifact_available=(
            report.artifact_object_key is not None and report.artifact_deleted_at is None
        ),
        signing_key_id=report.signing_key_id,
        signature_verified=report.signature_verified,
        finding_counts=counts,
    )


@router.get("/hosts/{host_id}/reports", response_model=list[ReportResponse])
def list_host_reports(
    host_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[ReportResponse]:
    host = db.get(Host, host_id)
    if host is None or host.tenant_id != user.tenant_id or host.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Host not found")
    reports = db.scalars(
        select(Report)
        .where(Report.host_id == host_id)
        .order_by(Report.generated_at.desc())
        .limit(limit)
    ).all()
    return [serialize_report(db, report) for report in reports]


def delta(finding: Finding) -> FindingDelta:
    return FindingDelta(
        control_id=finding.control_id,
        title=finding.title,
        severity=finding.severity.value,
    )


@router.get("/reports/{report_id}/compare", response_model=ReportComparison)
def compare_report(
    report_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ReportComparison:
    report = db.get(Report, report_id)
    if report is None or report.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Report not found")
    previous = db.scalar(
        select(Report)
        .where(Report.host_id == report.host_id, Report.generated_at < report.generated_at)
        .order_by(Report.generated_at.desc())
        .limit(1)
    )
    current_findings = {
        finding.control_id: finding
        for finding in report.findings
        if finding.status in {FindingStatus.failed, FindingStatus.error}
    }
    previous_findings = {
        finding.control_id: finding
        for finding in (previous.findings if previous else [])
        if finding.status in {FindingStatus.failed, FindingStatus.error}
    }
    current_ids = set(current_findings)
    previous_ids = set(previous_findings)
    return ReportComparison(
        current_report_id=report.id,
        previous_report_id=previous.id if previous else None,
        new=[delta(current_findings[item]) for item in sorted(current_ids - previous_ids)],
        persistent=[delta(current_findings[item]) for item in sorted(current_ids & previous_ids)],
        resolved=[delta(previous_findings[item]) for item in sorted(previous_ids - current_ids)],
    )


@router.get("/findings", response_model=list[FindingResponse])
def list_findings(
    severity: str | None = None,
    lifecycle: str | None = None,
    host_id: str | None = None,
    category: str | None = None,
    limit: int = Query(default=1000, ge=1, le=5000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[FindingResponse]:
    report_ids = latest_report_ids(db, user.tenant_id)
    if not report_ids:
        return []
    query = (
        select(Finding, Host.hostname)
        .join(Host, Host.id == Finding.host_id)
        .where(
            Finding.report_id.in_(report_ids),
            Finding.status.in_([FindingStatus.failed, FindingStatus.error, FindingStatus.manual]),
            Host.deleted_at.is_(None),
        )
    )
    if severity:
        query = query.where(Finding.severity == severity)
    if lifecycle:
        query = query.where(Finding.lifecycle == lifecycle)
    if host_id:
        query = query.where(Finding.host_id == host_id)
    if category:
        query = query.where(Finding.category == category)
    rows = db.execute(query.order_by(Finding.severity, Finding.control_id).limit(limit)).all()
    return [
        FindingResponse(
            id=finding.id,
            host_id=finding.host_id,
            hostname=hostname,
            report_id=finding.report_id,
            control_id=finding.control_id,
            module=finding.module,
            category=finding.category,
            title=finding.title,
            severity=finding.severity.value,
            status=finding.status.value,
            lifecycle=finding.lifecycle,
            expected=finding.expected,
            actual=finding.actual,
            remediation_summary=finding.remediation_summary,
            remediation_commands=finding.remediation_commands or [],
            reboot_required=finding.reboot_required,
        )
        for finding, hostname in rows
    ]


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    hosts = db.scalars(
        select(Host).where(Host.tenant_id == user.tenant_id, Host.deleted_at.is_(None))
    ).all()
    serialized = [serialize_host(db, host) for host in hosts]
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(days=7)
    finding_counts = Counter({severity: 0 for severity in ["critical", "high", "medium", "low"]})
    os_distribution: Counter[str] = Counter()
    for host in serialized:
        os_distribution[host.os_family] += 1
        finding_counts.update(host.finding_counts)
    security_scores = [host.security_score for host in hosts if host.security_score is not None]
    compliance_scores = [host.compliance_score for host in hosts if host.compliance_score is not None]
    critical_hosts = sum(host.finding_counts["critical"] > 0 for host in serialized)
    healthy_hosts = sum((host.security_score or 0) >= 90 for host in serialized)
    return DashboardResponse(
        total_hosts=len(hosts),
        healthy_hosts=healthy_hosts,
        at_risk_hosts=max(0, len(hosts) - healthy_hosts - critical_hosts),
        critical_hosts=critical_hosts,
        stale_hosts=sum(
            host.last_scan_at is None
            or (host.last_scan_at.replace(tzinfo=UTC) if host.last_scan_at.tzinfo is None else host.last_scan_at)
            < stale_cutoff
            for host in hosts
        ),
        overall_security_score=round(sum(security_scores) / len(security_scores), 1) if security_scores else 0,
        compliance_score=round(sum(compliance_scores) / len(compliance_scores), 1) if compliance_scores else 0,
        finding_counts=dict(finding_counts),
        os_distribution=dict(os_distribution),
        highest_risk_hosts=sorted(
            serialized, key=lambda item: item.security_score if item.security_score is not None else -1
        )[:5],
    )
