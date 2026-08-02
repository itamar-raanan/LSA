from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import Finding, FindingStatus, Host, Report, User
from lsa.schemas import (
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
