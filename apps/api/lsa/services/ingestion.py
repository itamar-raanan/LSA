from hashlib import sha256

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.dependencies import IngestionPrincipal
from lsa.models import AuditEvent, Finding, FindingStatus, Host, Report, Severity
from lsa.schemas import IngestResponse, ReportInput


SEVERITY_PENALTY = {"critical": 18, "high": 8, "medium": 3, "low": 1, "info": 0}


def calculate_scores(report: ReportInput) -> tuple[float, float]:
    summary = report.summary
    evaluated = summary.pass_count + summary.fail + summary.error
    compliance = summary.compliance_score
    if compliance is None:
        compliance = 100.0 if evaluated == 0 else round(summary.pass_count / evaluated * 100, 1)
    security = summary.security_score
    if security is None:
        penalty = sum(
            SEVERITY_PENALTY[finding.severity]
            for finding in report.findings
            if finding.status in {"fail", "error"}
        )
        security = max(0.0, round(100 - min(penalty, 100), 1))
    return compliance, security


def ingest_report(
    db: Session,
    report_data: ReportInput,
    principal: IngestionPrincipal,
    artifact_name: str | None = None,
    artifact_bytes: bytes | None = None,
) -> IngestResponse:
    report_id = str(report_data.report_id)
    host_id = str(report_data.host.host_id)
    if db.get(Report, report_id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Report already imported")
    if principal.host_id and principal.host_id != host_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token cannot submit for this host")

    host = db.get(Host, host_id)
    if host is not None and host.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Host belongs to another tenant")
    if host is None:
        host = Host(
            id=host_id,
            tenant_id=principal.tenant_id,
            hostname=report_data.host.hostname,
            fqdn=report_data.host.fqdn,
            machine_id_hash=report_data.host.machine_id_hash,
            operating_system=report_data.host.operating_system,
            os_family=report_data.host.os_family,
            os_version=report_data.host.os_version,
            kernel=report_data.host.kernel,
            architecture=report_data.host.architecture,
            ip_addresses=report_data.host.ip_addresses,
            tags=report_data.host.tags,
        )
        db.add(host)
    elif host.machine_id_hash.startswith("pending:"):
        host.machine_id_hash = report_data.host.machine_id_hash
    elif host.machine_id_hash != report_data.host.machine_id_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Machine identity does not match the enrolled host",
        )

    previous = db.scalar(
        select(Report)
        .where(Report.host_id == host.id)
        .order_by(Report.generated_at.desc())
        .limit(1)
    )
    previous_failed = {
        finding.control_id
        for finding in (previous.findings if previous else [])
        if finding.status in {FindingStatus.failed, FindingStatus.error}
    }
    current_failed = {
        finding.control_id
        for finding in report_data.findings
        if finding.status in {"fail", "error"}
    }
    compliance, security_score = calculate_scores(report_data)
    report = Report(
        id=report_id,
        tenant_id=principal.tenant_id,
        host_id=host.id,
        generated_at=report_data.generated_at,
        schema_version=report_data.schema_version,
        scanner_name=report_data.scanner.name,
        scanner_version=report_data.scanner.version,
        profile=report_data.scan.profile,
        modules=report_data.scan.modules,
        summary=report_data.summary.model_dump(by_alias=True),
        compliance_score=compliance,
        security_score=security_score,
        artifact_name=artifact_name,
        checksum=sha256(artifact_bytes).hexdigest() if artifact_bytes else None,
    )
    db.add(report)

    for item in report_data.findings:
        lifecycle = "persistent" if item.control_id in previous_failed else "new"
        if item.status == "pass":
            lifecycle = "resolved" if item.control_id in previous_failed else "clear"
        db.add(
            Finding(
                tenant_id=principal.tenant_id,
                host_id=host.id,
                report_id=report.id,
                control_id=item.control_id,
                module=item.module,
                category=item.category,
                title=item.title,
                severity=Severity(item.severity),
                status=FindingStatus(item.status),
                lifecycle=lifecycle,
                expected=item.expected,
                actual=item.actual,
                evidence=item.evidence,
                remediation_summary=item.remediation_summary,
                remediation_commands=item.remediation_commands,
                verification_commands=item.verification_commands,
                reboot_required=item.reboot_required,
                service_restart=item.service_restart,
            )
        )

    host.hostname = report_data.host.hostname
    host.fqdn = report_data.host.fqdn
    host.operating_system = report_data.host.operating_system
    host.os_family = report_data.host.os_family
    host.os_version = report_data.host.os_version
    host.kernel = report_data.host.kernel
    host.architecture = report_data.host.architecture
    host.ip_addresses = report_data.host.ip_addresses
    host.tags = report_data.host.tags
    host.compliance_score = compliance
    host.security_score = security_score
    host.last_scan_at = report_data.generated_at
    db.add(
        AuditEvent(
            tenant_id=principal.tenant_id,
            actor_type="ingestion_token",
            actor_id=principal.token_id,
            action="report.accepted",
            target_type="report",
            target_id=report.id,
            details={"host_id": host.id, "finding_count": len(report_data.findings)},
        )
    )
    db.commit()
    return IngestResponse(
        report_id=report.id,
        host_id=host.id,
        findings_imported=len(report_data.findings),
        new_findings=len(current_failed - previous_failed),
        resolved_findings=len(previous_failed - current_failed),
    )
