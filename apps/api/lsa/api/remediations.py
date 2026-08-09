import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from lsa.api.admin import require_admin
from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import AuditEvent, Finding, FindingStatus, Host, RemediationPlan, Report, User, now_utc
from lsa.schemas import RemediationPlanCreate, RemediationPlanDecision, RemediationPlanResponse


router = APIRouter(prefix="/remediation-plans", tags=["remediation planning"])
ACTIVE_PLAN_STATUSES = ("pending_approval", "approved")
OPEN_FINDING_STATUSES = (FindingStatus.failed, FindingStatus.error, FindingStatus.manual)
PATH_PATTERN = re.compile(r"(?<![A-Za-z0-9_.-])(/[A-Za-z0-9_.@+:-]+(?:/[A-Za-z0-9_.@+:-]+)+)")


def _latest_report_id(db: Session, tenant_id: str, host_id: str) -> str | None:
    return db.scalar(
        select(Report.id)
        .where(Report.tenant_id == tenant_id, Report.host_id == host_id)
        .order_by(Report.generated_at.desc(), Report.received_at.desc(), Report.id.desc())
        .limit(1)
    )


def _finding_for_plan(db: Session, user: User, finding_id: str) -> tuple[Finding, Host]:
    row = db.execute(
        select(Finding, Host)
        .join(Host, Host.id == Finding.host_id)
        .where(
            Finding.id == finding_id,
            Finding.tenant_id == user.tenant_id,
            Host.tenant_id == user.tenant_id,
            Host.deleted_at.is_(None),
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, host = row
    if finding.report_id != _latest_report_id(db, user.tenant_id, finding.host_id):
        raise HTTPException(status_code=409, detail="Only a finding from the host's latest report can be planned")
    if finding.status not in OPEN_FINDING_STATUSES:
        raise HTTPException(status_code=409, detail="Only an open finding can be planned")
    return finding, host


def _plan_for_user(db: Session, user: User, plan_id: str, *, lock: bool = False) -> RemediationPlan:
    query = select(RemediationPlan).where(
        RemediationPlan.id == plan_id, RemediationPlan.tenant_id == user.tenant_id
    )
    if lock:
        query = query.with_for_update()
    plan = db.scalar(query)
    if plan is None:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return plan


def _user_name(db: Session, user_id: str | None) -> str | None:
    if user_id is None:
        return None
    user = db.get(User, user_id)
    return user.display_name if user is not None else "Unknown user"


def _serialize(db: Session, plan: RemediationPlan) -> RemediationPlanResponse:
    host = db.get(Host, plan.host_id)
    latest_report_id = _latest_report_id(db, plan.tenant_id, plan.host_id)
    current_finding = db.scalar(
        select(Finding).where(
            Finding.tenant_id == plan.tenant_id,
            Finding.report_id == latest_report_id,
            Finding.control_id == plan.control_id,
            Finding.status.in_(OPEN_FINDING_STATUSES),
        )
    ) if latest_report_id is not None else None
    return RemediationPlanResponse(
        id=plan.id,
        finding_id=plan.finding_id,
        host_id=plan.host_id,
        hostname=host.hostname if host is not None else "Deleted host",
        report_id=plan.report_id,
        control_id=plan.control_id,
        title=plan.title,
        category=plan.category,
        severity=plan.severity,
        current_state=plan.current_state,
        required_state=plan.required_state,
        remediation_summary=plan.remediation_summary,
        affected_paths=plan.affected_paths or [],
        reboot_required=plan.reboot_required,
        service_restart=plan.service_restart,
        rationale=plan.rationale,
        status=plan.status,
        version=plan.version,
        requested_by=plan.requested_by,
        requested_by_name=_user_name(db, plan.requested_by) or "Unknown user",
        requested_at=plan.requested_at,
        approved_by=plan.approved_by,
        approved_by_name=_user_name(db, plan.approved_by),
        approved_at=plan.approved_at,
        rejected_by=plan.rejected_by,
        rejected_by_name=_user_name(db, plan.rejected_by),
        rejected_at=plan.rejected_at,
        rejection_reason=plan.rejection_reason,
        canceled_by=plan.canceled_by,
        canceled_by_name=_user_name(db, plan.canceled_by),
        canceled_at=plan.canceled_at,
        cancellation_reason=plan.cancellation_reason,
        source_is_current=plan.report_id == latest_report_id,
        finding_still_open=current_finding is not None,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


def _audit(db: Session, user: User, plan: RemediationPlan, action: str, details: dict[str, object]) -> None:
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action=action,
            target_type="remediation_plan",
            target_id=plan.id,
            details={"control_id": plan.control_id, "host_id": plan.host_id, **details},
        )
    )


def _extract_paths(finding: Finding) -> list[str]:
    values = [
        finding.actual or "",
        finding.expected or "",
        finding.remediation_summary or "",
        *(finding.evidence or []),
    ]
    return sorted({match.rstrip(".,;:") for value in values for match in PATH_PATTERN.findall(value)})


@router.get("", response_model=list[RemediationPlanResponse])
def list_remediation_plans(
    plan_status: Literal["pending_approval", "approved", "rejected", "canceled"] | None = Query(default=None, alias="status"),
    host_id: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[RemediationPlanResponse]:
    query = select(RemediationPlan).where(RemediationPlan.tenant_id == user.tenant_id)
    if plan_status is not None:
        query = query.where(RemediationPlan.status == plan_status)
    if host_id is not None:
        query = query.where(RemediationPlan.host_id == host_id)
    plans = db.scalars(query.order_by(RemediationPlan.created_at.desc())).all()
    return [_serialize(db, plan) for plan in plans]


@router.post("", response_model=RemediationPlanResponse, status_code=status.HTTP_201_CREATED)
def create_remediation_plan(
    request: RemediationPlanCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationPlanResponse:
    require_admin(user)
    finding, _ = _finding_for_plan(db, user, request.finding_id)
    duplicate = db.scalar(
        select(RemediationPlan).where(
            RemediationPlan.tenant_id == user.tenant_id,
            RemediationPlan.finding_id == finding.id,
            RemediationPlan.status.in_(ACTIVE_PLAN_STATUSES),
        )
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="An active remediation plan already exists for this finding")
    plan = RemediationPlan(
        tenant_id=user.tenant_id,
        finding_id=finding.id,
        active_finding_id=finding.id,
        host_id=finding.host_id,
        report_id=finding.report_id,
        control_id=finding.control_id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity.value,
        current_state=finding.actual,
        required_state=finding.expected,
        remediation_summary=finding.remediation_summary or "Review the control guidance and document the intended configuration change.",
        affected_paths=_extract_paths(finding),
        reboot_required=finding.reboot_required,
        service_restart=finding.service_restart,
        rationale=request.rationale,
        requested_by=user.id,
    )
    db.add(plan)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An active remediation plan already exists for this finding",
        ) from exc
    _audit(db, user, plan, "remediation_plan.requested", {"execution_enabled": False})
    db.commit()
    return _serialize(db, plan)


@router.get("/{plan_id}", response_model=RemediationPlanResponse)
def get_remediation_plan(
    plan_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationPlanResponse:
    return _serialize(db, _plan_for_user(db, user, plan_id))


@router.post("/{plan_id}/approve", response_model=RemediationPlanResponse)
def approve_remediation_plan(
    plan_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationPlanResponse:
    require_admin(user)
    plan = _plan_for_user(db, user, plan_id, lock=True)
    if plan.status != "pending_approval":
        raise HTTPException(status_code=409, detail="Only a pending plan can be approved")
    if plan.report_id != _latest_report_id(db, user.tenant_id, plan.host_id):
        raise HTTPException(status_code=409, detail="The source finding is stale; create a plan from the latest report")
    plan.status = "approved"
    plan.approved_by = user.id
    plan.approved_at = now_utc()
    plan.updated_at = plan.approved_at
    plan.version += 1
    _audit(db, user, plan, "remediation_plan.approved", {"version": plan.version, "execution_enabled": False})
    db.commit()
    return _serialize(db, plan)


@router.post("/{plan_id}/reject", response_model=RemediationPlanResponse)
def reject_remediation_plan(
    plan_id: str,
    request: RemediationPlanDecision,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationPlanResponse:
    require_admin(user)
    plan = _plan_for_user(db, user, plan_id, lock=True)
    if plan.status != "pending_approval":
        raise HTTPException(status_code=409, detail="Only a pending plan can be rejected")
    plan.status = "rejected"
    plan.active_finding_id = None
    plan.rejected_by = user.id
    plan.rejected_at = now_utc()
    plan.rejection_reason = request.reason
    plan.updated_at = plan.rejected_at
    plan.version += 1
    _audit(db, user, plan, "remediation_plan.rejected", {"version": plan.version, "reason": request.reason})
    db.commit()
    return _serialize(db, plan)


@router.post("/{plan_id}/cancel", response_model=RemediationPlanResponse)
def cancel_remediation_plan(
    plan_id: str,
    request: RemediationPlanDecision,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationPlanResponse:
    require_admin(user)
    plan = _plan_for_user(db, user, plan_id, lock=True)
    if plan.status not in ACTIVE_PLAN_STATUSES:
        raise HTTPException(status_code=409, detail="Only a pending or approved plan can be canceled")
    plan.status = "canceled"
    plan.active_finding_id = None
    plan.canceled_by = user.id
    plan.canceled_at = now_utc()
    plan.cancellation_reason = request.reason
    plan.updated_at = plan.canceled_at
    plan.version += 1
    _audit(db, user, plan, "remediation_plan.canceled", {"version": plan.version, "reason": request.reason})
    db.commit()
    return _serialize(db, plan)
