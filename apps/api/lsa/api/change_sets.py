from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from lsa.api.admin import require_admin
from lsa.api.remediations import _latest_report_id, _stored_action
from lsa.database import get_db
from lsa.dependencies import current_user
from lsa.models import (
    AgentGroup,
    AgentPolicy,
    AgentPolicyVersion,
    AuditEvent,
    Host,
    LinuxAgent,
    PlatformChangeSigningKey,
    PlatformCommandSigningKey,
    RemediationChangeSet,
    RemediationChangeSetPlan,
    RemediationChangeSetTarget,
    RemediationPlan,
    RemediationValidationJob,
    Report,
    User,
    now_utc,
    uuid_string,
)
from lsa.schemas import (
    RemediationChangeSetCreate,
    RemediationChangeSetDecision,
    RemediationChangeSetGate,
    RemediationChangeSetPlanResponse,
    RemediationChangeSetResponse,
    RemediationChangeSetTargetResponse,
    RemediationExecutionContractPreview,
    RemediationValidationJobCreate,
    RemediationValidationJobResponse,
)
from lsa.services.change_set_signing import (
    active_change_signing_key,
    payload_digest,
    sign_change_set,
    verify_change_set_signature,
)
from lsa.services.remediation_catalog import RemediationCatalogError
from lsa.services.remediation_execution_contract import (
    build_validation_contract,
    validation_contract_digest,
)


router = APIRouter(prefix="/remediation-change-sets", tags=["remediation change sets"])
ACTIVE_STATUSES = ("pending_authorization", "authorized")
REMEDIATION_CONTRACT_VALIDATION_CAPABILITY = "remediation-contract-validation-v1"
REMEDIATION_DRY_RUN_CAPABILITY = "remediation-dry-run-v1"
DEFAULT_LIMITS = {
    "remediation_four_eyes": True,
    "remediation_required_capability": "signed-change-set-planning-v1",
    "remediation_max_evidence_age_minutes": 1440,
    "remediation_max_agent_attestation_age_minutes": 15,
    "remediation_max_targets_per_change_set": 25,
    "remediation_max_canary_hosts": 3,
    "remediation_max_batch_hosts": 5,
    "remediation_min_batch_interval_minutes": 15,
}


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=now_utc().tzinfo)
    return value


def _user_name(db: Session, user_id: str | None) -> str | None:
    if user_id is None:
        return None
    user = db.get(User, user_id)
    return user.display_name if user is not None else "Unknown User"


def _latest_policy_version(db: Session, policy_id: str) -> AgentPolicyVersion | None:
    return db.scalar(
        select(AgentPolicyVersion)
        .where(AgentPolicyVersion.policy_id == policy_id)
        .order_by(AgentPolicyVersion.version.desc())
    )


def _policy_limits(version: AgentPolicyVersion) -> dict[str, object]:
    return {**DEFAULT_LIMITS, **(version.settings or {})}


def _gate(code: str, passed: bool, detail: str) -> RemediationChangeSetGate:
    return RemediationChangeSetGate(
        code=code,
        status="passed" if passed else "blocked",
        detail=detail,
    )


def _change_set(
    db: Session, user: User, change_set_id: str, *, lock: bool = False
) -> RemediationChangeSet:
    query = select(RemediationChangeSet).where(
        RemediationChangeSet.id == change_set_id,
        RemediationChangeSet.tenant_id == user.tenant_id,
    )
    if lock:
        query = query.with_for_update()
    change_set = db.scalar(query)
    if change_set is None:
        raise HTTPException(status_code=404, detail="Remediation change set not found")
    return change_set


def _links(db: Session, change_set: RemediationChangeSet):
    plan_links = db.scalars(
        select(RemediationChangeSetPlan)
        .where(RemediationChangeSetPlan.change_set_id == change_set.id)
        .order_by(RemediationChangeSetPlan.created_at, RemediationChangeSetPlan.id)
    ).all()
    target_links = db.scalars(
        select(RemediationChangeSetTarget)
        .where(RemediationChangeSetTarget.change_set_id == change_set.id)
        .order_by(RemediationChangeSetTarget.rollout_phase, RemediationChangeSetTarget.host_id)
    ).all()
    return plan_links, target_links


def _envelope_operational_values(change_set: RemediationChangeSet):
    try:
        window = change_set.payload["maintenance_window"]
        rollout = change_set.payload["rollout"]
        start = _aware(datetime.fromisoformat(str(window["start"]).replace("Z", "+00:00")))
        end = _aware(datetime.fromisoformat(str(window["end"]).replace("Z", "+00:00")))
        batch_size = int(rollout["batch_size"])
        batch_interval = int(rollout["batch_interval_minutes"])
        if rollout["strategy"] != "canary":
            raise ValueError
        return start, end, batch_size, batch_interval
    except (KeyError, TypeError, ValueError) as exc:
        raise RemediationCatalogError(
            "Remediation change-set operational envelope is malformed"
        ) from exc


def _envelope_records(
    change_set: RemediationChangeSet, key: Literal["plans", "targets"]
) -> list[dict[str, object]]:
    records = change_set.payload.get(key)
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise RemediationCatalogError(f"Remediation change-set {key} envelope is malformed")
    return records


def _assert_envelope_integrity(db: Session, change_set: RemediationChangeSet) -> None:
    if payload_digest(change_set.payload) != change_set.digest:
        raise RemediationCatalogError("Remediation change-set payload digest does not match")
    safeguards = change_set.payload.get("safeguards", {})
    if (
        not isinstance(safeguards, dict)
        or change_set.payload.get("schema_version") != change_set.payload_schema_version
        or change_set.payload.get("change_set_id") != change_set.id
        or change_set.payload.get("tenant_id") != change_set.tenant_id
        or safeguards.get("execution_enabled") is not False
        or safeguards.get("four_eyes_required") is not True
        or safeguards.get("post_change_verification_required") is not True
        or safeguards.get("rollback_checkpoint_required") is not True
    ):
        raise RemediationCatalogError(
            "Remediation change-set identity or safety invariants do not match the envelope"
        )
    start, end, batch_size, batch_interval = _envelope_operational_values(change_set)
    if (
        start != _aware(change_set.maintenance_window_start)
        or end != _aware(change_set.maintenance_window_end)
        or batch_size != change_set.batch_size
        or batch_interval != change_set.batch_interval_minutes
    ):
        raise RemediationCatalogError(
            "Remediation change-set operational columns do not match the signed envelope"
        )
    plan_links, target_links = _links(db, change_set)
    plan_records = _envelope_records(change_set, "plans")
    target_records = _envelope_records(change_set, "targets")
    payload_plan_ids = [item.get("plan_id") for item in plan_records]
    payload_targets = {
        (item.get("host_id"), item.get("agent_id"), item.get("rollout_phase"))
        for item in target_records
    }
    if sorted(payload_plan_ids) != sorted(link.plan_id for link in plan_links):
        raise RemediationCatalogError(
            "Remediation change-set plan links do not match the signed envelope"
        )
    if payload_targets != {
        (link.host_id, link.agent_id, link.rollout_phase) for link in target_links
    }:
        raise RemediationCatalogError(
            "Remediation change-set targets do not match the signed envelope"
        )
    payload_plans = {item.get("plan_id"): item for item in plan_records}
    for link in plan_links:
        plan = db.get(RemediationPlan, link.plan_id)
        item = payload_plans.get(link.plan_id)
        immutable_state = {
            "plan_id": plan.id if plan else None,
            "host_id": plan.host_id if plan else None,
            "report_id": plan.report_id if plan else None,
            "control_id": plan.control_id if plan else None,
            "action_id": plan.action_id if plan else None,
            "action_version": plan.action_version if plan else None,
            "action_digest": plan.action_digest if plan else None,
        }
        if (
            plan is None
            or item is None
            or any(item.get(key) != value for key, value in immutable_state.items())
        ):
            raise RemediationCatalogError(
                "Remediation change-set plan state does not match the signed envelope"
            )


def _readiness_gates(
    db: Session,
    change_set: RemediationChangeSet,
    authorizer: User | None = None,
) -> list[RemediationChangeSetGate]:
    _assert_envelope_integrity(db, change_set)
    plan_links, target_links = _links(db, change_set)
    plans = [db.get(RemediationPlan, link.plan_id) for link in plan_links]
    targets = [
        (link, db.get(LinuxAgent, link.agent_id), db.get(Host, link.host_id))
        for link in target_links
    ]
    now = now_utc()

    actions_valid = True
    rollbacks_valid = True
    evidence_valid = True
    policy_valid = True
    attestation_valid = True
    approvers: set[str] = set()
    policy_limits: list[dict[str, object]] = []
    payload_targets = {item.get("host_id"): item for item in _envelope_records(change_set, "targets")}

    for plan in plans:
        if plan is None or plan.tenant_id != change_set.tenant_id or plan.status != "approved":
            actions_valid = False
            evidence_valid = False
            continue
        if plan.approved_by:
            approvers.add(plan.approved_by)
        try:
            action = _stored_action(plan)
        except RemediationCatalogError:
            action = None
        if action is None:
            actions_valid = False
            rollbacks_valid = False
        elif not action.rollback or not all(
            operation.kind in {"restore_backup", "service_reload", "sysctl_reload"}
            for operation in action.rollback
        ):
            rollbacks_valid = False

        report = db.get(Report, plan.report_id)
        if report is None or plan.report_id != _latest_report_id(db, plan.tenant_id, plan.host_id):
            evidence_valid = False

    for link, agent, host in targets:
        if agent is None or host is None or agent.revoked_at is not None:
            policy_valid = False
            attestation_valid = False
            continue
        group = db.get(AgentGroup, agent.group_id)
        policy = db.get(AgentPolicy, group.policy_id) if group is not None else None
        version = _latest_policy_version(db, policy.id) if policy is not None else None
        if group is None or policy is None or version is None:
            policy_valid = False
            attestation_valid = False
            continue
        limits = _policy_limits(version)
        policy_limits.append(limits)
        required_capability = str(limits["remediation_required_capability"])
        payload_target = payload_targets.get(link.host_id)
        if payload_target is None or any(
            payload_target.get(key) != value
            for key, value in {
                "agent_id": agent.id,
                "group_id": group.id,
                "policy_id": policy.id,
                "policy_version": version.version,
                "required_capability": required_capability,
            }.items()
        ):
            policy_valid = False
        if required_capability not in (agent.capabilities or []):
            attestation_valid = False
        max_attestation_age = timedelta(
            minutes=int(limits["remediation_max_agent_attestation_age_minutes"])
        )
        if (
            agent.capabilities_attested_at is None
            or now - _aware(agent.capabilities_attested_at) > max_attestation_age
        ):
            attestation_valid = False
        related_plans = [
            plan for plan in plans if plan is not None and plan.host_id == link.host_id
        ]
        for plan in related_plans:
            effective_mode = (version.control_modes or {}).get(
                plan.control_id, version.default_mode.value
            )
            if effective_mode != "remediate" or not bool(limits["remediation_four_eyes"]):
                policy_valid = False
            report = db.get(Report, plan.report_id)
            max_evidence_age = timedelta(
                minutes=int(limits["remediation_max_evidence_age_minutes"])
            )
            if report is None or now - _aware(report.generated_at) > max_evidence_age:
                evidence_valid = False

    max_targets = min(
        (int(item["remediation_max_targets_per_change_set"]) for item in policy_limits), default=0
    )
    max_canaries = min(
        (int(item["remediation_max_canary_hosts"]) for item in policy_limits), default=0
    )
    max_batch = min((int(item["remediation_max_batch_hosts"]) for item in policy_limits), default=0)
    min_interval = max(
        (int(item["remediation_min_batch_interval_minutes"]) for item in policy_limits), default=15
    )
    canary_count = sum(link.rollout_phase == "canary" for link in target_links)
    canary_valid = (
        bool(target_links) and 0 < canary_count <= max_canaries and len(target_links) <= max_targets
    )
    window_start, window_end, batch_size, batch_interval = _envelope_operational_values(change_set)
    rate_valid = batch_size <= max_batch and batch_interval >= min_interval
    window_valid = (
        now < window_start < window_end
        and timedelta(minutes=30) <= window_end - window_start <= timedelta(hours=8)
    )
    four_eyes_valid = False
    if change_set.authorized_by is not None:
        four_eyes_valid = (
            change_set.authorized_by != change_set.requested_by
            and change_set.authorized_by not in approvers
        )
    elif authorizer is not None:
        four_eyes_valid = (
            authorizer.id != change_set.requested_by and authorizer.id not in approvers
        )

    return [
        _gate(
            "action_integrity",
            actions_valid,
            "Every plan is approved and retains its digest-verified catalog action."
            if actions_valid
            else "A plan or catalog action is missing, stale, or no longer approved.",
        ),
        _gate(
            "evidence_freshness",
            evidence_valid,
            "Every plan uses the latest report inside the policy evidence-age limit."
            if evidence_valid
            else "At least one target has stale or superseded evidence.",
        ),
        _gate(
            "policy_authorization",
            policy_valid,
            "Every effective control mode is Remediate and four-eyes governance is enforced."
            if policy_valid
            else "A target policy does not authorize remediation for its control.",
        ),
        _gate(
            "agent_attestation",
            attestation_valid,
            "Every active agent recently attested signed change-set planning support."
            if attestation_valid
            else "An agent is revoked, stale, or has not attested signed change-set planning support.",
        ),
        _gate(
            "canary_scope",
            canary_valid,
            "Canary and total target counts are within the strictest assigned policy."
            if canary_valid
            else "Canary or total target scope exceeds an assigned policy limit.",
        ),
        _gate(
            "rate_limit",
            rate_valid,
            "Batch size and interval are within the strictest assigned policy."
            if rate_valid
            else "Batch size or interval violates an assigned policy limit.",
        ),
        _gate(
            "maintenance_window",
            window_valid,
            "The bounded maintenance window remains valid."
            if window_valid
            else "The maintenance window has started, is reversed, or falls outside the 30-minute to eight-hour boundary.",
        ),
        _gate(
            "rollback_checkpoint",
            rollbacks_valid,
            "Every action includes an explicit reviewed rollback checkpoint."
            if rollbacks_valid
            else "At least one action lacks a reviewed rollback checkpoint.",
        ),
        _gate(
            "four_eyes",
            four_eyes_valid,
            "Authorization was provided by an independent administrator."
            if four_eyes_valid
            else "A different administrator must authorize this change set.",
        ),
    ]


def _serialize(db: Session, change_set: RemediationChangeSet) -> RemediationChangeSetResponse:
    _assert_envelope_integrity(db, change_set)
    plan_links, target_links = _links(db, change_set)
    payload_plans = {item["plan_id"]: item for item in _envelope_records(change_set, "plans")}
    payload_targets = {item["host_id"]: item for item in _envelope_records(change_set, "targets")}
    plans: list[RemediationChangeSetPlanResponse] = []
    for link in plan_links:
        plan = db.get(RemediationPlan, link.plan_id)
        snapshot = payload_plans.get(link.plan_id)
        if (
            plan is None
            or snapshot is None
            or plan.action_id is None
            or plan.action_version is None
            or plan.action_digest is None
            or plan.approved_by is None
        ):
            raise RemediationCatalogError("Remediation change-set plan record is incomplete")
        plans.append(
            RemediationChangeSetPlanResponse(
                plan_id=plan.id,
                hostname=str(snapshot["hostname"]),
                host_id=str(snapshot["host_id"]),
                control_id=str(snapshot["control_id"]),
                title=str(snapshot["title"]),
                action_id=str(snapshot["action_id"]),
                action_version=int(snapshot["action_version"]),
                action_digest=str(snapshot["action_digest"]),
                plan_approved_by=str(snapshot["plan_approved_by"]),
            )
        )

    targets: list[RemediationChangeSetTargetResponse] = []
    for link in target_links:
        agent = db.get(LinuxAgent, link.agent_id)
        snapshot = payload_targets.get(link.host_id)
        if agent is None or snapshot is None:
            raise RemediationCatalogError("Remediation change-set target record is incomplete")
        required_capability = str(snapshot["required_capability"])
        targets.append(
            RemediationChangeSetTargetResponse(
                host_id=str(snapshot["host_id"]),
                hostname=str(snapshot["hostname"]),
                agent_id=str(snapshot["agent_id"]),
                group_id=str(snapshot["group_id"]),
                group_name=str(snapshot["group_name"]),
                policy_id=str(snapshot["policy_id"]),
                policy_name=str(snapshot["policy_name"]),
                policy_version=int(snapshot["policy_version"]),
                rollout_phase=str(snapshot["rollout_phase"]),
                required_capability=required_capability,
                capability_attested=required_capability in (agent.capabilities or []),
            )
        )

    signing_key = (
        db.get(PlatformChangeSigningKey, change_set.signing_key_id)
        if change_set.signing_key_id
        else None
    )
    if change_set.signature is not None and (
        signing_key is None
        or change_set.signature is None
        or not verify_change_set_signature(
            signing_key.public_key,
            change_set.payload,
            change_set.signature,
        )
    ):
        raise RemediationCatalogError("Authorized remediation change-set signature does not verify")
    return RemediationChangeSetResponse(
        id=change_set.id,
        status=change_set.status,
        payload_schema_version=change_set.payload_schema_version,
        payload=change_set.payload,
        digest=change_set.digest,
        signature=change_set.signature,
        signing_key_id=signing_key.id if signing_key else None,
        signing_key_fingerprint=signing_key.fingerprint if signing_key else None,
        signing_public_key=signing_key.public_key if signing_key else None,
        maintenance_window_start=change_set.maintenance_window_start,
        maintenance_window_end=change_set.maintenance_window_end,
        batch_size=change_set.batch_size,
        batch_interval_minutes=change_set.batch_interval_minutes,
        plans=plans,
        targets=targets,
        gates=_readiness_gates(db, change_set),
        requested_by=change_set.requested_by,
        requested_by_name=_user_name(db, change_set.requested_by) or "Unknown User",
        requested_at=change_set.requested_at,
        authorized_by=change_set.authorized_by,
        authorized_by_name=_user_name(db, change_set.authorized_by),
        authorized_at=change_set.authorized_at,
        canceled_by=change_set.canceled_by,
        canceled_by_name=_user_name(db, change_set.canceled_by),
        canceled_at=change_set.canceled_at,
        cancellation_reason=change_set.cancellation_reason,
        created_at=change_set.created_at,
        updated_at=change_set.updated_at,
    )


@router.get("", response_model=list[RemediationChangeSetResponse])
def list_change_sets(
    change_set_status: Literal["pending_authorization", "authorized", "canceled"] | None = Query(
        default=None, alias="status"
    ),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[RemediationChangeSetResponse]:
    query = select(RemediationChangeSet).where(RemediationChangeSet.tenant_id == user.tenant_id)
    if change_set_status is not None:
        query = query.where(RemediationChangeSet.status == change_set_status)
    change_sets = db.scalars(query.order_by(RemediationChangeSet.created_at.desc())).all()
    return [_serialize(db, item) for item in change_sets]


@router.post("", response_model=RemediationChangeSetResponse, status_code=status.HTTP_201_CREATED)
def create_change_set(
    request: RemediationChangeSetCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationChangeSetResponse:
    require_admin(user)
    plan_ids = list(dict.fromkeys(request.plan_ids))
    canary_host_ids = list(dict.fromkeys(request.canary_host_ids))
    if len(plan_ids) != len(request.plan_ids) or len(canary_host_ids) != len(
        request.canary_host_ids
    ):
        raise HTTPException(status_code=422, detail="Plan and canary identifiers must be unique")
    start = _aware(request.maintenance_window_start)
    end = _aware(request.maintenance_window_end)
    now = now_utc()
    if start < now or start > now + timedelta(days=30):
        raise HTTPException(
            status_code=422, detail="Maintenance window must begin within the next 30 days"
        )
    if end <= start or end - start < timedelta(minutes=30) or end - start > timedelta(hours=8):
        raise HTTPException(
            status_code=422, detail="Maintenance window must last between 30 minutes and 8 hours"
        )

    plans = db.scalars(
        select(RemediationPlan).where(
            RemediationPlan.tenant_id == user.tenant_id,
            RemediationPlan.id.in_(plan_ids),
        ).order_by(RemediationPlan.id).with_for_update()
    ).all()
    if len(plans) != len(plan_ids):
        raise HTTPException(status_code=404, detail="One or more remediation plans were not found")
    if any(plan.status != "approved" for plan in plans):
        raise HTTPException(status_code=409, detail="Every remediation plan must be approved")
    if any(_stored_action(plan) is None for plan in plans):
        raise HTTPException(
            status_code=409, detail="Every remediation plan must contain a reviewed catalog action"
        )
    existing = db.scalar(
        select(RemediationChangeSetPlan)
        .join(
            RemediationChangeSet, RemediationChangeSet.id == RemediationChangeSetPlan.change_set_id
        )
        .where(
            RemediationChangeSetPlan.plan_id.in_(plan_ids),
            RemediationChangeSet.status.in_(ACTIVE_STATUSES),
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=409, detail="A plan already belongs to an active remediation change set"
        )

    host_ids = sorted({plan.host_id for plan in plans})
    if not set(canary_host_ids) <= set(host_ids):
        raise HTTPException(
            status_code=422, detail="Canary hosts must belong to the selected plans"
        )
    agents = db.scalars(
        select(LinuxAgent).where(
            LinuxAgent.tenant_id == user.tenant_id,
            LinuxAgent.host_id.in_(host_ids),
            LinuxAgent.revoked_at.is_(None),
        )
    ).all()
    agents_by_host = {agent.host_id: agent for agent in agents}
    if set(agents_by_host) != set(host_ids):
        raise HTTPException(
            status_code=409, detail="Every target host must have an active managed agent"
        )

    hosts_by_id = {
        host.id: host
        for host in db.scalars(select(Host).where(Host.id.in_(host_ids))).all()
    }
    if set(hosts_by_id) != set(host_ids):
        raise HTTPException(status_code=409, detail="Every remediation target must still exist")
    policy_snapshots: dict[str, dict[str, object]] = {}
    limits: list[dict[str, object]] = []
    for agent in agents:
        group = db.get(AgentGroup, agent.group_id)
        policy = db.get(AgentPolicy, group.policy_id) if group is not None else None
        version = _latest_policy_version(db, policy.id) if policy is not None else None
        if group is None or policy is None or version is None:
            raise HTTPException(
                status_code=409, detail="Every target must have a published agent policy"
            )
        policy_limits = _policy_limits(version)
        limits.append(policy_limits)
        policy_snapshots[agent.host_id] = {
            "group_id": group.id,
            "group_name": group.name,
            "policy_id": policy.id,
            "policy_name": policy.name,
            "policy_version": version.version,
            "required_capability": policy_limits["remediation_required_capability"],
        }
    strict_max_targets = min(int(item["remediation_max_targets_per_change_set"]) for item in limits)
    strict_max_canaries = min(int(item["remediation_max_canary_hosts"]) for item in limits)
    strict_max_batch = min(int(item["remediation_max_batch_hosts"]) for item in limits)
    strict_min_interval = max(
        int(item["remediation_min_batch_interval_minutes"]) for item in limits
    )
    if len(host_ids) > strict_max_targets or len(canary_host_ids) > strict_max_canaries:
        raise HTTPException(
            status_code=422, detail="Target or canary scope exceeds the strictest assigned policy"
        )
    if (
        request.batch_size > strict_max_batch
        or request.batch_interval_minutes < strict_min_interval
    ):
        raise HTTPException(
            status_code=422, detail="Batch size or interval violates the strictest assigned policy"
        )

    change_set_id = uuid_string()
    requested_at = now_utc()
    payload = {
        "schema_version": "1.0",
        "change_set_id": change_set_id,
        "tenant_id": user.tenant_id,
        "requested_at": requested_at.isoformat(),
        "maintenance_window": {"start": start.isoformat(), "end": end.isoformat()},
        "rollout": {
            "strategy": "canary",
            "batch_size": request.batch_size,
            "batch_interval_minutes": request.batch_interval_minutes,
        },
        "safeguards": {
            "execution_enabled": False,
            "four_eyes_required": True,
            "post_change_verification_required": True,
            "rollback_checkpoint_required": True,
        },
        "plans": sorted(
            [
                {
                    "plan_id": plan.id,
                    "plan_version": plan.version,
                    "host_id": plan.host_id,
                    "hostname": hosts_by_id[plan.host_id].hostname,
                    "report_id": plan.report_id,
                    "control_id": plan.control_id,
                    "title": plan.title,
                    "action_id": plan.action_id,
                    "action_version": plan.action_version,
                    "action_digest": plan.action_digest,
                    "plan_approved_by": plan.approved_by,
                }
                for plan in plans
            ],
            key=lambda item: item["plan_id"],
        ),
        "targets": sorted(
            [
                {
                    "host_id": host_id,
                    "hostname": hosts_by_id[host_id].hostname,
                    "agent_id": agents_by_host[host_id].id,
                    "rollout_phase": "canary" if host_id in canary_host_ids else "deferred",
                    **policy_snapshots[host_id],
                }
                for host_id in host_ids
            ],
            key=lambda item: item["host_id"],
        ),
    }
    change_set = RemediationChangeSet(
        id=change_set_id,
        tenant_id=user.tenant_id,
        payload=payload,
        digest=payload_digest(payload),
        maintenance_window_start=start,
        maintenance_window_end=end,
        batch_size=request.batch_size,
        batch_interval_minutes=request.batch_interval_minutes,
        requested_by=user.id,
        requested_at=requested_at,
        created_at=requested_at,
        updated_at=requested_at,
    )
    db.add(change_set)
    db.add_all(
        [
            RemediationChangeSetPlan(
                tenant_id=user.tenant_id,
                change_set_id=change_set.id,
                plan_id=plan.id,
            )
            for plan in plans
        ]
    )
    db.add_all(
        [
            RemediationChangeSetTarget(
                tenant_id=user.tenant_id,
                change_set_id=change_set.id,
                host_id=host_id,
                agent_id=agents_by_host[host_id].id,
                rollout_phase="canary" if host_id in canary_host_ids else "deferred",
            )
            for host_id in host_ids
        ]
    )
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="remediation_change_set.requested",
            target_type="remediation_change_set",
            target_id=change_set.id,
            details={"digest": change_set.digest, "plan_ids": plan_ids, "execution_enabled": False},
        )
    )
    db.commit()
    return _serialize(db, change_set)


@router.get("/{change_set_id}", response_model=RemediationChangeSetResponse)
def get_change_set(
    change_set_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationChangeSetResponse:
    return _serialize(db, _change_set(db, user, change_set_id))


def _validation_contract_for_agent(
    db: Session,
    change_set: RemediationChangeSet,
    tenant_id: str,
    agent_id: str,
) -> tuple[RemediationExecutionContractPreview, LinuxAgent]:
    if change_set.status != "authorized":
        raise HTTPException(
            status_code=409,
            detail="Only an authorized change set can produce a validation contract",
        )
    try:
        _assert_envelope_integrity(db, change_set)
    except RemediationCatalogError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if change_set.signature is None or change_set.signing_key_id is None:
        raise HTTPException(status_code=409, detail="Authorized change-set signature is missing")
    change_signing_key = db.get(PlatformChangeSigningKey, change_set.signing_key_id)
    if (
        change_signing_key is None
        or change_signing_key.tenant_id != tenant_id
        or change_signing_key.revoked_at is not None
        or not verify_change_set_signature(
            change_signing_key.public_key,
            change_set.payload,
            change_set.signature,
        )
    ):
        raise HTTPException(status_code=409, detail="Authorized change-set signature does not verify")
    target_link = db.scalar(
        select(RemediationChangeSetTarget).where(
            RemediationChangeSetTarget.change_set_id == change_set.id,
            RemediationChangeSetTarget.agent_id == agent_id,
        )
    )
    if target_link is None:
        raise HTTPException(status_code=404, detail="Agent is not a target of this change set")
    agent = db.get(LinuxAgent, target_link.agent_id)
    if (
        agent is None
        or agent.tenant_id != tenant_id
        or agent.revoked_at is not None
        or REMEDIATION_CONTRACT_VALIDATION_CAPABILITY not in (agent.capabilities or [])
    ):
        raise HTTPException(
            status_code=409,
            detail="Target agent has not attested validation-only remediation contract support",
        )
    platform_key = (
        db.get(PlatformCommandSigningKey, agent.platform_command_key_id)
        if agent.platform_command_key_id is not None
        else None
    )
    if (
        platform_key is None
        or platform_key.tenant_id != tenant_id
        or platform_key.status != "active"
        or platform_key.revoked_at is not None
        or platform_key.fingerprint != agent.platform_command_key_fingerprint
    ):
        raise HTTPException(status_code=409, detail="Target agent platform trust is unavailable")
    payload_targets = _envelope_records(change_set, "targets")
    target = next(
        (
            item
            for item in payload_targets
            if item.get("agent_id") == agent.id and item.get("host_id") == agent.host_id
        ),
        None,
    )
    if target is None:
        raise HTTPException(status_code=409, detail="Signed target binding is unavailable")
    actions: list[dict[str, object]] = []
    for link in db.scalars(
        select(RemediationChangeSetPlan).where(
            RemediationChangeSetPlan.change_set_id == change_set.id
        )
    ).all():
        plan = db.get(RemediationPlan, link.plan_id)
        if plan is None or plan.host_id != agent.host_id:
            continue
        try:
            action = _stored_action(plan)
        except RemediationCatalogError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if action is None:
            raise HTTPException(status_code=409, detail="Target plan has no reviewed action")
        actions.append(
            {
                "plan_id": plan.id,
                "host_id": plan.host_id,
                "control_id": plan.control_id,
                "action_id": action.action_id,
                "action_version": action.version,
                "action_digest": action.digest,
                "action_snapshot": action.model_dump(mode="json"),
            }
        )
    if not actions:
        raise HTTPException(status_code=409, detail="Target has no reviewed remediation actions")
    return (
        build_validation_contract(
            change_set=change_set,
            change_signing_key=change_signing_key,
            platform_command_key=platform_key,
            target=dict(target),
            actions=sorted(actions, key=lambda item: str(item["plan_id"])),
        ),
        agent,
    )


def _validation_job_response(
    db: Session,
    job: RemediationValidationJob,
    *,
    include_contract: bool = True,
) -> RemediationValidationJobResponse:
    return RemediationValidationJobResponse(
        id=job.id,
        change_set_id=job.change_set_id,
        host_id=job.host_id,
        agent_id=job.agent_id,
        status=job.status,
        contract_digest=job.contract_digest,
        contract=job.contract if include_contract else None,
        requested_by=job.requested_by,
        requested_by_name=_user_name(db, job.requested_by) or "Unknown User",
        requested_at=job.requested_at,
        delivered_at=job.delivered_at,
        lease_expires_at=job.lease_expires_at,
        completed_at=job.completed_at,
        receipt=job.receipt,
        receipt_signature=job.receipt_signature,
        error=job.error,
    )


@router.get(
    "/{change_set_id}/execution-contract-preview/{agent_id}",
    response_model=RemediationExecutionContractPreview,
)
def execution_contract_preview(
    change_set_id: str,
    agent_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationExecutionContractPreview:
    require_admin(user)
    contract, _ = _validation_contract_for_agent(
        db,
        _change_set(db, user, change_set_id),
        user.tenant_id,
        agent_id,
    )
    return contract


@router.get(
    "/{change_set_id}/validation-jobs",
    response_model=list[RemediationValidationJobResponse],
)
def list_validation_jobs(
    change_set_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[RemediationValidationJobResponse]:
    require_admin(user)
    change_set = _change_set(db, user, change_set_id)
    jobs = db.scalars(
        select(RemediationValidationJob)
        .where(
            RemediationValidationJob.tenant_id == user.tenant_id,
            RemediationValidationJob.change_set_id == change_set.id,
        )
        .order_by(RemediationValidationJob.requested_at.desc())
    ).all()
    return [_validation_job_response(db, job) for job in jobs]


@router.post(
    "/{change_set_id}/validation-jobs",
    response_model=RemediationValidationJobResponse,
    status_code=202,
)
def queue_validation_job(
    change_set_id: str,
    request: RemediationValidationJobCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationValidationJobResponse:
    require_admin(user)
    change_set = _change_set(db, user, change_set_id, lock=True)
    contract, agent = _validation_contract_for_agent(
        db,
        change_set,
        user.tenant_id,
        request.agent_id,
    )
    if REMEDIATION_DRY_RUN_CAPABILITY not in (agent.capabilities or []):
        raise HTTPException(
            status_code=409,
            detail="Target agent has not attested read-only remediation dry-run support",
        )
    existing = db.scalar(
        select(RemediationValidationJob).where(
            RemediationValidationJob.change_set_id == change_set.id,
            RemediationValidationJob.agent_id == agent.id,
            RemediationValidationJob.status.in_(["queued", "delivered"]),
        )
    )
    if existing is not None:
        return _validation_job_response(db, existing)
    contract_payload = contract.model_dump(mode="json")
    job = RemediationValidationJob(
        tenant_id=user.tenant_id,
        change_set_id=change_set.id,
        host_id=agent.host_id,
        agent_id=agent.id,
        status="queued",
        contract=contract_payload,
        contract_digest=validation_contract_digest(contract_payload),
        requested_by=user.id,
    )
    db.add(job)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="remediation_validation.queued",
            target_type="remediation_validation_job",
            target_id=job.id,
            details={
                "change_set_id": change_set.id,
                "agent_id": agent.id,
                "host_id": agent.host_id,
                "contract_digest": job.contract_digest,
                "execution_enabled": False,
            },
        )
    )
    db.commit()
    return _validation_job_response(db, job)


@router.post("/{change_set_id}/authorize", response_model=RemediationChangeSetResponse)
def authorize_change_set(
    change_set_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationChangeSetResponse:
    require_admin(user)
    change_set = _change_set(db, user, change_set_id, lock=True)
    if change_set.status != "pending_authorization":
        raise HTTPException(status_code=409, detail="Only a pending change set can be authorized")
    try:
        gates = _readiness_gates(db, change_set, authorizer=user)
    except RemediationCatalogError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    blocked = [gate for gate in gates if gate.status == "blocked"]
    if blocked:
        blocked_labels = ", ".join(gate.code.replace("_", " ") for gate in blocked)
        raise HTTPException(
            status_code=409,
            detail=f"Change set readiness gates are blocked: {blocked_labels}",
        )
    signing_key, created = active_change_signing_key(db, user.tenant_id)
    if created:
        db.add(
            AuditEvent(
                tenant_id=user.tenant_id,
                actor_type="system",
                actor_id=None,
                action="remediation_change_signing_key.created",
                target_type="platform_change_signing_key",
                target_id=signing_key.id,
                details={"fingerprint": signing_key.fingerprint},
            )
        )
    change_set.signature = sign_change_set(signing_key, change_set.payload)
    change_set.signing_key_id = signing_key.id
    change_set.status = "authorized"
    change_set.authorized_by = user.id
    change_set.authorized_at = now_utc()
    change_set.updated_at = change_set.authorized_at
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="remediation_change_set.authorized",
            target_type="remediation_change_set",
            target_id=change_set.id,
            details={
                "digest": change_set.digest,
                "signing_key_fingerprint": signing_key.fingerprint,
                "execution_enabled": False,
            },
        )
    )
    db.commit()
    return _serialize(db, change_set)


@router.post("/{change_set_id}/cancel", response_model=RemediationChangeSetResponse)
def cancel_change_set(
    change_set_id: str,
    request: RemediationChangeSetDecision,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> RemediationChangeSetResponse:
    require_admin(user)
    change_set = _change_set(db, user, change_set_id, lock=True)
    if change_set.status == "canceled":
        raise HTTPException(status_code=409, detail="Change set is already canceled")
    change_set.status = "canceled"
    change_set.canceled_by = user.id
    change_set.canceled_at = now_utc()
    change_set.cancellation_reason = request.reason.strip()
    change_set.updated_at = change_set.canceled_at
    for job in db.scalars(
        select(RemediationValidationJob).where(
            RemediationValidationJob.change_set_id == change_set.id,
            RemediationValidationJob.status.in_(["queued", "delivered"]),
        )
    ).all():
        job.status = "canceled"
        job.completed_at = change_set.canceled_at
        job.error = "Parent change set was canceled before validation completed"
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="remediation_change_set.canceled",
            target_type="remediation_change_set",
            target_id=change_set.id,
            details={"reason": change_set.cancellation_reason, "execution_enabled": False},
        )
    )
    db.commit()
    return _serialize(db, change_set)
