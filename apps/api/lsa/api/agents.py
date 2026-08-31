import base64
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta
from importlib.resources import files

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from lsa.api.admin import require_admin
from lsa.database import get_db
from lsa.dependencies import bearer, current_user
from lsa.models import (
    AgentEnrollmentToken,
    AgentGroup,
    AgentPolicy,
    AgentPolicyVersion,
    AgentTask,
    AuditEvent,
    Finding,
    Host,
    IngestionToken,
    LinuxAgent,
    PolicyMode,
    PlatformCommandSigningKey,
    RemediationChangeSet,
    RemediationCheckpointJob,
    RemediationRecoveryVerificationJob,
    RemediationValidationJob,
    SigningKey,
    Tenant,
    User,
    now_utc,
)
from lsa.schemas import (
    AgentEffectivePolicyResponse,
    AgentBulkGroupAssignment,
    AgentBulkResult,
    AgentBulkSelection,
    AgentEnrollmentRequest,
    AgentEnrollmentResponse,
    AgentEnrollmentTokenCreate,
    AgentEnrollmentTokenCreated,
    AgentEnrollmentTokenResponse,
    AgentGroupAssignment,
    AgentGroupCreate,
    AgentGroupResponse,
    AgentGroupUpdate,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentPolicyCreate,
    AgentPolicyResponse,
    AgentPolicyRestoreRequest,
    AgentPolicyVersionResponse,
    AgentPolicyUpdate,
    AgentTaskCompletion,
    AgentTaskResponse,
    ControlCatalogItem,
    LinuxAgentResponse,
    PlatformControlResponse,
    RemediationCheckpointReceiptSubmission,
    RemediationRecoveryVerificationReceiptSubmission,
    RemediationValidationReceiptSubmission,
)
from lsa.security import hash_ingestion_token
from lsa.services.platform_command_trust import (
    active_platform_command_key,
    platform_key_rotation_proof,
    platform_trust_descriptor,
    sign_platform_envelope,
)
from lsa.services.remediation_execution_contract import validation_contract_digest
from lsa.services.remediation_receipts import (
    checkpoint_journal_digest,
    validate_recovery_plan,
    verify_validation_receipt,
)


router = APIRouter(tags=["agents"])
AGENT_CLOCK_SKEW_SECONDS = 300
AGENT_TASK_LEASE_SECONDS = 3600
REMEDIATION_VALIDATION_LEASE_SECONDS = 300
SIGNED_PLATFORM_CONTROL_CAPABILITY = "signed-platform-control-v1"
PLATFORM_KEY_ROTATION_CAPABILITY = "platform-key-rotation-v1"
REMEDIATION_CONTRACT_VALIDATION_CAPABILITY = "remediation-contract-validation-v1"
REMEDIATION_DRY_RUN_CAPABILITY = "remediation-dry-run-v1"
REMEDIATION_RECOVERY_PLANNING_CAPABILITY = "remediation-recovery-planning-v1"
REMEDIATION_CHECKPOINT_CAPABILITY = "remediation-checkpoint-v1"
REMEDIATION_RECOVERY_VERIFICATION_CAPABILITY = "remediation-recovery-verification-v1"


@dataclass(frozen=True)
class AgentPrincipal:
    agent: LinuxAgent
    signed_control_requested: bool = False


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=now_utc().tzinfo)
    return value


def _lock_tenant(db: Session, tenant_id: str) -> None:
    if db.scalar(select(Tenant.id).where(Tenant.id == tenant_id).with_for_update()) is None:
        raise HTTPException(status_code=404, detail="Tenant not found")


def _validate_public_key(encoded: str) -> tuple[Ed25519PublicKey, bytes]:
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Public key must be base64 Ed25519 raw bytes") from exc


def _latest_policy_version(db: Session, policy_id: str) -> AgentPolicyVersion:
    version = db.scalar(
        select(AgentPolicyVersion)
        .where(AgentPolicyVersion.policy_id == policy_id)
        .order_by(AgentPolicyVersion.version.desc())
    )
    if version is None:
        raise HTTPException(status_code=409, detail="Policy has no published version")
    return version


def _validate_policy_settings(settings: dict[str, object]) -> dict[str, object]:
    result = {
        "schedule_minutes": 60,
        "jitter_seconds": 300,
        "profile": "level2_server",
        "remediation_approval": "required",
        "remediation_four_eyes": True,
        "remediation_required_capability": "signed-change-set-planning-v1",
        "remediation_max_evidence_age_minutes": 1440,
        "remediation_max_agent_attestation_age_minutes": 15,
        "remediation_max_targets_per_change_set": 25,
        "remediation_max_canary_hosts": 3,
        "remediation_max_batch_hosts": 5,
        "remediation_min_batch_interval_minutes": 15,
        **settings,
    }
    try:
        schedule = int(result["schedule_minutes"])
        jitter = int(result["jitter_seconds"])
        max_evidence_age = int(result["remediation_max_evidence_age_minutes"])
        max_attestation_age = int(result["remediation_max_agent_attestation_age_minutes"])
        max_targets = int(result["remediation_max_targets_per_change_set"])
        max_canaries = int(result["remediation_max_canary_hosts"])
        max_batch = int(result["remediation_max_batch_hosts"])
        min_interval = int(result["remediation_min_batch_interval_minutes"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Policy timing and remediation limits must be integers") from exc
    if schedule < 5 or schedule > 10080:
        raise HTTPException(status_code=422, detail="Policy schedule must be between 5 and 10080 minutes")
    if jitter < 0 or jitter > 3600:
        raise HTTPException(status_code=422, detail="Policy jitter must be between 0 and 3600 seconds")
    if max_evidence_age < 15 or max_evidence_age > 10080:
        raise HTTPException(status_code=422, detail="Remediation evidence age must be between 15 and 10080 minutes")
    if max_attestation_age < 5 or max_attestation_age > 1440:
        raise HTTPException(status_code=422, detail="Agent attestation age must be between 5 and 1440 minutes")
    if max_targets < 1 or max_targets > 100:
        raise HTTPException(status_code=422, detail="Change-set target limit must be between 1 and 100")
    if max_canaries < 1 or max_canaries > min(10, max_targets):
        raise HTTPException(
            status_code=422,
            detail="Canary limit must be between 1 and 10 and not exceed the target limit",
        )
    if max_batch < 1 or max_batch > max_targets:
        raise HTTPException(status_code=422, detail="Batch limit must be between 1 and the target limit")
    if min_interval < 15 or min_interval > 1440:
        raise HTTPException(status_code=422, detail="Batch interval must be between 15 and 1440 minutes")
    result["schedule_minutes"] = schedule
    result["jitter_seconds"] = jitter
    result["remediation_approval"] = "required"
    result["remediation_four_eyes"] = True
    result["remediation_required_capability"] = "signed-change-set-planning-v1"
    result["remediation_max_evidence_age_minutes"] = max_evidence_age
    result["remediation_max_agent_attestation_age_minutes"] = max_attestation_age
    result["remediation_max_targets_per_change_set"] = max_targets
    result["remediation_max_canary_hosts"] = max_canaries
    result["remediation_max_batch_hosts"] = max_batch
    result["remediation_min_batch_interval_minutes"] = min_interval
    return result


def _policy_response(db: Session, policy: AgentPolicy) -> AgentPolicyResponse:
    version = _latest_policy_version(db, policy.id)
    assigned_groups = (
        db.scalar(select(func.count()).select_from(AgentGroup).where(AgentGroup.policy_id == policy.id)) or 0
    )
    return AgentPolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        version=version.version,
        default_mode=version.default_mode.value,
        control_modes=version.control_modes or {},
        settings=version.settings or {},
        assigned_groups=assigned_groups,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _group_response(db: Session, group: AgentGroup) -> AgentGroupResponse:
    policy = db.get(AgentPolicy, group.policy_id)
    if policy is None:
        raise HTTPException(status_code=409, detail="Assigned policy no longer exists")
    version = _latest_policy_version(db, policy.id)
    agent_count = (
        db.scalar(
            select(func.count())
            .select_from(LinuxAgent)
            .where(LinuxAgent.group_id == group.id, LinuxAgent.revoked_at.is_(None))
        )
        or 0
    )
    return AgentGroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        policy_id=policy.id,
        policy_name=policy.name,
        policy_version=version.version,
        agent_count=agent_count,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


def _require_policy(db: Session, tenant_id: str, policy_id: str) -> AgentPolicy:
    policy = db.get(AgentPolicy, policy_id)
    if policy is None or policy.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Agent policy not found")
    return policy


def _require_group(db: Session, tenant_id: str, group_id: str) -> AgentGroup:
    group = db.get(AgentGroup, group_id)
    if group is None or group.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Agent group not found")
    return group


def _agent_response(db: Session, agent: LinuxAgent) -> LinuxAgentResponse:
    host = db.get(Host, agent.host_id)
    group = db.get(AgentGroup, agent.group_id)
    if host is None or group is None:
        raise HTTPException(status_code=409, detail="Agent inventory relationship is incomplete")
    policy = db.get(AgentPolicy, group.policy_id)
    if policy is None:
        raise HTTPException(status_code=409, detail="Assigned policy no longer exists")
    version = _latest_policy_version(db, policy.id)
    latest_task = db.scalar(
        select(AgentTask).where(AgentTask.agent_id == agent.id).order_by(AgentTask.created_at.desc())
    )
    return LinuxAgentResponse(
        id=agent.id,
        host_id=agent.host_id,
        hostname=host.hostname,
        group_id=group.id,
        group_name=group.name,
        policy_name=policy.name,
        policy_version=version.version,
        agent_version=agent.agent_version,
        capabilities=agent.capabilities or [],
        fingerprint=agent.fingerprint,
        platform_trust_status="pinned" if agent.platform_command_key_id else "missing",
        platform_command_key_fingerprint=agent.platform_command_key_fingerprint,
        last_seen_at=agent.last_seen_at,
        last_policy_version=agent.last_policy_version,
        last_scan_at=host.last_scan_at,
        latest_task_status=latest_task.status if latest_task else None,
        latest_task_created_at=latest_task.created_at if latest_task else None,
        revoked_at=agent.revoked_at,
        created_at=agent.created_at,
    )


async def signed_agent_principal(request: Request, db: Session = Depends(get_db)) -> AgentPrincipal:
    agent_id = request.headers.get("X-LSA-Agent-ID")
    timestamp_text = request.headers.get("X-LSA-Agent-Timestamp")
    signature_text = request.headers.get("X-LSA-Agent-Signature")
    if not agent_id or not timestamp_text or not signature_text:
        raise HTTPException(status_code=401, detail="Signed agent authentication required")
    try:
        timestamp = int(timestamp_text)
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid agent signature headers") from None
    now_timestamp = int(now_utc().timestamp())
    if abs(now_timestamp - timestamp) > AGENT_CLOCK_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Agent request timestamp is outside the allowed window")
    agent = db.scalar(select(LinuxAgent).where(LinuxAgent.id == agent_id).with_for_update())
    if agent is None or agent.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Unknown or revoked agent")
    public_key, _ = _validate_public_key(agent.public_key)
    body_hash = hashlib.sha256(await request.body()).hexdigest()
    message = f"{request.method}\n{request.url.path}\n{timestamp_text}\n{body_hash}".encode()
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise HTTPException(status_code=401, detail="Invalid agent signature") from exc
    return AgentPrincipal(
        agent=agent,
        signed_control_requested=request.headers.get("X-LSA-Platform-Control") == "signed-v1",
    )


@router.get("/agent-policies", response_model=list[AgentPolicyResponse])
def list_policies(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    policies = db.scalars(
        select(AgentPolicy).where(AgentPolicy.tenant_id == user.tenant_id).order_by(AgentPolicy.name)
    ).all()
    return [_policy_response(db, policy) for policy in policies]


@router.post("/agent-policies", response_model=AgentPolicyResponse, status_code=201)
def create_policy(request: AgentPolicyCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    policy = AgentPolicy(tenant_id=user.tenant_id, name=request.name.strip(), description=request.description.strip())
    db.add(policy)
    db.flush()
    version = AgentPolicyVersion(
        tenant_id=user.tenant_id,
        policy_id=policy.id,
        version=1,
        default_mode=PolicyMode(request.default_mode),
        control_modes=request.control_modes,
        settings=_validate_policy_settings(request.settings),
        created_by=user.id,
    )
    db.add(version)
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_policy.created",
            target_type="agent_policy",
            target_id=policy.id,
            details={"name": policy.name, "version": 1},
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An agent policy with this name already exists") from exc
    return _policy_response(db, policy)


@router.put("/agent-policies/{policy_id}", response_model=AgentPolicyResponse)
def update_policy(
    policy_id: str,
    request: AgentPolicyUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    policy = db.scalar(
        select(AgentPolicy)
        .where(AgentPolicy.id == policy_id, AgentPolicy.tenant_id == user.tenant_id)
        .with_for_update()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Agent policy not found")
    previous = _latest_policy_version(db, policy.id)
    policy.description = request.description.strip()
    policy.updated_at = now_utc()
    version = AgentPolicyVersion(
        tenant_id=user.tenant_id,
        policy_id=policy.id,
        version=previous.version + 1,
        default_mode=PolicyMode(request.default_mode),
        control_modes=request.control_modes,
        settings=_validate_policy_settings(request.settings),
        created_by=user.id,
    )
    db.add(version)
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_policy.version_published",
            target_type="agent_policy",
            target_id=policy.id,
            details={"version": version.version, "enforcement_enabled": False},
        )
    )
    db.commit()
    return _policy_response(db, policy)


@router.get("/agent-policies/{policy_id}/versions", response_model=list[AgentPolicyVersionResponse])
def list_policy_versions(policy_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    _require_policy(db, user.tenant_id, policy_id)
    versions = db.scalars(
        select(AgentPolicyVersion)
        .where(
            AgentPolicyVersion.policy_id == policy_id,
            AgentPolicyVersion.tenant_id == user.tenant_id,
        )
        .order_by(AgentPolicyVersion.version.desc())
    ).all()
    return [
        AgentPolicyVersionResponse(
            version=item.version,
            default_mode=item.default_mode.value,
            control_modes=item.control_modes or {},
            settings=item.settings or {},
            created_by_name=(
                db.get(User, item.created_by).display_name
                if item.created_by and db.get(User, item.created_by)
                else None
            ),
            created_at=item.created_at,
        )
        for item in versions
    ]


@router.post("/agent-policies/{policy_id}/restore", response_model=AgentPolicyResponse)
def restore_policy_version(
    policy_id: str,
    request: AgentPolicyRestoreRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    policy = _require_policy(db, user.tenant_id, policy_id)
    source = db.scalar(
        select(AgentPolicyVersion).where(
            AgentPolicyVersion.policy_id == policy.id, AgentPolicyVersion.version == request.version
        )
    )
    if source is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    latest = _latest_policy_version(db, policy.id)
    restored = AgentPolicyVersion(
        tenant_id=user.tenant_id,
        policy_id=policy.id,
        version=latest.version + 1,
        default_mode=source.default_mode,
        control_modes=dict(source.control_modes or {}),
        settings=dict(source.settings or {}),
        created_by=user.id,
    )
    policy.updated_at = now_utc()
    db.add(restored)
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_policy.version_restored",
            target_type="agent_policy",
            target_id=policy.id,
            details={
                "source_version": source.version,
                "version": restored.version,
                "enforcement_enabled": False,
            },
        )
    )
    db.commit()
    return _policy_response(db, policy)


@router.get("/agent-groups", response_model=list[AgentGroupResponse])
def list_groups(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    groups = db.scalars(
        select(AgentGroup).where(AgentGroup.tenant_id == user.tenant_id).order_by(AgentGroup.name)
    ).all()
    return [_group_response(db, group) for group in groups]


@router.post("/agent-groups", response_model=AgentGroupResponse, status_code=201)
def create_group(request: AgentGroupCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    _require_policy(db, user.tenant_id, request.policy_id)
    group = AgentGroup(
        tenant_id=user.tenant_id,
        policy_id=request.policy_id,
        name=request.name.strip(),
        description=request.description.strip(),
    )
    db.add(group)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_group.created",
            target_type="agent_group",
            target_id=group.id,
            details={"name": group.name, "policy_id": group.policy_id},
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An agent group with this name already exists") from exc
    return _group_response(db, group)


@router.put("/agent-groups/{group_id}", response_model=AgentGroupResponse)
def update_group(
    group_id: str,
    request: AgentGroupUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    group = _require_group(db, user.tenant_id, group_id)
    _require_policy(db, user.tenant_id, request.policy_id)
    group.name = request.name.strip()
    group.description = request.description.strip()
    group.policy_id = request.policy_id
    group.updated_at = now_utc()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_group.updated",
            target_type="agent_group",
            target_id=group.id,
            details={"policy_id": group.policy_id},
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An agent group with this name already exists") from exc
    return _group_response(db, group)


@router.get("/agents", response_model=list[LinuxAgentResponse])
def list_agents(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    agents = db.scalars(
        select(LinuxAgent).where(LinuxAgent.tenant_id == user.tenant_id).order_by(LinuxAgent.created_at.desc())
    ).all()
    return [_agent_response(db, agent) for agent in agents]


def _selected_agents(
    db: Session, tenant_id: str, agent_ids: list[str], *, active_only: bool = True
) -> list[LinuxAgent]:
    unique_ids = list(dict.fromkeys(agent_ids))
    agents = db.scalars(
        select(LinuxAgent).where(LinuxAgent.tenant_id == tenant_id, LinuxAgent.id.in_(unique_ids)).with_for_update()
    ).all()
    if len(agents) != len(unique_ids):
        raise HTTPException(status_code=404, detail="One or more agents were not found")
    if active_only and any(agent.revoked_at is not None for agent in agents):
        raise HTTPException(status_code=409, detail="Revoked agents cannot be changed")
    return agents


@router.post("/agents/actions/run-audit", response_model=list[AgentTaskResponse], status_code=202)
def queue_agent_audits(request: AgentBulkSelection, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    agents = _selected_agents(db, user.tenant_id, request.agent_ids)
    tasks: list[AgentTask] = []
    for agent in agents:
        existing = db.scalar(
            select(AgentTask)
            .where(AgentTask.agent_id == agent.id, AgentTask.status.in_(["queued", "dispatched"]))
            .order_by(AgentTask.created_at.desc())
        )
        if existing:
            tasks.append(existing)
            continue
        task = AgentTask(
            tenant_id=user.tenant_id,
            agent_id=agent.id,
            task_type="audit",
            status="queued",
            requested_by=user.id,
        )
        db.add(task)
        tasks.append(task)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent.audit_queued",
            target_type="linux_agent",
            target_id="bulk",
            details={
                "agent_ids": [agent.id for agent in agents],
                "task_ids": [task.id for task in tasks],
            },
        )
    )
    db.commit()
    return tasks


@router.post("/agents/actions/assign-group", response_model=AgentBulkResult)
def bulk_assign_agent_group(
    request: AgentBulkGroupAssignment,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    _lock_tenant(db, user.tenant_id)
    _require_group(db, user.tenant_id, request.group_id)
    agents = _selected_agents(db, user.tenant_id, request.agent_ids)
    for agent in agents:
        agent.group_id = request.group_id
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent.group_bulk_assigned",
            target_type="agent_group",
            target_id=request.group_id,
            details={"agent_ids": [agent.id for agent in agents]},
        )
    )
    db.commit()
    return AgentBulkResult(affected=len(agents))


def _revoke_agent_credentials(db: Session, agent: LinuxAgent, revoked_at) -> None:
    agent.revoked_at = revoked_at
    token = db.get(IngestionToken, agent.ingestion_token_id)
    key = db.get(SigningKey, agent.signing_key_id)
    if token is not None:
        token.revoked_at = revoked_at
    if key is not None:
        key.revoked_at = revoked_at
    for task in db.scalars(
        select(AgentTask).where(AgentTask.agent_id == agent.id, AgentTask.status.in_(["queued", "dispatched"]))
    ).all():
        task.status = "cancelled"
        task.completed_at = revoked_at


@router.post("/agents/actions/revoke", response_model=AgentBulkResult)
def bulk_revoke_agents(request: AgentBulkSelection, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    agents = _selected_agents(db, user.tenant_id, request.agent_ids)
    revoked_at = now_utc()
    for agent in agents:
        _revoke_agent_credentials(db, agent, revoked_at)
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent.bulk_revoked",
            target_type="linux_agent",
            target_id="bulk",
            details={"agent_ids": [agent.id for agent in agents]},
        )
    )
    db.commit()
    return AgentBulkResult(affected=len(agents))


@router.patch("/agents/{agent_id}/group", response_model=LinuxAgentResponse)
def assign_agent_group(
    agent_id: str,
    request: AgentGroupAssignment,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    agent = db.get(LinuxAgent, agent_id)
    if agent is None or agent.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    _require_group(db, user.tenant_id, request.group_id)
    previous = agent.group_id
    agent.group_id = request.group_id
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent.group_assigned",
            target_type="linux_agent",
            target_id=agent.id,
            details={"previous_group_id": previous, "group_id": agent.group_id},
        )
    )
    db.commit()
    return _agent_response(db, agent)


@router.delete("/agents/{agent_id}", status_code=204)
def revoke_agent(agent_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    agent = db.get(LinuxAgent, agent_id)
    if agent is None or agent.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Agent is already revoked")
    revoked_at = now_utc()
    _revoke_agent_credentials(db, agent, revoked_at)
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent.revoked",
            target_type="linux_agent",
            target_id=agent.id,
            details={"host_id": agent.host_id},
        )
    )
    db.commit()
    return Response(status_code=204)


@router.post("/agent-enrollment-tokens", response_model=AgentEnrollmentTokenCreated, status_code=201)
def create_enrollment_token(
    request: AgentEnrollmentTokenCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    _require_group(db, user.tenant_id, request.group_id)
    expires_at = _aware(request.expires_at)
    maximum_lifetime = timedelta(days=365 if request.token_type == "reusable" else 30)
    if expires_at <= now_utc() or expires_at > now_utc() + maximum_lifetime:
        maximum_days = maximum_lifetime.days
        raise HTTPException(
            status_code=422,
            detail=f"{request.token_type.replace('_', ' ').title()} enrollment token expiry must be within the next {maximum_days} days",
        )
    if request.token_type == "one_time" and request.max_uses is not None:
        raise HTTPException(status_code=422, detail="One-time enrollment tokens cannot set a usage limit")
    if request.token_type == "reusable":
        active_reusable = db.scalar(
            select(AgentEnrollmentToken).where(
                AgentEnrollmentToken.tenant_id == user.tenant_id,
                AgentEnrollmentToken.token_type == "reusable",
                AgentEnrollmentToken.revoked_at.is_(None),
                AgentEnrollmentToken.expires_at > now_utc(),
                or_(
                    AgentEnrollmentToken.max_uses.is_(None),
                    AgentEnrollmentToken.use_count < AgentEnrollmentToken.max_uses,
                ),
            )
        )
        if active_reusable is not None:
            raise HTTPException(
                status_code=409,
                detail="An active reusable tenant enrollment token already exists; revoke it before creating another",
            )
    prefix = "lsa_tenant_enroll_" if request.token_type == "reusable" else "lsa_enroll_"
    raw_token = f"{prefix}{secrets.token_urlsafe(32)}"
    platform_key, key_created = active_platform_command_key(db, user.tenant_id)
    token = AgentEnrollmentToken(
        tenant_id=user.tenant_id,
        group_id=request.group_id,
        platform_command_key_id=platform_key.id,
        name=request.name.strip(),
        token_prefix=raw_token[:24],
        token_hash=hash_ingestion_token(raw_token),
        token_type=request.token_type,
        max_uses=request.max_uses,
        expires_at=expires_at,
    )
    db.add(token)
    db.flush()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_enrollment_token.created",
            target_type="agent_enrollment_token",
            target_id=token.id,
            details={
                "group_id": token.group_id,
                "expires_at": token.expires_at.isoformat(),
                "token_type": token.token_type,
                "max_uses": token.max_uses,
                "platform_command_key_fingerprint": platform_key.fingerprint,
                "platform_command_key_created": key_created,
            },
        )
    )
    db.commit()
    return AgentEnrollmentTokenCreated(
        id=token.id,
        name=token.name,
        group_id=token.group_id,
        token=raw_token,
        token_prefix=token.token_prefix,
        expires_at=token.expires_at,
        token_type=token.token_type,
        max_uses=token.max_uses,
        use_count=token.use_count,
        platform_trust=platform_trust_descriptor(platform_key),
    )


@router.get("/agent-enrollment-tokens", response_model=list[AgentEnrollmentTokenResponse])
def list_enrollment_tokens(user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    tokens = db.scalars(
        select(AgentEnrollmentToken)
        .where(AgentEnrollmentToken.tenant_id == user.tenant_id)
        .order_by(AgentEnrollmentToken.created_at.desc())
    ).all()
    result = []
    for token in tokens:
        group = _require_group(db, user.tenant_id, token.group_id)
        result.append(
            AgentEnrollmentTokenResponse(
                id=token.id,
                name=token.name,
                group_id=group.id,
                group_name=group.name,
                token_prefix=token.token_prefix,
                token_type=token.token_type,
                max_uses=token.max_uses,
                use_count=token.use_count,
                expires_at=token.expires_at,
                used_at=token.used_at,
                last_used_at=token.last_used_at,
                revoked_at=token.revoked_at,
                created_at=token.created_at,
            )
        )
    return result


@router.delete("/agent-enrollment-tokens/{token_id}", status_code=204)
def revoke_enrollment_token(token_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    token = db.get(AgentEnrollmentToken, token_id)
    if token is None or token.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Enrollment token not found")
    if token.token_type == "one_time" and token.used_at is not None:
        raise HTTPException(status_code=409, detail="Enrollment token was already consumed")
    if token.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Enrollment token is already revoked")
    token.revoked_at = now_utc()
    db.add(
        AuditEvent(
            tenant_id=user.tenant_id,
            actor_type="user",
            actor_id=user.id,
            action="agent_enrollment_token.revoked",
            target_type="agent_enrollment_token",
            target_id=token.id,
            details={
                "group_id": token.group_id,
                "token_type": token.token_type,
                "use_count": token.use_count,
            },
        )
    )
    db.commit()
    return Response(status_code=204)


@router.get("/control-catalog", response_model=list[ControlCatalogItem])
def list_control_catalog(user: User = Depends(current_user), db: Session = Depends(get_db)):
    catalog = json.loads(files("lsa").joinpath("data/control_catalog.json").read_text())
    by_id = {item["control_id"]: item for item in catalog}
    rows = db.execute(
        select(Finding.control_id, Finding.title, Finding.category, Finding.module)
        .where(Finding.tenant_id == user.tenant_id)
        .distinct()
        .order_by(Finding.category, Finding.control_id)
    ).all()
    for row in rows:
        by_id[row.control_id] = {
            "control_id": row.control_id,
            "title": row.title,
            "category": row.category,
            "module": row.module,
        }
    ordered = sorted(by_id.values(), key=lambda item: (item["category"], item["control_id"]))
    return [ControlCatalogItem(**item) for item in ordered]


@router.post("/agent/enroll", response_model=AgentEnrollmentResponse, status_code=201)
def enroll_agent(
    request: AgentEnrollmentRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Enrollment token required")
    token_hash = hash_ingestion_token(credentials.credentials)
    candidate = db.scalar(
        select(AgentEnrollmentToken).where(AgentEnrollmentToken.token_hash == token_hash)
    )
    if candidate is None:
        raise HTTPException(status_code=401, detail="Invalid, expired, revoked, consumed, or exhausted enrollment token")
    _lock_tenant(db, candidate.tenant_id)
    enrollment = db.scalar(
        select(AgentEnrollmentToken)
        .where(AgentEnrollmentToken.id == candidate.id)
        .with_for_update()
    )
    token_exhausted = (
        enrollment is not None
        and enrollment.max_uses is not None
        and enrollment.use_count >= enrollment.max_uses
    )
    token_consumed = (
        enrollment is not None
        and enrollment.token_type == "one_time"
        and enrollment.used_at is not None
    )
    if (
        enrollment is None
        or token_consumed
        or token_exhausted
        or enrollment.revoked_at is not None
        or _aware(enrollment.expires_at) <= now_utc()
    ):
        raise HTTPException(status_code=401, detail="Invalid, expired, revoked, consumed, or exhausted enrollment token")
    group = _require_group(db, enrollment.tenant_id, enrollment.group_id)
    if enrollment.platform_command_key_id is None:
        raise HTTPException(
            status_code=409,
            detail="Enrollment token predates platform identity pinning; create a new token",
        )
    platform_key = db.get(PlatformCommandSigningKey, enrollment.platform_command_key_id)
    if (
        platform_key is None
        or platform_key.tenant_id != enrollment.tenant_id
        or platform_key.revoked_at is not None
    ):
        raise HTTPException(status_code=409, detail="Enrollment platform identity is unavailable")
    _, public_key_raw = _validate_public_key(request.public_key)
    fingerprint = hashlib.sha256(public_key_raw).hexdigest()
    identity_agent = db.scalar(
        select(LinuxAgent).where(LinuxAgent.tenant_id == enrollment.tenant_id, LinuxAgent.fingerprint == fingerprint)
    )
    if identity_agent is not None and identity_agent.revoked_at is None:
        raise HTTPException(status_code=409, detail="This agent identity is already enrolled")
    host = db.scalar(
        select(Host).where(Host.tenant_id == enrollment.tenant_id, Host.machine_id_hash == request.machine_id_hash)
    )
    if host is None:
        host = db.scalar(
            select(Host).where(
                Host.tenant_id == enrollment.tenant_id,
                Host.hostname == request.hostname,
                Host.machine_id_hash.like("pending:%"),
                Host.deleted_at.is_(None),
            )
        )
    if host is None:
        host = Host(
            id=str(uuid.uuid4()),
            tenant_id=enrollment.tenant_id,
            hostname=request.hostname,
            machine_id_hash=request.machine_id_hash,
            operating_system=request.operating_system,
            os_family=request.os_family,
            os_version=request.os_version,
            kernel=request.kernel,
            architecture=request.architecture,
        )
        db.add(host)
    elif host.deleted_at is not None:
        raise HTTPException(status_code=409, detail="This host was deleted and cannot be enrolled")
    host_agent = db.scalar(select(LinuxAgent).where(LinuxAgent.host_id == host.id))
    if host_agent is not None and host_agent.revoked_at is None:
        raise HTTPException(status_code=409, detail="This host already has an enrolled agent")
    if identity_agent is not None and host_agent is not None and identity_agent.id != host_agent.id:
        raise HTTPException(status_code=409, detail="Agent identity belongs to a different revoked host")
    host.hostname = request.hostname
    host.fqdn = request.fqdn
    host.machine_id_hash = request.machine_id_hash
    host.operating_system = request.operating_system
    host.os_family = request.os_family
    host.os_version = request.os_version
    host.kernel = request.kernel
    host.architecture = request.architecture
    host.ip_addresses = request.ip_addresses
    host.tags = request.tags
    host.system_info = request.system_info
    raw_ingestion_token = f"lsa_ingest_{secrets.token_urlsafe(32)}"
    ingestion_token = IngestionToken(
        tenant_id=enrollment.tenant_id,
        host_id=host.id,
        name=f"Agent: {request.name}",
        token_prefix=raw_ingestion_token[:20],
        token_hash=hash_ingestion_token(raw_ingestion_token),
    )
    recovering_agent = identity_agent or host_agent
    if recovering_agent is not None and recovering_agent.fingerprint == fingerprint:
        signing_key = db.get(SigningKey, recovering_agent.signing_key_id)
        if signing_key is None:
            raise HTTPException(status_code=409, detail="Revoked agent signing identity is unavailable")
        signing_key.revoked_at = None
        signing_key.host_id = host.id
        signing_key.name = f"Agent: {request.name}"
    else:
        signing_key = SigningKey(
            tenant_id=enrollment.tenant_id,
            host_id=host.id,
            name=f"Agent: {request.name}",
            public_key=request.public_key,
            fingerprint=fingerprint,
        )
        db.add(signing_key)
    db.add(ingestion_token)
    db.flush()
    if recovering_agent is None:
        agent = LinuxAgent(tenant_id=enrollment.tenant_id, host_id=host.id)
    else:
        agent = recovering_agent
    agent.group_id = group.id
    agent.ingestion_token_id = ingestion_token.id
    agent.signing_key_id = signing_key.id
    agent.name = request.name
    agent.public_key = request.public_key
    agent.fingerprint = fingerprint
    agent.agent_version = request.agent_version
    agent.capabilities = request.capabilities
    agent.capabilities_attested_at = now_utc()
    agent.platform_command_key_id = platform_key.id
    agent.platform_command_key_fingerprint = platform_key.fingerprint
    agent.platform_envelope_sequence = 1
    agent.last_seen_at = now_utc()
    agent.last_policy_version = None
    agent.revoked_at = None
    agent.pending_platform_command_key_id = None
    agent.pending_platform_command_key_fingerprint = None
    staged_key = db.scalar(
        select(PlatformCommandSigningKey).where(
            PlatformCommandSigningKey.tenant_id == enrollment.tenant_id,
            PlatformCommandSigningKey.status == "staged",
            PlatformCommandSigningKey.revoked_at.is_(None),
        )
    )
    if staged_key is not None:
        agent.pending_platform_command_key_id = staged_key.id
        agent.pending_platform_command_key_fingerprint = staged_key.fingerprint
    db.add(agent)
    db.flush()
    enrollment_used_at = now_utc()
    enrollment.use_count += 1
    enrollment.last_used_at = enrollment_used_at
    if enrollment.token_type == "one_time":
        enrollment.used_at = enrollment_used_at
    version = _latest_policy_version(db, group.policy_id)
    db.add(
        AuditEvent(
            tenant_id=enrollment.tenant_id,
            actor_type="agent",
            actor_id=agent.id,
            action="agent.reenrolled" if recovering_agent is not None else "agent.enrolled",
            target_type="host",
            target_id=host.id,
            details={
                "group_id": group.id,
                "policy_version": version.version,
                "fingerprint": fingerprint,
                "enrollment_token_id": enrollment.id,
                "enrollment_token_type": enrollment.token_type,
                "enrollment_token_use_count": enrollment.use_count,
                "recovered_revoked_agent": recovering_agent is not None,
            },
        )
    )
    issued_at = now_utc()
    envelope = {
        "schema_version": "1.0",
        "kind": "agent-enrollment",
        "key_id": platform_key.id,
        "sequence": 1,
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(minutes=5)).isoformat(),
        "agent_id": agent.id,
        "payload": {
            "agent_id": agent.id,
            "host_id": host.id,
            "group_id": group.id,
            "ingestion_token": raw_ingestion_token,
            "signing_key_id": signing_key.id,
            "policy_version": version.version,
            "agent_identity_fingerprint": fingerprint,
            "execution_enabled": False,
            "signed_control_required": SIGNED_PLATFORM_CONTROL_CAPABILITY in request.capabilities,
            "platform_key_rotation": (
                platform_key_rotation_proof(platform_key, staged_key)
                if staged_key is not None
                else None
            ),
        },
    }
    signature = sign_platform_envelope(platform_key, envelope)
    db.commit()
    return AgentEnrollmentResponse(
        agent_id=agent.id,
        host_id=host.id,
        group_id=group.id,
        ingestion_token=raw_ingestion_token,
        signing_key_id=signing_key.id,
        policy_version=version.version,
        platform_trust=platform_trust_descriptor(platform_key),
        platform_envelope=envelope,
        platform_signature=signature,
    )


def _effective_policy(db: Session, agent: LinuxAgent) -> AgentEffectivePolicyResponse:
    group = _require_group(db, agent.tenant_id, agent.group_id)
    policy = _require_policy(db, agent.tenant_id, group.policy_id)
    version = _latest_policy_version(db, policy.id)
    return AgentEffectivePolicyResponse(
        policy_id=policy.id,
        policy_name=policy.name,
        policy_version=version.version,
        group_id=group.id,
        group_name=group.name,
        default_mode=version.default_mode.value,
        control_modes=version.control_modes or {},
        settings=version.settings or {},
        enforcement_enabled=False,
    )


def _signed_control_response(
    db: Session,
    agent: LinuxAgent,
    kind: str,
    payload: dict[str, object],
) -> PlatformControlResponse:
    if agent.platform_command_key_id is None:
        raise HTTPException(status_code=409, detail="Agent platform trust is not pinned; re-enroll the agent")
    platform_key = db.get(PlatformCommandSigningKey, agent.platform_command_key_id)
    if (
        platform_key is None
        or platform_key.tenant_id != agent.tenant_id
        or platform_key.revoked_at is not None
        or platform_key.fingerprint != agent.platform_command_key_fingerprint
    ):
        raise HTTPException(status_code=409, detail="Agent platform trust is unavailable")
    agent.platform_envelope_sequence += 1
    issued_at = now_utc()
    rotation: dict[str, object] | None = None
    if agent.pending_platform_command_key_id is not None:
        staged_key = db.get(PlatformCommandSigningKey, agent.pending_platform_command_key_id)
        if (
            staged_key is not None
            and staged_key.status == "staged"
            and staged_key.revoked_at is None
            and staged_key.fingerprint == agent.pending_platform_command_key_fingerprint
        ):
            rotation = platform_key_rotation_proof(platform_key, staged_key)
    elif platform_key.status == "active" and platform_key.supersedes_key_id is not None:
        rotation = {
            "phase": "activated",
            "next_key": platform_trust_descriptor(platform_key),
        }
    envelope = {
        "schema_version": "1.0",
        "kind": kind,
        "key_id": platform_key.id,
        "sequence": agent.platform_envelope_sequence,
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(minutes=5)).isoformat(),
        "agent_id": agent.id,
        "payload": {
            **payload,
            "agent_id": agent.id,
            "agent_identity_fingerprint": agent.fingerprint,
            "execution_enabled": False,
            "platform_key_rotation": rotation,
        },
    }
    return PlatformControlResponse(
        platform_trust=platform_trust_descriptor(platform_key),
        platform_envelope=envelope,
        platform_signature=sign_platform_envelope(platform_key, envelope),
    )


def _requires_signed_control(agent: LinuxAgent) -> bool:
    return SIGNED_PLATFORM_CONTROL_CAPABILITY in (agent.capabilities or [])


def _principal_requires_signed_control(principal: AgentPrincipal) -> bool:
    return principal.signed_control_requested or _requires_signed_control(principal.agent)


@router.get("/agent/policy", response_model=PlatformControlResponse | AgentEffectivePolicyResponse)
def get_agent_policy(principal: AgentPrincipal = Depends(signed_agent_principal), db: Session = Depends(get_db)):
    principal.agent.last_seen_at = now_utc()
    policy = _effective_policy(db, principal.agent)
    response = (
        _signed_control_response(db, principal.agent, "agent-policy", policy.model_dump(mode="json"))
        if _principal_requires_signed_control(principal)
        else policy
    )
    db.commit()
    return response


@router.post("/agent/heartbeat", response_model=PlatformControlResponse | AgentHeartbeatResponse)
def agent_heartbeat(
    request: AgentHeartbeatRequest,
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
):
    agent = principal.agent
    policy = _effective_policy(db, agent)
    signed_control_required = _principal_requires_signed_control(principal)
    agent.agent_version = request.agent_version
    agent.capabilities = list(request.capabilities)
    if signed_control_required and SIGNED_PLATFORM_CONTROL_CAPABILITY not in agent.capabilities:
        agent.capabilities.append(SIGNED_PLATFORM_CONTROL_CAPABILITY)
    agent.capabilities_attested_at = now_utc()
    agent.last_seen_at = agent.capabilities_attested_at
    agent.last_policy_version = request.policy_version
    if request.platform_key_ack_fingerprint is not None:
        if (
            agent.pending_platform_command_key_id is None
            or agent.pending_platform_command_key_fingerprint
            != request.platform_key_ack_fingerprint
        ):
            raise HTTPException(status_code=409, detail="Platform key acknowledgement does not match the staged key")
        agent.platform_command_key_acknowledged_at = now_utc()
    heartbeat = AgentHeartbeatResponse(
        accepted_at=agent.last_seen_at,
        policy_changed=request.policy_version != policy.policy_version,
        policy_version=policy.policy_version,
    )
    response = (
        _signed_control_response(db, agent, "agent-heartbeat", heartbeat.model_dump(mode="json"))
        if signed_control_required
        else heartbeat
    )
    db.commit()
    return response


def _require_remediation_validation_agent(agent: LinuxAgent) -> None:
    capabilities = set(agent.capabilities or [])
    required = {
        SIGNED_PLATFORM_CONTROL_CAPABILITY,
        REMEDIATION_CONTRACT_VALIDATION_CAPABILITY,
        REMEDIATION_DRY_RUN_CAPABILITY,
    }
    if not required <= capabilities:
        raise HTTPException(
            status_code=409,
            detail="Agent has not attested the signed remediation dry-run capabilities",
        )


def _require_remediation_checkpoint_agent(agent: LinuxAgent) -> None:
    _require_remediation_validation_agent(agent)
    capabilities = set(agent.capabilities or [])
    if not {REMEDIATION_RECOVERY_PLANNING_CAPABILITY, REMEDIATION_CHECKPOINT_CAPABILITY} <= capabilities:
        raise HTTPException(
            status_code=409,
            detail="Agent has not attested encrypted remediation checkpoint support",
        )


def _require_recovery_verification_agent(agent: LinuxAgent) -> None:
    _require_remediation_checkpoint_agent(agent)
    if REMEDIATION_RECOVERY_VERIFICATION_CAPABILITY not in set(agent.capabilities or []):
        raise HTTPException(
            status_code=409,
            detail="Agent has not attested encrypted recovery verification support",
        )


@router.get(
    "/agent/remediation-validations/next",
    response_model=PlatformControlResponse,
)
def next_remediation_validation(
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
) -> PlatformControlResponse:
    _require_remediation_validation_agent(principal.agent)
    now = now_utc()
    selected: RemediationValidationJob | None = None
    jobs = db.scalars(
        select(RemediationValidationJob)
        .where(
            RemediationValidationJob.agent_id == principal.agent.id,
            RemediationValidationJob.tenant_id == principal.agent.tenant_id,
            RemediationValidationJob.status.in_(["queued", "delivered"]),
        )
        .order_by(RemediationValidationJob.requested_at)
        .with_for_update()
    ).all()
    for job in jobs:
        change_set = db.get(RemediationChangeSet, job.change_set_id)
        endorsement = job.contract.get("platform_endorsement", {})
        if (
            change_set is None
            or change_set.status != "authorized"
            or _aware(change_set.maintenance_window_end) <= now
            or validation_contract_digest(job.contract) != job.contract_digest
            or not isinstance(endorsement, dict)
            or endorsement.get("platform_command_key_id")
            != principal.agent.platform_command_key_id
        ):
            job.status = "expired"
            job.completed_at = now
            job.error = "Validation contract is no longer eligible for delivery"
            continue
        selected = job
        break
    payload: dict[str, object] = {"validation": None}
    if selected is not None:
        if selected.status == "queued":
            selected.status = "delivered"
            selected.delivered_at = now
        selected.lease_expires_at = now + timedelta(seconds=REMEDIATION_VALIDATION_LEASE_SECONDS)
        payload["validation"] = {
            "validation_id": selected.id,
            "change_set_id": selected.change_set_id,
            "contract_digest": selected.contract_digest,
            "contract": selected.contract,
        }
    principal.agent.last_seen_at = now
    response = _signed_control_response(
        db,
        principal.agent,
        "remediation-validation",
        payload,
    )
    db.commit()
    return response


@router.post(
    "/agent/remediation-validations/{validation_id}/receipt",
    response_model=PlatformControlResponse,
)
def submit_remediation_validation_receipt(
    validation_id: str,
    request: RemediationValidationReceiptSubmission,
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
) -> PlatformControlResponse:
    _require_remediation_validation_agent(principal.agent)
    job = db.scalar(
        select(RemediationValidationJob)
        .where(
            RemediationValidationJob.id == validation_id,
            RemediationValidationJob.agent_id == principal.agent.id,
            RemediationValidationJob.tenant_id == principal.agent.tenant_id,
        )
        .with_for_update()
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Remediation validation job not found")
    # Preserve the exact signed shape for backward-compatible 0.8 receipts that
    # predate the optional recovery-plan field.
    receipt = request.receipt.model_dump(mode="json", exclude_unset=True)
    if job.status in {"ready", "blocked"}:
        if job.receipt != receipt or job.receipt_signature != request.signature:
            raise HTTPException(status_code=409, detail="Validation job already has another receipt")
        response = _signed_control_response(
            db,
            principal.agent,
            "remediation-validation-receipt",
            {"validation_id": job.id, "status": job.status, "accepted": True},
        )
        db.commit()
        return response
    if job.status != "delivered":
        raise HTTPException(status_code=409, detail="Validation job is not awaiting a receipt")
    if (
        validation_contract_digest(job.contract) != job.contract_digest
        or receipt["validation_id"] != job.id
        or receipt["change_set_id"] != job.change_set_id
        or receipt["contract_digest"] != job.contract_digest
        or receipt["agent_id"] != job.agent_id
        or receipt["host_id"] != job.host_id
        or receipt["execution_enabled"] is not False
        or receipt["changes_applied"] is not False
        or not verify_validation_receipt(
            principal.agent.public_key,
            receipt,
            request.signature,
        )
    ):
        raise HTTPException(status_code=409, detail="Validation receipt trust binding is invalid")
    evaluated_at = request.receipt.evaluated_at
    if evaluated_at.tzinfo is None:
        raise HTTPException(status_code=409, detail="Validation receipt time must include a timezone")
    evaluated_at = evaluated_at.astimezone(now_utc().tzinfo)
    change_set = db.get(RemediationChangeSet, job.change_set_id)
    if (
        job.delivered_at is None
        or evaluated_at < _aware(job.delivered_at) - timedelta(minutes=5)
        or evaluated_at > now_utc() + timedelta(minutes=5)
        or change_set is None
        or evaluated_at > _aware(change_set.maintenance_window_end)
    ):
        raise HTTPException(status_code=409, detail="Validation receipt time is outside its contract")
    expected_actions = {
        item.get("plan_id"): item.get("action_digest")
        for item in job.contract.get("actions", [])
        if isinstance(item, dict)
    }
    received_actions = {item.plan_id: item for item in request.receipt.action_results}
    if len(received_actions) != len(request.receipt.action_results):
        raise HTTPException(status_code=409, detail="Validation receipt repeats an action result")
    if any(
        plan_id not in expected_actions
        or expected_actions[plan_id] != result.action_digest
        for plan_id, result in received_actions.items()
    ):
        raise HTTPException(status_code=409, detail="Validation receipt action binding is invalid")
    recovery_plan = receipt.get("recovery_plan")
    recovery_capable = REMEDIATION_RECOVERY_PLANNING_CAPABILITY in (
        principal.agent.capabilities or []
    )
    if recovery_plan is not None and not validate_recovery_plan(job.contract, recovery_plan):
        raise HTTPException(status_code=409, detail="Recovery plan binding is invalid")
    if recovery_capable and recovery_plan is None and not (
        receipt["status"] == "blocked" and receipt["error"]
    ):
        raise HTTPException(status_code=409, detail="Recovery-capable receipt omitted its plan")
    if recovery_plan is not None and recovery_plan["status"] == "blocked" and receipt["status"] != "blocked":
        raise HTTPException(status_code=409, detail="Blocked recovery plan requires a blocked receipt")
    if receipt["status"] == "ready":
        if (
            set(received_actions) != set(expected_actions)
            or any(result.status != "ready" for result in received_actions.values())
            or receipt["error"] is not None
            or (recovery_capable and recovery_plan["status"] != "ready")
        ):
            raise HTTPException(status_code=409, detail="Ready receipt has incomplete action results")
    elif set(received_actions) != set(expected_actions) and not receipt["error"]:
        raise HTTPException(status_code=409, detail="Blocked receipt must explain incomplete results")
    job.status = receipt["status"]
    job.receipt = receipt
    job.receipt_signature = request.signature
    job.error = receipt["error"]
    job.completed_at = now_utc()
    principal.agent.last_seen_at = job.completed_at
    db.add(
        AuditEvent(
            tenant_id=job.tenant_id,
            actor_type="agent",
            actor_id=principal.agent.id,
            action=f"remediation_validation.{job.status}",
            target_type="remediation_validation_job",
            target_id=job.id,
            details={
                "change_set_id": job.change_set_id,
                "contract_digest": job.contract_digest,
                "recovery_status": recovery_plan["status"] if recovery_plan else "not_reported",
                "recovery_checkpoints": len(recovery_plan["entries"]) if recovery_plan else 0,
                "changes_applied": False,
            },
        )
    )
    response = _signed_control_response(
        db,
        principal.agent,
        "remediation-validation-receipt",
        {"validation_id": job.id, "status": job.status, "accepted": True},
    )
    db.commit()
    return response


@router.get("/agent/remediation-checkpoints/next", response_model=PlatformControlResponse)
def next_remediation_checkpoint(
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
) -> PlatformControlResponse:
    _require_remediation_checkpoint_agent(principal.agent)
    now = now_utc()
    selected: RemediationCheckpointJob | None = None
    jobs = db.scalars(
        select(RemediationCheckpointJob)
        .where(
            RemediationCheckpointJob.agent_id == principal.agent.id,
            RemediationCheckpointJob.tenant_id == principal.agent.tenant_id,
            RemediationCheckpointJob.status.in_(["queued", "delivered"]),
        )
        .order_by(RemediationCheckpointJob.requested_at)
        .with_for_update()
    ).all()
    for job in jobs:
        change_set = db.get(RemediationChangeSet, job.change_set_id)
        if (
            change_set is None
            or change_set.status != "authorized"
            or _aware(change_set.maintenance_window_end) <= now
            or validation_contract_digest(job.contract) != job.contract_digest
            or not validate_recovery_plan(job.contract, job.recovery_plan)
            or job.recovery_plan.get("status") != "ready"
        ):
            job.status = "expired"
            job.completed_at = now
            job.error = "Checkpoint contract is no longer eligible for delivery"
            continue
        selected = job
        break
    payload: dict[str, object] = {"checkpoint": None}
    if selected is not None:
        if selected.status == "queued":
            selected.status = "delivered"
            selected.delivered_at = now
        selected.lease_expires_at = now + timedelta(seconds=REMEDIATION_VALIDATION_LEASE_SECONDS)
        payload["checkpoint"] = {
            "checkpoint_job_id": selected.id,
            "validation_id": selected.validation_job_id,
            "change_set_id": selected.change_set_id,
            "contract_digest": selected.contract_digest,
            "contract": selected.contract,
            "recovery_plan": selected.recovery_plan,
        }
    principal.agent.last_seen_at = now
    response = _signed_control_response(db, principal.agent, "remediation-checkpoint", payload)
    db.commit()
    return response


@router.post(
    "/agent/remediation-checkpoints/{checkpoint_job_id}/receipt",
    response_model=PlatformControlResponse,
)
def submit_remediation_checkpoint_receipt(
    checkpoint_job_id: str,
    request: RemediationCheckpointReceiptSubmission,
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
) -> PlatformControlResponse:
    _require_remediation_checkpoint_agent(principal.agent)
    job = db.scalar(
        select(RemediationCheckpointJob)
        .where(
            RemediationCheckpointJob.id == checkpoint_job_id,
            RemediationCheckpointJob.agent_id == principal.agent.id,
            RemediationCheckpointJob.tenant_id == principal.agent.tenant_id,
        )
        .with_for_update()
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Remediation checkpoint job not found")
    receipt = request.receipt.model_dump(mode="json")
    if job.status in {"ready", "blocked"}:
        if job.receipt != receipt or job.receipt_signature != request.signature:
            raise HTTPException(status_code=409, detail="Checkpoint job already has another receipt")
        response = _signed_control_response(
            db,
            principal.agent,
            "remediation-checkpoint-receipt",
            {"checkpoint_job_id": job.id, "status": job.status, "accepted": True},
        )
        db.commit()
        return response
    if job.status != "delivered":
        raise HTTPException(status_code=409, detail="Checkpoint job is not awaiting a receipt")
    if (
        validation_contract_digest(job.contract) != job.contract_digest
        or not validate_recovery_plan(job.contract, job.recovery_plan)
        or receipt["checkpoint_job_id"] != job.id
        or receipt["validation_id"] != job.validation_job_id
        or receipt["change_set_id"] != job.change_set_id
        or receipt["contract_digest"] != job.contract_digest
        or receipt["agent_id"] != job.agent_id
        or receipt["host_id"] != job.host_id
        or not verify_validation_receipt(principal.agent.public_key, receipt, request.signature)
    ):
        raise HTTPException(status_code=409, detail="Checkpoint receipt trust binding is invalid")
    prepared_at = request.receipt.prepared_at
    change_set = db.get(RemediationChangeSet, job.change_set_id)
    if (
        prepared_at.tzinfo is None
        or job.delivered_at is None
        or prepared_at < _aware(job.delivered_at) - timedelta(minutes=5)
        or prepared_at > now_utc() + timedelta(minutes=5)
        or change_set is None
        or prepared_at > _aware(change_set.maintenance_window_end)
    ):
        raise HTTPException(status_code=409, detail="Checkpoint receipt time is outside its contract")
    expected = {entry["checkpoint_id"]: entry for entry in job.recovery_plan["entries"]}
    received = {item.checkpoint_id: item for item in request.receipt.checkpoint_results}
    if len(received) != len(request.receipt.checkpoint_results) or set(received) != set(expected):
        raise HTTPException(status_code=409, detail="Checkpoint receipt coverage is invalid")
    for checkpoint_id, result in received.items():
        source_state = expected[checkpoint_id]["source_state"]
        if result.source_state != source_state:
            raise HTTPException(status_code=409, detail="Checkpoint source binding is invalid")
        if result.status == "blocked" and (
            result.backup_created is not False
            or result.encrypted_blob_digest is not None
            or result.encrypted_size_bytes is not None
            or not result.error
        ):
            raise HTTPException(status_code=409, detail="Blocked checkpoint evidence is invalid")
        if result.status == "ready" and result.error is not None:
            raise HTTPException(status_code=409, detail="Ready checkpoint evidence is invalid")
        if source_state == "regular_file" and result.status == "ready" and (
            result.backup_created is not True
            or result.encrypted_blob_digest is None
            or result.encrypted_size_bytes is None
        ):
            raise HTTPException(status_code=409, detail="Regular-file checkpoint evidence is incomplete")
        if source_state == "absent" and (
            result.backup_created is not False
            or result.encrypted_blob_digest is not None
            or result.encrypted_size_bytes is not None
        ):
            raise HTTPException(status_code=409, detail="Absent-file checkpoint evidence is invalid")
    if receipt["status"] == "ready" and (
        receipt["journal_state"] != "checkpointed"
        or any(item.status != "ready" for item in received.values())
        or receipt["error"] is not None
    ):
        raise HTTPException(status_code=409, detail="Ready checkpoint receipt is incomplete")
    if receipt["status"] == "blocked" and (
        receipt["journal_state"] != "blocked"
        or not receipt["error"]
        or not any(item.status == "blocked" for item in received.values())
    ):
        raise HTTPException(status_code=409, detail="Blocked checkpoint receipt lacks failure evidence")
    result_documents = [item.model_dump(mode="json") for item in request.receipt.checkpoint_results]
    if receipt["journal_digest"] != checkpoint_journal_digest(
        checkpoint_job_id=job.id,
        validation_id=job.validation_job_id,
        contract_digest=job.contract_digest,
        recovery_plan=job.recovery_plan,
        state=receipt["journal_state"],
        checkpoint_results=result_documents,
        error=receipt["error"],
    ):
        raise HTTPException(status_code=409, detail="Checkpoint journal digest is invalid")
    job.status = receipt["status"]
    job.receipt = receipt
    job.receipt_signature = request.signature
    job.error = receipt["error"]
    job.completed_at = now_utc()
    principal.agent.last_seen_at = job.completed_at
    db.add(
        AuditEvent(
            tenant_id=job.tenant_id,
            actor_type="agent",
            actor_id=principal.agent.id,
            action=f"remediation_checkpoint.{job.status}",
            target_type="remediation_checkpoint_job",
            target_id=job.id,
            details={
                "change_set_id": job.change_set_id,
                "validation_job_id": job.validation_job_id,
                "journal_state": receipt["journal_state"],
                "checkpoint_count": len(received),
                "storage_scope": "agent_local_encrypted",
                "changes_applied": False,
            },
        )
    )
    response = _signed_control_response(
        db,
        principal.agent,
        "remediation-checkpoint-receipt",
        {"checkpoint_job_id": job.id, "status": job.status, "accepted": True},
    )
    db.commit()
    return response


@router.get(
    "/agent/remediation-recovery-verifications/next",
    response_model=PlatformControlResponse,
)
def next_recovery_verification(
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
) -> PlatformControlResponse:
    _require_recovery_verification_agent(principal.agent)
    now = now_utc()
    selected: RemediationRecoveryVerificationJob | None = None
    jobs = db.scalars(
        select(RemediationRecoveryVerificationJob)
        .where(
            RemediationRecoveryVerificationJob.agent_id == principal.agent.id,
            RemediationRecoveryVerificationJob.tenant_id == principal.agent.tenant_id,
            RemediationRecoveryVerificationJob.status.in_(["queued", "delivered"]),
        )
        .order_by(RemediationRecoveryVerificationJob.requested_at)
        .with_for_update()
    ).all()
    for job in jobs:
        change_set = db.get(RemediationChangeSet, job.change_set_id)
        checkpoint = db.get(RemediationCheckpointJob, job.checkpoint_job_id)
        if (
            change_set is None
            or change_set.status != "authorized"
            or _aware(change_set.maintenance_window_end) <= now
            or checkpoint is None
            or checkpoint.status != "ready"
            or not isinstance(checkpoint.receipt, dict)
            or checkpoint.receipt.get("journal_digest") != job.checkpoint_journal_digest
            or validation_contract_digest(job.contract) != job.contract_digest
            or not validate_recovery_plan(job.contract, job.recovery_plan)
            or job.recovery_plan.get("status") != "ready"
        ):
            job.status = "expired"
            job.completed_at = now
            job.error = "Recovery verification contract is no longer eligible for delivery"
            continue
        selected = job
        break
    payload: dict[str, object] = {"verification": None}
    if selected is not None:
        if selected.status == "queued":
            selected.status = "delivered"
            selected.delivered_at = now
        selected.lease_expires_at = now + timedelta(seconds=REMEDIATION_VALIDATION_LEASE_SECONDS)
        payload["verification"] = {
            "verification_job_id": selected.id,
            "checkpoint_job_id": selected.checkpoint_job_id,
            "validation_id": selected.validation_job_id,
            "change_set_id": selected.change_set_id,
            "contract_digest": selected.contract_digest,
            "contract": selected.contract,
            "recovery_plan": selected.recovery_plan,
            "checkpoint_journal_digest": selected.checkpoint_journal_digest,
        }
    principal.agent.last_seen_at = now
    response = _signed_control_response(
        db, principal.agent, "remediation-recovery-verification", payload
    )
    db.commit()
    return response


@router.post(
    "/agent/remediation-recovery-verifications/{verification_job_id}/receipt",
    response_model=PlatformControlResponse,
)
def submit_recovery_verification_receipt(
    verification_job_id: str,
    request: RemediationRecoveryVerificationReceiptSubmission,
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
) -> PlatformControlResponse:
    _require_recovery_verification_agent(principal.agent)
    job = db.scalar(
        select(RemediationRecoveryVerificationJob)
        .where(
            RemediationRecoveryVerificationJob.id == verification_job_id,
            RemediationRecoveryVerificationJob.agent_id == principal.agent.id,
            RemediationRecoveryVerificationJob.tenant_id == principal.agent.tenant_id,
        )
        .with_for_update()
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Recovery verification job not found")
    receipt = request.receipt.model_dump(mode="json")
    if job.status in {"ready", "blocked"}:
        if job.receipt != receipt or job.receipt_signature != request.signature:
            raise HTTPException(status_code=409, detail="Recovery verification job already has another receipt")
        response = _signed_control_response(
            db,
            principal.agent,
            "remediation-recovery-verification-receipt",
            {"verification_job_id": job.id, "status": job.status, "accepted": True},
        )
        db.commit()
        return response
    if job.status != "delivered":
        raise HTTPException(status_code=409, detail="Recovery verification job is not awaiting a receipt")
    if (
        validation_contract_digest(job.contract) != job.contract_digest
        or not validate_recovery_plan(job.contract, job.recovery_plan)
        or receipt["verification_job_id"] != job.id
        or receipt["checkpoint_job_id"] != job.checkpoint_job_id
        or receipt["validation_id"] != job.validation_job_id
        or receipt["change_set_id"] != job.change_set_id
        or receipt["contract_digest"] != job.contract_digest
        or receipt["checkpoint_journal_digest"] != job.checkpoint_journal_digest
        or receipt["agent_id"] != job.agent_id
        or receipt["host_id"] != job.host_id
        or not verify_validation_receipt(principal.agent.public_key, receipt, request.signature)
    ):
        raise HTTPException(status_code=409, detail="Recovery verification receipt trust binding is invalid")
    verified_at = request.receipt.verified_at
    change_set = db.get(RemediationChangeSet, job.change_set_id)
    if (
        verified_at.tzinfo is None
        or job.delivered_at is None
        or verified_at < _aware(job.delivered_at) - timedelta(minutes=5)
        or verified_at > now_utc() + timedelta(minutes=5)
        or change_set is None
        or verified_at > _aware(change_set.maintenance_window_end)
    ):
        raise HTTPException(status_code=409, detail="Recovery verification time is outside its contract")
    expected = {entry["checkpoint_id"]: entry for entry in job.recovery_plan["entries"]}
    checkpoint = db.get(RemediationCheckpointJob, job.checkpoint_job_id)
    checkpoint_results = {
        item["checkpoint_id"]: item
        for item in (checkpoint.receipt or {}).get("checkpoint_results", [])
        if isinstance(item, dict)
    } if checkpoint is not None else {}
    received = {item.checkpoint_id: item for item in request.receipt.verification_results}
    if len(received) != len(request.receipt.verification_results) or set(received) != set(expected):
        raise HTTPException(status_code=409, detail="Recovery verification coverage is invalid")
    for checkpoint_id, result in received.items():
        source_state = expected[checkpoint_id]["source_state"]
        if result.source_state != source_state:
            raise HTTPException(status_code=409, detail="Recovery verification source binding is invalid")
        if result.status == "blocked" and (
            result.encrypted_blob_digest is not None
            or result.encrypted_size_bytes is not None
            or not result.error
        ):
            raise HTTPException(status_code=409, detail="Blocked recovery verification evidence is invalid")
        if result.status == "verified" and result.error is not None:
            raise HTTPException(status_code=409, detail="Verified recovery evidence is invalid")
        checkpoint_result = checkpoint_results.get(checkpoint_id, {})
        if source_state == "regular_file" and result.status == "verified" and (
            result.encrypted_blob_digest != checkpoint_result.get("encrypted_blob_digest")
            or result.encrypted_size_bytes != checkpoint_result.get("encrypted_size_bytes")
        ):
            raise HTTPException(status_code=409, detail="Encrypted checkpoint verification evidence is invalid")
        if source_state == "absent" and (
            result.encrypted_blob_digest is not None or result.encrypted_size_bytes is not None
        ):
            raise HTTPException(status_code=409, detail="Absent-source verification evidence is invalid")
    if receipt["status"] == "ready" and (
        receipt["verification_state"] != "verified"
        or any(item.status != "verified" for item in received.values())
        or receipt["error"] is not None
    ):
        raise HTTPException(status_code=409, detail="Ready recovery verification receipt is incomplete")
    if receipt["status"] == "blocked" and (
        receipt["verification_state"] != "blocked"
        or not receipt["error"]
        or not any(item.status == "blocked" for item in received.values())
    ):
        raise HTTPException(status_code=409, detail="Blocked recovery verification receipt lacks failure evidence")
    job.status = receipt["status"]
    job.receipt = receipt
    job.receipt_signature = request.signature
    job.error = receipt["error"]
    job.completed_at = now_utc()
    principal.agent.last_seen_at = job.completed_at
    db.add(
        AuditEvent(
            tenant_id=job.tenant_id,
            actor_type="agent",
            actor_id=principal.agent.id,
            action=f"remediation_recovery_verification.{job.status}",
            target_type="remediation_recovery_verification_job",
            target_id=job.id,
            details={
                "change_set_id": job.change_set_id,
                "checkpoint_job_id": job.checkpoint_job_id,
                "verification_count": len(received),
                "changes_applied": False,
            },
        )
    )
    response = _signed_control_response(
        db,
        principal.agent,
        "remediation-recovery-verification-receipt",
        {"verification_job_id": job.id, "status": job.status, "accepted": True},
    )
    db.commit()
    return response


@router.get("/agent/tasks/next", response_model=PlatformControlResponse | AgentTaskResponse | None)
def next_agent_task(principal: AgentPrincipal = Depends(signed_agent_principal), db: Session = Depends(get_db)):
    agent = principal.agent
    stale_lease = now_utc() - timedelta(seconds=AGENT_TASK_LEASE_SECONDS)
    task = db.scalar(
        select(AgentTask)
        .where(
            AgentTask.agent_id == agent.id,
            AgentTask.tenant_id == agent.tenant_id,
            or_(
                AgentTask.status == "queued",
                (AgentTask.status == "dispatched") & (AgentTask.dispatched_at < stale_lease),
            ),
        )
        .order_by(AgentTask.created_at)
        .with_for_update()
    )
    agent.last_seen_at = now_utc()
    if task is not None:
        task.status = "dispatched"
        task.dispatched_at = now_utc()
    task_payload = AgentTaskResponse.model_validate(task, from_attributes=True).model_dump(mode="json") if task else None
    response = (
        _signed_control_response(db, agent, "agent-task", {"task": task_payload})
        if _principal_requires_signed_control(principal)
        else task
    )
    db.commit()
    return response


@router.post("/agent/tasks/{task_id}/complete", response_model=PlatformControlResponse | AgentTaskResponse)
def complete_agent_task(
    task_id: str,
    request: AgentTaskCompletion,
    principal: AgentPrincipal = Depends(signed_agent_principal),
    db: Session = Depends(get_db),
):
    task = db.get(AgentTask, task_id)
    if task is None or task.agent_id != principal.agent.id or task.tenant_id != principal.agent.tenant_id:
        raise HTTPException(status_code=404, detail="Agent task not found")
    if task.status != "dispatched":
        raise HTTPException(status_code=409, detail="Agent task is not in progress")
    task.status = request.status
    task.result = request.result
    task.error = request.error
    task.completed_at = now_utc()
    principal.agent.last_seen_at = task.completed_at
    db.add(
        AuditEvent(
            tenant_id=task.tenant_id,
            actor_type="agent",
            actor_id=principal.agent.id,
            action=f"agent.audit_{request.status}",
            target_type="agent_task",
            target_id=task.id,
            details={"error": request.error},
        )
    )
    task_payload = AgentTaskResponse.model_validate(task, from_attributes=True).model_dump(mode="json")
    response = (
        _signed_control_response(
            db, principal.agent, "agent-task-completion", {"task": task_payload}
        )
        if _principal_requires_signed_control(principal)
        else task
    )
    db.commit()
    return response
