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
from sqlalchemy import func, select
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
    AuditEvent,
    Finding,
    Host,
    IngestionToken,
    LinuxAgent,
    PolicyMode,
    SigningKey,
    User,
    now_utc,
)
from lsa.schemas import (
    AgentEffectivePolicyResponse,
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
    AgentPolicyUpdate,
    ControlCatalogItem,
    LinuxAgentResponse,
)
from lsa.security import hash_ingestion_token


router = APIRouter(tags=["agents"])
AGENT_CLOCK_SKEW_SECONDS = 300


@dataclass(frozen=True)
class AgentPrincipal:
    agent: LinuxAgent


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=now_utc().tzinfo)
    return value


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
        **settings,
    }
    try:
        schedule = int(result["schedule_minutes"])
        jitter = int(result["jitter_seconds"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Policy schedule and jitter must be integers") from exc
    if schedule < 5 or schedule > 10080:
        raise HTTPException(status_code=422, detail="Policy schedule must be between 5 and 10080 minutes")
    if jitter < 0 or jitter > 3600:
        raise HTTPException(status_code=422, detail="Policy jitter must be between 0 and 3600 seconds")
    result["schedule_minutes"] = schedule
    result["jitter_seconds"] = jitter
    result["remediation_approval"] = "required"
    return result


def _policy_response(db: Session, policy: AgentPolicy) -> AgentPolicyResponse:
    version = _latest_policy_version(db, policy.id)
    assigned_groups = db.scalar(
        select(func.count()).select_from(AgentGroup).where(AgentGroup.policy_id == policy.id)
    ) or 0
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
    agent_count = db.scalar(
        select(func.count()).select_from(LinuxAgent).where(
            LinuxAgent.group_id == group.id, LinuxAgent.revoked_at.is_(None)
        )
    ) or 0
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
        last_seen_at=agent.last_seen_at,
        last_policy_version=agent.last_policy_version,
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
    agent = db.get(LinuxAgent, agent_id)
    if agent is None or agent.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Unknown or revoked agent")
    public_key, _ = _validate_public_key(agent.public_key)
    body_hash = hashlib.sha256(await request.body()).hexdigest()
    message = f"{request.method}\n{request.url.path}\n{timestamp_text}\n{body_hash}".encode()
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise HTTPException(status_code=401, detail="Invalid agent signature") from exc
    return AgentPrincipal(agent=agent)


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
    policy = AgentPolicy(
        tenant_id=user.tenant_id, name=request.name.strip(), description=request.description.strip()
    )
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
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent_policy.created", target_type="agent_policy", target_id=policy.id, details={"name": policy.name, "version": 1}))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An agent policy with this name already exists") from exc
    return _policy_response(db, policy)


@router.put("/agent-policies/{policy_id}", response_model=AgentPolicyResponse)
def update_policy(policy_id: str, request: AgentPolicyUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    policy = db.scalar(
        select(AgentPolicy).where(
            AgentPolicy.id == policy_id, AgentPolicy.tenant_id == user.tenant_id
        ).with_for_update()
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
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent_policy.version_published", target_type="agent_policy", target_id=policy.id, details={"version": version.version, "enforcement_enabled": False}))
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
    group = AgentGroup(tenant_id=user.tenant_id, policy_id=request.policy_id, name=request.name.strip(), description=request.description.strip())
    db.add(group)
    db.flush()
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent_group.created", target_type="agent_group", target_id=group.id, details={"name": group.name, "policy_id": group.policy_id}))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An agent group with this name already exists") from exc
    return _group_response(db, group)


@router.put("/agent-groups/{group_id}", response_model=AgentGroupResponse)
def update_group(group_id: str, request: AgentGroupUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    group = _require_group(db, user.tenant_id, group_id)
    _require_policy(db, user.tenant_id, request.policy_id)
    group.name = request.name.strip()
    group.description = request.description.strip()
    group.policy_id = request.policy_id
    group.updated_at = now_utc()
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent_group.updated", target_type="agent_group", target_id=group.id, details={"policy_id": group.policy_id}))
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


@router.patch("/agents/{agent_id}/group", response_model=LinuxAgentResponse)
def assign_agent_group(agent_id: str, request: AgentGroupAssignment, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    agent = db.get(LinuxAgent, agent_id)
    if agent is None or agent.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    _require_group(db, user.tenant_id, request.group_id)
    previous = agent.group_id
    agent.group_id = request.group_id
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent.group_assigned", target_type="linux_agent", target_id=agent.id, details={"previous_group_id": previous, "group_id": agent.group_id}))
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
    agent.revoked_at = revoked_at
    token = db.get(IngestionToken, agent.ingestion_token_id)
    key = db.get(SigningKey, agent.signing_key_id)
    if token is not None:
        token.revoked_at = revoked_at
    if key is not None:
        key.revoked_at = revoked_at
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent.revoked", target_type="linux_agent", target_id=agent.id, details={"host_id": agent.host_id}))
    db.commit()
    return Response(status_code=204)


@router.post("/agent-enrollment-tokens", response_model=AgentEnrollmentTokenCreated, status_code=201)
def create_enrollment_token(request: AgentEnrollmentTokenCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_admin(user)
    _require_group(db, user.tenant_id, request.group_id)
    expires_at = _aware(request.expires_at)
    if expires_at <= now_utc() or expires_at > now_utc() + timedelta(days=30):
        raise HTTPException(status_code=422, detail="Enrollment token expiry must be within the next 30 days")
    raw_token = f"lsa_enroll_{secrets.token_urlsafe(32)}"
    token = AgentEnrollmentToken(
        tenant_id=user.tenant_id,
        group_id=request.group_id,
        name=request.name.strip(),
        token_prefix=raw_token[:24],
        token_hash=hash_ingestion_token(raw_token),
        expires_at=expires_at,
    )
    db.add(token)
    db.flush()
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent_enrollment_token.created", target_type="agent_enrollment_token", target_id=token.id, details={"group_id": token.group_id, "expires_at": token.expires_at.isoformat()}))
    db.commit()
    return AgentEnrollmentTokenCreated(id=token.id, name=token.name, group_id=token.group_id, token=raw_token, token_prefix=token.token_prefix, expires_at=token.expires_at)


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
                expires_at=token.expires_at,
                used_at=token.used_at,
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
    if token.used_at is not None:
        raise HTTPException(status_code=409, detail="Enrollment token was already consumed")
    if token.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Enrollment token is already revoked")
    token.revoked_at = now_utc()
    db.add(AuditEvent(tenant_id=user.tenant_id, actor_type="user", actor_id=user.id, action="agent_enrollment_token.revoked", target_type="agent_enrollment_token", target_id=token.id, details={"group_id": token.group_id}))
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
def enroll_agent(request: AgentEnrollmentRequest, credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Enrollment token required")
    enrollment = db.scalar(
        select(AgentEnrollmentToken)
        .where(AgentEnrollmentToken.token_hash == hash_ingestion_token(credentials.credentials))
        .with_for_update()
    )
    if enrollment is None or enrollment.used_at is not None or enrollment.revoked_at is not None or _aware(enrollment.expires_at) <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid, expired, or already used enrollment token")
    group = _require_group(db, enrollment.tenant_id, enrollment.group_id)
    _, public_key_raw = _validate_public_key(request.public_key)
    fingerprint = hashlib.sha256(public_key_raw).hexdigest()
    if db.scalar(select(LinuxAgent).where(LinuxAgent.tenant_id == enrollment.tenant_id, LinuxAgent.fingerprint == fingerprint)):
        raise HTTPException(status_code=409, detail="This agent identity is already enrolled")
    host = db.scalar(select(Host).where(Host.tenant_id == enrollment.tenant_id, Host.machine_id_hash == request.machine_id_hash))
    if host is None:
        host = db.scalar(select(Host).where(Host.tenant_id == enrollment.tenant_id, Host.hostname == request.hostname, Host.machine_id_hash.like("pending:%"), Host.deleted_at.is_(None)))
    if host is None:
        host = Host(id=str(uuid.uuid4()), tenant_id=enrollment.tenant_id, hostname=request.hostname, machine_id_hash=request.machine_id_hash, operating_system=request.operating_system, os_family=request.os_family, os_version=request.os_version, kernel=request.kernel, architecture=request.architecture)
        db.add(host)
    elif host.deleted_at is not None:
        raise HTTPException(status_code=409, detail="This host was deleted and cannot be enrolled")
    if db.scalar(select(LinuxAgent).where(LinuxAgent.host_id == host.id)):
        raise HTTPException(status_code=409, detail="This host already has an enrolled agent")
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
    ingestion_token = IngestionToken(tenant_id=enrollment.tenant_id, host_id=host.id, name=f"Agent: {request.name}", token_prefix=raw_ingestion_token[:20], token_hash=hash_ingestion_token(raw_ingestion_token))
    signing_key = SigningKey(tenant_id=enrollment.tenant_id, host_id=host.id, name=f"Agent: {request.name}", public_key=request.public_key, fingerprint=fingerprint)
    db.add_all([ingestion_token, signing_key])
    db.flush()
    agent = LinuxAgent(tenant_id=enrollment.tenant_id, host_id=host.id, group_id=group.id, ingestion_token_id=ingestion_token.id, signing_key_id=signing_key.id, name=request.name, public_key=request.public_key, fingerprint=fingerprint, agent_version=request.agent_version, capabilities=request.capabilities, last_seen_at=now_utc())
    db.add(agent)
    db.flush()
    enrollment.used_at = now_utc()
    version = _latest_policy_version(db, group.policy_id)
    db.add(AuditEvent(tenant_id=enrollment.tenant_id, actor_type="agent", actor_id=agent.id, action="agent.enrolled", target_type="host", target_id=host.id, details={"group_id": group.id, "policy_version": version.version, "fingerprint": fingerprint}))
    db.commit()
    return AgentEnrollmentResponse(agent_id=agent.id, host_id=host.id, group_id=group.id, ingestion_token=raw_ingestion_token, signing_key_id=signing_key.id, policy_version=version.version)


def _effective_policy(db: Session, agent: LinuxAgent) -> AgentEffectivePolicyResponse:
    group = _require_group(db, agent.tenant_id, agent.group_id)
    policy = _require_policy(db, agent.tenant_id, group.policy_id)
    version = _latest_policy_version(db, policy.id)
    return AgentEffectivePolicyResponse(policy_id=policy.id, policy_name=policy.name, policy_version=version.version, group_id=group.id, group_name=group.name, default_mode=version.default_mode.value, control_modes=version.control_modes or {}, settings=version.settings or {}, enforcement_enabled=False)


@router.get("/agent/policy", response_model=AgentEffectivePolicyResponse)
def get_agent_policy(principal: AgentPrincipal = Depends(signed_agent_principal), db: Session = Depends(get_db)):
    principal.agent.last_seen_at = now_utc()
    policy = _effective_policy(db, principal.agent)
    db.commit()
    return policy


@router.post("/agent/heartbeat", response_model=AgentHeartbeatResponse)
def agent_heartbeat(request: AgentHeartbeatRequest, principal: AgentPrincipal = Depends(signed_agent_principal), db: Session = Depends(get_db)):
    agent = principal.agent
    policy = _effective_policy(db, agent)
    agent.agent_version = request.agent_version
    agent.capabilities = request.capabilities
    agent.last_seen_at = now_utc()
    agent.last_policy_version = request.policy_version
    db.commit()
    return AgentHeartbeatResponse(accepted_at=agent.last_seen_at, policy_changed=request.policy_version != policy.policy_version, policy_version=policy.policy_version)
