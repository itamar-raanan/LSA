"""Fail-closed validation for non-executable remediation contract previews."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


FORBIDDEN_KEYS = {
    "arg",
    "args",
    "argv",
    "command",
    "commands",
    "executable",
    "script",
    "shell",
}
ALLOWED_OPERATION_KINDS = {
    "config_setting",
    "restore_backup",
    "service_reload",
    "sysctl_reload",
    "sysctl_setting",
}
ACTION_KEYS = {
    "action_id",
    "version",
    "digest",
    "status",
    "control_ids",
    "title",
    "description",
    "supported_systems",
    "risk",
    "parameters",
    "preconditions",
    "operations",
    "validation",
    "rollback",
    "impact",
    "execution_enabled",
    "execution_status",
}
OPERATION_KEYS = {
    "kind",
    "resource",
    "path",
    "format",
    "key",
    "value_from",
    "backup_required",
}
SUPPORT_KEYS = {"family", "versions"}
PARAMETER_KEYS = {
    "name",
    "type",
    "required",
    "default",
    "allowed_values",
    "minimum",
    "maximum",
    "description",
}
PRECONDITION_KEYS = {"kind", "resource", "expected", "failure_mode", "description"}
VALIDATION_KEYS = {"kind", "resource", "key", "expected"}
IMPACT_KEYS = {"service_restart", "reboot_required", "availability", "notes"}
PLAN_KEYS = {
    "plan_id",
    "host_id",
    "report_id",
    "control_id",
    "action_id",
    "action_version",
    "action_digest",
}
TARGET_KEYS = {
    "host_id",
    "hostname",
    "agent_id",
    "group_id",
    "group_name",
    "policy_id",
    "policy_name",
    "policy_version",
    "rollout_phase",
    "required_capability",
    "capability_attested",
}
PACKAGE_RESOURCES = {
    "openssh_server": {"openssh-server"},
}


class RemediationContractError(RuntimeError):
    pass


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RemediationContractError(f"{label} schema is invalid")
    return value


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).lower() for key in value} | {
            key for child in value.values() for key in _walk_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _walk_keys(child)}
    return set()


def _decode_public_key(descriptor: dict[str, Any], label: str) -> tuple[Ed25519PublicKey, bytes]:
    _exact_keys(
        descriptor,
        {"key_id", "algorithm", "public_key", "fingerprint"},
        label,
    )
    try:
        raw = base64.b64decode(str(descriptor["public_key"]), validate=True)
        if (
            len(raw) != 32
            or descriptor["algorithm"] != "Ed25519"
            or descriptor["fingerprint"] != hashlib.sha256(raw).hexdigest()
            or not isinstance(descriptor["key_id"], str)
        ):
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except (TypeError, ValueError) as exc:
        raise RemediationContractError(f"{label} is invalid") from exc


def _verify_signature(
    key: Ed25519PublicKey, signature: object, payload: dict[str, Any], label: str
) -> None:
    try:
        decoded = base64.b64decode(str(signature), validate=True)
        if len(decoded) != 64:
            raise ValueError
        key.verify(decoded, _canonical(payload))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise RemediationContractError(f"{label} signature is invalid") from exc


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise RemediationContractError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RemediationContractError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise RemediationContractError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_path(path: object) -> None:
    if path is None:
        return
    if not isinstance(path, str):
        raise RemediationContractError("remediation operation path is invalid")
    parsed = PurePosixPath(path)
    if not path.startswith("/etc/") or ".." in parsed.parts or str(parsed) != path:
        raise RemediationContractError("remediation operation path is outside reviewed roots")


def _action_digest(snapshot: dict[str, Any]) -> str:
    digest_payload = {
        key: value
        for key, value in snapshot.items()
        if key not in {"digest", "execution_enabled", "execution_status"}
    }
    return hashlib.sha256(_canonical(digest_payload)).hexdigest()


def _validate_action_record(
    record: dict[str, Any], signed_plan: dict[str, Any], expected_host_id: str
) -> None:
    _exact_keys(
        record,
        {
            "plan_id",
            "host_id",
            "control_id",
            "action_id",
            "action_version",
            "action_digest",
            "action_snapshot",
        },
        "remediation action record",
    )
    for key in (
        "plan_id",
        "host_id",
        "control_id",
        "action_id",
        "action_version",
        "action_digest",
    ):
        if record.get(key) != signed_plan.get(key):
            raise RemediationContractError("remediation action does not match the signed plan")
    if record["host_id"] != expected_host_id:
        raise RemediationContractError("remediation action belongs to another host")
    snapshot = _exact_keys(record["action_snapshot"], ACTION_KEYS, "action snapshot")
    if _walk_keys(snapshot) & FORBIDDEN_KEYS:
        raise RemediationContractError("action snapshot contains executable content")
    if (
        snapshot.get("execution_enabled") is not False
        or snapshot.get("execution_status") != "catalog_only"
        or snapshot.get("status") != "reviewed"
        or snapshot.get("action_id") != record["action_id"]
        or snapshot.get("version") != record["action_version"]
        or snapshot.get("digest") != record["action_digest"]
        or record["control_id"] not in snapshot.get("control_ids", [])
        or _action_digest(snapshot) != record["action_digest"]
    ):
        raise RemediationContractError("action snapshot identity or digest is invalid")
    operations = snapshot.get("operations")
    rollback = snapshot.get("rollback")
    validation = snapshot.get("validation")
    preconditions = snapshot.get("preconditions")
    if not all(isinstance(value, list) and value for value in (operations, rollback, validation, preconditions)):
        raise RemediationContractError("action snapshot lacks safety stages")
    support = snapshot.get("supported_systems")
    parameters = snapshot.get("parameters")
    impact = snapshot.get("impact")
    if not isinstance(support, list) or not support:
        raise RemediationContractError("action snapshot lacks supported systems")
    for item in support:
        typed = _exact_keys(item, SUPPORT_KEYS, "action supported system")
        if not isinstance(typed.get("family"), str) or not isinstance(typed.get("versions"), list):
            raise RemediationContractError("action supported system is invalid")
    if not isinstance(parameters, list):
        raise RemediationContractError("action parameters are invalid")
    for item in parameters:
        _exact_keys(item, PARAMETER_KEYS, "action parameter")
    for item in preconditions:
        typed = _exact_keys(item, PRECONDITION_KEYS, "action precondition")
        if typed.get("failure_mode") != "stop":
            raise RemediationContractError("action precondition does not fail closed")
    for item in validation:
        _exact_keys(item, VALIDATION_KEYS, "action validation")
    _exact_keys(impact, IMPACT_KEYS, "action impact")
    modified_paths: set[str] = set()
    restored_paths: set[str] = set()
    for collection_name, collection in (("operations", operations), ("rollback", rollback)):
        for operation in collection:
            typed = _exact_keys(operation, OPERATION_KEYS, f"action {collection_name} operation")
            if typed.get("kind") not in ALLOWED_OPERATION_KINDS:
                raise RemediationContractError("action operation kind is not allow-listed")
            _validate_path(typed.get("path"))
            if typed.get("backup_required") is True and isinstance(typed.get("path"), str):
                modified_paths.add(typed["path"])
            if typed.get("kind") == "restore_backup" and isinstance(typed.get("path"), str):
                restored_paths.add(typed["path"])
    if not modified_paths or not modified_paths <= restored_paths:
        raise RemediationContractError("action backup and rollback coverage is incomplete")


def validate_remediation_contract_preview(
    contract: dict[str, Any],
    *,
    pinned_platform_key: Ed25519PublicKey,
    pinned_platform_raw: bytes,
    expected_platform_key_id: str,
    expected_agent_id: str,
    expected_host_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate trust and schema, returning only a non-executable summary."""

    root = _exact_keys(
        contract,
        {
            "schema_version",
            "contract_type",
            "mode",
            "execution_enabled",
            "dispatch_enabled",
            "change_set",
            "platform_endorsement",
            "platform_endorsement_signature",
            "target",
            "actions",
        },
        "remediation contract",
    )
    if (
        root["schema_version"] != "1.0"
        or root["contract_type"] != "remediation-validation"
        or root["mode"] != "validate_only"
        or root["execution_enabled"] is not False
        or root["dispatch_enabled"] is not False
    ):
        raise RemediationContractError("remediation contract safety lock is invalid")

    endorsement = _exact_keys(
        root["platform_endorsement"],
        {
            "schema_version",
            "kind",
            "tenant_id",
            "purpose",
            "platform_command_key_id",
            "change_signing_key",
        },
        "platform endorsement",
    )
    pinned_fingerprint = hashlib.sha256(pinned_platform_raw).hexdigest()
    supplied_platform_raw = pinned_platform_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if (
        len(pinned_platform_raw) != 32
        or supplied_platform_raw != pinned_platform_raw
        or endorsement["schema_version"] != "1.0"
        or endorsement["kind"] != "change-signing-key-endorsement"
        or endorsement["purpose"] != "remediation-validation"
        or endorsement["platform_command_key_id"] != expected_platform_key_id
    ):
        raise RemediationContractError("platform endorsement binding is invalid")
    _verify_signature(
        pinned_platform_key,
        root["platform_endorsement_signature"],
        endorsement,
        "platform endorsement",
    )

    change_set = _exact_keys(
        root["change_set"],
        {"change_set_id", "tenant_id", "digest", "payload", "signature", "signing_key"},
        "change set",
    )
    signing_descriptor = endorsement["change_signing_key"]
    if change_set["signing_key"] != signing_descriptor:
        raise RemediationContractError("change-set signer is not platform endorsed")
    change_key, _ = _decode_public_key(signing_descriptor, "change-signing key")
    payload = _exact_keys(
        change_set["payload"],
        {
            "schema_version",
            "change_set_id",
            "tenant_id",
            "requested_at",
            "maintenance_window",
            "rollout",
            "safeguards",
            "plans",
            "targets",
        },
        "change-set payload",
    )
    if (
        payload["schema_version"] != "1.0"
        or payload["change_set_id"] != change_set["change_set_id"]
        or payload["tenant_id"] != change_set["tenant_id"]
        or payload["tenant_id"] != endorsement["tenant_id"]
        or hashlib.sha256(_canonical(payload)).hexdigest() != change_set["digest"]
    ):
        raise RemediationContractError("change-set identity or digest is invalid")
    _verify_signature(change_key, change_set["signature"], payload, "change set")
    safeguards = payload.get("safeguards")
    if (
        not isinstance(safeguards, dict)
        or set(safeguards)
        != {
            "execution_enabled",
            "four_eyes_required",
            "post_change_verification_required",
            "rollback_checkpoint_required",
        }
        or safeguards.get("execution_enabled") is not False
        or safeguards.get("four_eyes_required") is not True
        or safeguards.get("post_change_verification_required") is not True
        or safeguards.get("rollback_checkpoint_required") is not True
    ):
        raise RemediationContractError("signed change-set safeguards are invalid")

    target = root["target"]
    targets = payload.get("targets")
    if isinstance(targets, list):
        for item in targets:
            _exact_keys(item, TARGET_KEYS, "signed remediation target")
    if (
        not isinstance(target, dict)
        or not isinstance(targets, list)
        or target not in targets
        or target.get("agent_id") != expected_agent_id
        or target.get("host_id") != expected_host_id
        or target.get("rollout_phase") not in {"canary", "deferred"}
    ):
        raise RemediationContractError("remediation target binding is invalid")

    window = payload.get("maintenance_window")
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise RemediationContractError("maintenance window schema is invalid")
    start = _parse_time(window["start"], "maintenance window start")
    end = _parse_time(window["end"], "maintenance window end")
    if (
        end <= (now or datetime.now(UTC)).astimezone(UTC)
        or end <= start
        or not timedelta(minutes=30) <= end - start <= timedelta(hours=8)
    ):
        raise RemediationContractError("maintenance window is expired or invalid")

    rollout = _exact_keys(
        payload.get("rollout"),
        {"strategy", "batch_size", "batch_interval_minutes"},
        "change-set rollout",
    )
    if (
        rollout.get("strategy") != "canary"
        or not isinstance(rollout.get("batch_size"), int)
        or isinstance(rollout.get("batch_size"), bool)
        or not 1 <= rollout["batch_size"] <= 25
        or not isinstance(rollout.get("batch_interval_minutes"), int)
        or isinstance(rollout.get("batch_interval_minutes"), bool)
        or not 15 <= rollout["batch_interval_minutes"] <= 1440
    ):
        raise RemediationContractError("change-set rollout is invalid")

    signed_plans = payload.get("plans")
    actions = root["actions"]
    if not isinstance(signed_plans, list) or not isinstance(actions, list) or not actions:
        raise RemediationContractError("remediation actions are missing")
    for item in signed_plans:
        _exact_keys(item, PLAN_KEYS, "signed remediation plan")
    plans_for_host = {
        item.get("plan_id"): item
        for item in signed_plans
        if isinstance(item, dict) and item.get("host_id") == expected_host_id
    }
    action_plan_ids: set[str] = set()
    for action in actions:
        if not isinstance(action, dict) or not isinstance(action.get("plan_id"), str):
            raise RemediationContractError("remediation action record is invalid")
        plan_id = action["plan_id"]
        if plan_id in action_plan_ids or plan_id not in plans_for_host:
            raise RemediationContractError("remediation action plan coverage is invalid")
        _validate_action_record(action, plans_for_host[plan_id], expected_host_id)
        action_plan_ids.add(plan_id)
    if action_plan_ids != set(plans_for_host):
        raise RemediationContractError("remediation action plan coverage is incomplete")

    return {
        "validated": True,
        "mode": "validate_only",
        "execution_enabled": False,
        "dispatch_enabled": False,
        "change_set_id": change_set["change_set_id"],
        "agent_id": expected_agent_id,
        "host_id": expected_host_id,
        "rollout_phase": target["rollout_phase"],
        "action_count": len(actions),
        "platform_key_fingerprint": pinned_fingerprint,
        "change_signing_key_fingerprint": signing_descriptor["fingerprint"],
    }


def canonical_validation_receipt(receipt: dict[str, Any]) -> bytes:
    return _canonical(receipt)


def sign_validation_receipt(key: Ed25519PrivateKey, receipt: dict[str, Any]) -> str:
    return base64.b64encode(key.sign(canonical_validation_receipt(receipt))).decode()


def _read_os_release(root: Path) -> tuple[str, str]:
    values: dict[str, str] = {}
    path = root / "etc/os-release"
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        return "unknown", "unknown"
    release_id = values.get("ID", "unknown").lower()
    family = {"rhel": "redhat", "ol": "oraclelinux"}.get(release_id, release_id)
    return family, values.get("VERSION_ID", "unknown")


def _installed_packages(root: Path) -> set[str]:
    packages: set[str] = set()
    status_path = root / "var/lib/dpkg/status"
    try:
        for record in status_path.read_text(encoding="utf-8", errors="replace").split("\n\n"):
            fields = {
                key: value.strip()
                for line in record.splitlines()
                if ":" in line
                for key, value in [line.split(":", 1)]
            }
            if fields.get("Status") == "install ok installed" and fields.get("Package"):
                packages.add(fields["Package"])
    except OSError:
        pass
    return packages


def _mapped_path(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def _path_preflight(root: Path, path: str) -> tuple[bool, str]:
    mapped = _mapped_path(root, path)
    reviewed_root = (root / "etc").resolve()
    try:
        resolved = mapped.resolve(strict=False)
        resolved.relative_to(reviewed_root)
    except (OSError, ValueError):
        return False, f"{path} resolves outside the reviewed /etc boundary"
    parent = mapped.parent
    if not parent.exists() or not parent.is_dir():
        return False, f"Parent directory {parent} is unavailable"
    if mapped.exists() and not mapped.is_file():
        return False, f"{path} is not a regular configuration file"
    return True, f"{path} and its parent remain inside the reviewed /etc boundary"


def _append_check(checks: list[dict[str, str]], code: str, passed: bool, detail: str) -> None:
    checks.append(
        {
            "code": code,
            "status": "passed" if passed else "blocked",
            "detail": detail,
        }
    )


def dry_run_remediation_contract(
    contract: dict[str, Any],
    *,
    root: Path = Path("/"),
    command_lookup: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    """Evaluate local readiness using reads only; never return executable operations."""

    family, version = _read_os_release(root)
    installed_packages = _installed_packages(root)
    action_results: list[dict[str, Any]] = []
    for record in contract["actions"]:
        snapshot = record["action_snapshot"]
        checks: list[dict[str, str]] = []

        supported = any(
            item["family"] == family and version in item["versions"]
            for item in snapshot["supported_systems"]
        )
        _append_check(
            checks,
            "supported_system",
            supported,
            f"Detected {family} {version}; action support {'matches' if supported else 'does not match'}",
        )
        for index, parameter in enumerate(snapshot["parameters"]):
            default = parameter["default"]
            parameter_type = parameter["type"]
            typed = (
                (parameter_type == "boolean" and type(default) is bool)
                or (parameter_type == "integer" and type(default) is int)
                or (parameter_type in {"enum", "string"} and isinstance(default, str))
            )
            allowed = not parameter["allowed_values"] or default in parameter["allowed_values"]
            _append_check(
                checks,
                f"parameter_{index}",
                typed and allowed and (default is not None or not parameter["required"]),
                f"Parameter {parameter['name']} uses its reviewed typed default",
            )
        for index, precondition in enumerate(snapshot["preconditions"]):
            kind = precondition["kind"]
            resource = precondition["resource"]
            if kind == "command_available":
                passed = command_lookup(resource) is not None
                detail = f"Required program {resource} {'is' if passed else 'is not'} available"
            elif kind == "package_present":
                package_names = PACKAGE_RESOURCES.get(resource, set())
                passed = bool(package_names & installed_packages)
                detail = (
                    f"Required package resource {resource} "
                    f"{'is' if passed else 'is not'} installed"
                )
            elif kind == "manual_confirmation":
                passed = False
                detail = f"Manual confirmation is still required: {precondition['description']}"
            else:
                passed = False
                detail = f"Host-role exclusion requires operator confirmation: {resource}"
            _append_check(checks, f"precondition_{index}", passed, detail)
        for index, operation in enumerate(snapshot["operations"]):
            kind = operation["kind"]
            path = operation["path"]
            if path is not None:
                passed, detail = _path_preflight(root, path)
            elif kind in {"service_reload", "sysctl_reload"}:
                program = "systemctl" if kind == "service_reload" else "sysctl"
                passed = command_lookup(program) is not None
                detail = f"Required reload interface {program} {'is' if passed else 'is not'} available"
            else:
                passed = False
                detail = f"Operation {kind} has no reviewed local resource"
            _append_check(checks, f"operation_{index}", passed, detail)
        for index, validation in enumerate(snapshot["validation"]):
            if validation["kind"] == "effective_setting":
                program = "sshd" if validation["resource"] == "openssh_server" else validation["resource"]
                passed = command_lookup(program) is not None
                detail = f"Validation interface {program} {'is' if passed else 'is not'} available"
            else:
                proc_path = _mapped_path(
                    root,
                    "/proc/sys/" + validation["key"].replace(".", "/"),
                )
                passed = proc_path.is_file()
                detail = f"Kernel validation path {proc_path} {'is' if passed else 'is not'} readable"
            _append_check(checks, f"validation_{index}", passed, detail)
        ready = all(item["status"] == "passed" for item in checks)
        action_results.append(
            {
                "plan_id": record["plan_id"],
                "action_digest": record["action_digest"],
                "status": "ready" if ready else "blocked",
                "checks": checks,
            }
        )
    return {
        "status": (
            "ready"
            if action_results and all(item["status"] == "ready" for item in action_results)
            else "blocked"
        ),
        "action_results": action_results,
        "execution_enabled": False,
        "changes_applied": False,
    }
