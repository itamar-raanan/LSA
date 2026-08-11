"""Validated, non-executable remediation action catalog."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any

from pydantic import ValidationError

from lsa.schemas import RemediationActionOperation, RemediationActionResponse


CATALOG_SCHEMA_VERSION = "1.0"
ALLOWED_PATH_PREFIXES = ("/etc/",)
FORBIDDEN_KEYS = {"argv", "command", "commands", "executable", "script", "shell"}


class RemediationCatalogError(RuntimeError):
    pass


def _canonical_digest(action: dict[str, Any]) -> str:
    encoded = json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _action_digest(action: RemediationActionResponse) -> str:
    payload = action.model_dump(
        mode="json",
        exclude={"digest", "execution_enabled", "execution_status"},
    )
    return _canonical_digest(payload)


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).lower() for key in value} | {
            nested for child in value.values() for nested in _walk_keys(child)
        }
    if isinstance(value, list):
        return {nested for child in value for nested in _walk_keys(child)}
    return set()


def _validate_path(path: str, label: str) -> None:
    parsed = PurePosixPath(path)
    if not path.startswith(ALLOWED_PATH_PREFIXES) or ".." in parsed.parts or str(parsed) != path:
        raise RemediationCatalogError(f"{label} contains an unapproved path: {path}")


def _validate_operation(
    operation: RemediationActionOperation,
    parameter_names: set[str],
    label: str,
) -> None:
    if operation.path is not None:
        _validate_path(operation.path, label)
    if operation.kind in {"config_setting", "sysctl_setting"}:
        if not all((operation.path, operation.format, operation.key, operation.value_from)):
            raise RemediationCatalogError(f"{label} is missing structured setting fields")
        if operation.value_from not in parameter_names:
            raise RemediationCatalogError(f"{label} references an unknown parameter")
        if not operation.backup_required:
            raise RemediationCatalogError(f"{label} must require a backup")
    elif operation.kind == "restore_backup" and operation.path is None:
        raise RemediationCatalogError(f"{label} must identify the reviewed backup path")
    elif any((operation.format, operation.key, operation.value_from)):
        raise RemediationCatalogError(f"{label} contains fields not valid for {operation.kind}")


def _validate_action(action: RemediationActionResponse, control_ids: set[str]) -> None:
    label = f"{action.action_id}@{action.version}"
    if action.version < 1 or not action.action_id.startswith("linux."):
        raise RemediationCatalogError(f"{label} has an invalid identity")
    if not action.control_ids or len(action.control_ids) != len(set(action.control_ids)):
        raise RemediationCatalogError(f"{label} must map unique controls")
    unknown_controls = set(action.control_ids) - control_ids
    if unknown_controls:
        raise RemediationCatalogError(f"{label} maps unknown controls: {sorted(unknown_controls)}")
    if not action.supported_systems or not action.preconditions or not action.operations:
        raise RemediationCatalogError(f"{label} is missing support, preconditions, or operations")
    if not action.validation or not action.rollback:
        raise RemediationCatalogError(f"{label} is missing validation or rollback")

    parameter_names = {parameter.name for parameter in action.parameters}
    if len(parameter_names) != len(action.parameters):
        raise RemediationCatalogError(f"{label} contains duplicate parameters")
    for parameter in action.parameters:
        if parameter.required and parameter.default is None:
            raise RemediationCatalogError(f"{label}.{parameter.name} requires a reviewed default")
        if parameter.allowed_values and parameter.default not in parameter.allowed_values:
            raise RemediationCatalogError(f"{label}.{parameter.name} default is outside its allow-list")
        if parameter.type == "integer" and type(parameter.default) is not int:
            raise RemediationCatalogError(f"{label}.{parameter.name} must use an integer default")
        if parameter.type == "boolean" and type(parameter.default) is not bool:
            raise RemediationCatalogError(f"{label}.{parameter.name} must use a boolean default")

    support_keys = [(support.family, version) for support in action.supported_systems for version in support.versions]
    if len(support_keys) != len(set(support_keys)) or any(not support.versions for support in action.supported_systems):
        raise RemediationCatalogError(f"{label} contains duplicate or empty operating-system support")

    for index, operation in enumerate(action.operations):
        _validate_operation(operation, parameter_names, f"{label}.operations[{index}]")
    for index, operation in enumerate(action.rollback):
        _validate_operation(operation, parameter_names, f"{label}.rollback[{index}]")

    backed_up_paths = {operation.path for operation in action.operations if operation.backup_required}
    rollback_paths = {operation.path for operation in action.rollback if operation.kind == "restore_backup"}
    if not backed_up_paths <= rollback_paths:
        raise RemediationCatalogError(f"{label} does not restore every modified path")


@lru_cache(maxsize=1)
def load_remediation_catalog() -> tuple[RemediationActionResponse, ...]:
    raw = json.loads(files("lsa").joinpath("data/remediation_action_catalog.json").read_text())
    if set(raw) != {"catalog_schema_version", "actions"}:
        raise RemediationCatalogError("Remediation action catalog contains unknown root fields")
    if raw.get("catalog_schema_version") != CATALOG_SCHEMA_VERSION:
        raise RemediationCatalogError("Unsupported remediation action catalog schema")
    if _walk_keys(raw) & FORBIDDEN_KEYS:
        raise RemediationCatalogError("Remediation action catalog contains executable payload fields")

    control_catalog = json.loads(files("lsa").joinpath("data/control_catalog.json").read_text())
    known_controls = {item["control_id"] for item in control_catalog}
    actions: list[RemediationActionResponse] = []
    identities: set[tuple[str, int]] = set()
    for raw_action in raw.get("actions", []):
        try:
            action = RemediationActionResponse.model_validate({**raw_action, "digest": "0" * 64})
        except ValidationError as exc:
            raise RemediationCatalogError(f"Invalid remediation action: {exc}") from exc
        action = action.model_copy(update={"digest": _action_digest(action)})
        identity = (action.action_id, action.version)
        if identity in identities:
            raise RemediationCatalogError(f"Duplicate remediation action version: {identity}")
        identities.add(identity)
        _validate_action(action, known_controls)
        actions.append(action)

    if not actions:
        raise RemediationCatalogError("Remediation action catalog is empty")
    latest: dict[str, RemediationActionResponse] = {}
    for action in actions:
        if action.action_id not in latest or action.version > latest[action.action_id].version:
            latest[action.action_id] = action
    control_owners: dict[str, str] = {}
    for action in latest.values():
        for control_id in action.control_ids:
            owner = control_owners.setdefault(control_id, action.action_id)
            if owner != action.action_id:
                raise RemediationCatalogError(
                    f"Current actions {owner} and {action.action_id} both map {control_id}"
                )
    return tuple(sorted(actions, key=lambda item: (item.action_id, item.version)))


def validate_action_snapshot(
    snapshot: dict[str, object],
    expected_digest: str,
) -> RemediationActionResponse:
    try:
        action = RemediationActionResponse.model_validate(snapshot)
    except ValidationError as exc:
        raise RemediationCatalogError(f"Invalid stored remediation action snapshot: {exc}") from exc
    if action.digest != expected_digest or _action_digest(action) != expected_digest:
        raise RemediationCatalogError("Stored remediation action snapshot digest does not match")
    return action


def latest_remediation_actions() -> tuple[RemediationActionResponse, ...]:
    latest: dict[str, RemediationActionResponse] = {}
    for action in load_remediation_catalog():
        if action.action_id not in latest or action.version > latest[action.action_id].version:
            latest[action.action_id] = action
    return tuple(sorted(latest.values(), key=lambda item: item.action_id))


def action_supports(action: RemediationActionResponse, os_family: str, os_version: str) -> bool:
    family = os_family.strip().lower()
    version = os_version.strip()
    return any(
        support.family.lower() == family and version in support.versions
        for support in action.supported_systems
    )


def match_remediation_action(
    control_id: str,
    os_family: str,
    os_version: str,
) -> tuple[str, RemediationActionResponse | None]:
    candidates = [action for action in latest_remediation_actions() if control_id in action.control_ids]
    if not candidates:
        return "not_cataloged", None
    supported = [action for action in candidates if action_supports(action, os_family, os_version)]
    if not supported:
        return "unsupported_system", None
    if len(supported) != 1:
        raise RemediationCatalogError(f"Multiple current actions match {control_id} on {os_family} {os_version}")
    return "matched", supported[0]


def remediation_action(action_id: str, version: int | None = None) -> RemediationActionResponse | None:
    candidates = [action for action in load_remediation_catalog() if action.action_id == action_id]
    if not candidates:
        return None
    if version is None:
        return max(candidates, key=lambda item: item.version)
    return next((action for action in candidates if action.version == version), None)
