from copy import deepcopy
from types import SimpleNamespace

import pytest

from lsa.api.remediations import _stored_action
from lsa.services.remediation_catalog import (
    RemediationCatalogError,
    action_supports,
    latest_remediation_actions,
    load_remediation_catalog,
    match_remediation_action,
    remediation_action,
    validate_action_snapshot,
)


def test_catalog_is_versioned_structured_and_non_executable():
    actions = load_remediation_catalog()

    assert len(actions) == 4
    assert len({(action.action_id, action.version) for action in actions}) == len(actions)
    assert all(action.status == "reviewed" for action in actions)
    assert all(action.execution_enabled is False for action in actions)
    assert all(action.execution_status == "catalog_only" for action in actions)
    assert all(len(action.digest) == 64 for action in actions)
    assert all(action.preconditions and action.operations for action in actions)
    assert all(action.validation and action.rollback for action in actions)

    serialized = [action.model_dump(mode="json") for action in actions]
    forbidden = {"argv", "command", "commands", "executable", "script", "shell"}

    def keys(value):
        if isinstance(value, dict):
            return {str(key).lower() for key in value} | {
                nested for child in value.values() for nested in keys(child)
            }
        if isinstance(value, list):
            return {nested for child in value for nested in keys(child)}
        return set()

    assert not (keys(serialized) & forbidden)


def test_catalog_matches_only_explicit_supported_systems():
    status, action = match_remediation_action("CIS-DEBIAN13-5.1.21", "debian", "13")
    assert status == "matched"
    assert action is not None
    assert action.action_id == "linux.ssh.permit-root-login.disabled"
    assert action_supports(action, "ubuntu", "24.04") is True

    status, action = match_remediation_action("CIS-DEBIAN13-5.1.21", "debian", "14")
    assert status == "unsupported_system"
    assert action is None

    status, action = match_remediation_action("CIS-DEBIAN13-1.1.1", "debian", "13")
    assert status == "not_cataloged"
    assert action is None


def test_action_snapshot_digest_is_tamper_evident():
    action = remediation_action("linux.ssh.permit-root-login.disabled")
    assert action is not None
    snapshot = action.model_dump(mode="json")
    assert validate_action_snapshot(snapshot, action.digest) == action

    tampered = deepcopy(snapshot)
    tampered["operations"][0]["path"] = "/etc/ssh/sshd_config"
    with pytest.raises(RemediationCatalogError, match="digest"):
        validate_action_snapshot(tampered, action.digest)


def test_plan_snapshot_identity_and_catalog_status_fail_closed():
    action = remediation_action("linux.ssh.permit-root-login.disabled")
    assert action is not None
    plan = SimpleNamespace(
        action_id=action.action_id,
        action_version=action.version,
        action_digest=action.digest,
        action_snapshot=action.model_dump(mode="json"),
        action_catalog_status="not_cataloged",
        control_id="CIS-DEBIAN13-5.1.21",
    )

    with pytest.raises(RemediationCatalogError, match="not marked as matched"):
        _stored_action(plan)

    plan.action_catalog_status = "matched"
    plan.control_id = "CIS-DEBIAN13-1.1.1"
    with pytest.raises(RemediationCatalogError, match="control does not match"):
        _stored_action(plan)


def test_latest_catalog_returns_one_version_per_action():
    latest = latest_remediation_actions()
    assert len(latest) == 4
    assert len({action.action_id for action in latest}) == len(latest)
