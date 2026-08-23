"""Canonical verification for agent-signed remediation validation receipts."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_receipt(receipt: dict[str, Any]) -> bytes:
    return json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def verify_validation_receipt(public_key: str, receipt: dict[str, Any], signature: str) -> bool:
    try:
        public_raw = base64.b64decode(public_key, validate=True)
        signature_raw = base64.b64decode(signature, validate=True)
        if len(public_raw) != 32 or len(signature_raw) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw,
            canonical_receipt(receipt),
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def _checkpoint_id(identity: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_receipt(identity)).hexdigest()


def validate_recovery_plan(contract: dict[str, Any], plan: dict[str, Any]) -> bool:
    """Verify recovery-plan coverage and ordering against the frozen contract."""

    expected: list[dict[str, Any]] = []
    for record in contract.get("actions", []):
        if not isinstance(record, dict):
            return False
        snapshot = record.get("action_snapshot")
        if not isinstance(snapshot, dict):
            return False
        rollbacks = snapshot.get("rollback")
        operations = snapshot.get("operations")
        if not isinstance(rollbacks, list) or not isinstance(operations, list):
            return False
        rollback_by_path: dict[str, list[int]] = {}
        for rollback_index, operation in enumerate(rollbacks):
            if (
                isinstance(operation, dict)
                and operation.get("kind") == "restore_backup"
                and isinstance(operation.get("path"), str)
            ):
                rollback_by_path.setdefault(operation["path"], []).append(rollback_index)
        for operation_index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                return False
            path = operation.get("path")
            if operation.get("backup_required") is not True or not isinstance(path, str):
                continue
            rollback_indexes = rollback_by_path.get(path, [])
            identity = {
                "action_digest": record.get("action_digest"),
                "operation_index": operation_index,
                "path": path,
                "plan_id": record.get("plan_id"),
                "rollback_index": rollback_indexes[0] if len(rollback_indexes) == 1 else -1,
            }
            expected.append({"checkpoint_id": _checkpoint_id(identity), **identity})

    entries = plan.get("entries")
    if not isinstance(entries, list) or len(entries) != len(expected) or not entries:
        return False
    for entry, expected_entry in zip(entries, expected, strict=True):
        if not isinstance(entry, dict) or any(
            entry.get(key) != value for key, value in expected_entry.items()
        ):
            return False
        metadata = [entry.get(key) for key in ("source_digest", "size_bytes", "mode", "uid", "gid")]
        if entry.get("backup_created") is not False:
            return False
        if entry.get("source_state") == "regular_file":
            if entry.get("status") != "ready" or any(value is None for value in metadata):
                return False
        elif entry.get("source_state") == "absent":
            if entry.get("status") != "ready" or any(value is not None for value in metadata):
                return False
        elif entry.get("source_state") == "blocked":
            if entry.get("status") != "blocked" or any(value is not None for value in metadata):
                return False
        else:
            return False

    checkpoint_ids = [entry["checkpoint_id"] for entry in entries]
    if len(set(checkpoint_ids)) != len(checkpoint_ids):
        return False
    if plan.get("rollback_order") != list(reversed(checkpoint_ids)):
        return False
    unique_paths = len({entry["path"] for entry in entries}) == len(entries)
    expected_ready = unique_paths and all(
        entry.get("status") == "ready" and entry.get("rollback_index", -1) >= 0
        for entry in entries
    )
    return plan.get("status") == ("ready" if expected_ready else "blocked")


def checkpoint_journal_digest(
    *,
    checkpoint_job_id: str,
    validation_id: str,
    contract_digest: str,
    recovery_plan: dict[str, Any],
    state: str,
    checkpoint_results: list[dict[str, Any]],
    error: str | None,
) -> str:
    journal = {
        "schema_version": "1.0",
        "kind": "remediation-checkpoint-journal",
        "checkpoint_job_id": checkpoint_job_id,
        "validation_id": validation_id,
        "contract_digest": contract_digest,
        "recovery_plan_digest": hashlib.sha256(canonical_receipt(recovery_plan)).hexdigest(),
        "recovery_plan": recovery_plan,
        "state": state,
        "checkpoint_results": checkpoint_results,
        "error": error,
        "execution_enabled": False,
        "changes_applied": False,
    }
    return hashlib.sha256(canonical_receipt(journal)).hexdigest()
