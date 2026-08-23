"""Read-only recovery planning for future constrained remediation execution.

This module intentionally contains no mutation, backup creation, restore, service,
sysctl, subprocess, or command-execution primitive. It only inspects reviewed
configuration paths and produces a deterministic plan that a future executor must
satisfy before its first host change.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any


MAX_CHECKPOINT_SOURCE_BYTES = 8 * 1024 * 1024


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _checkpoint_id(
    *,
    plan_id: str,
    action_digest: str,
    operation_index: int,
    rollback_index: int,
    path: str,
) -> str:
    identity = {
        "action_digest": action_digest,
        "operation_index": operation_index,
        "path": path,
        "plan_id": plan_id,
        "rollback_index": rollback_index,
    }
    return hashlib.sha256(_canonical(identity)).hexdigest()


def _mapped_path(root: Path, path: str) -> Path:
    parsed = PurePosixPath(path)
    if not path.startswith("/etc/") or ".." in parsed.parts or str(parsed) != path:
        raise ValueError("recovery path is outside the reviewed /etc boundary")
    return root.joinpath(*parsed.parts[1:])


def _safe_parent(mapped: Path, root: Path) -> tuple[bool, str]:
    try:
        relative_parent = mapped.parent.relative_to(root)
    except ValueError:
        return False, "Path parent escapes the configured inspection root"
    current = root
    for part in relative_parent.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            return False, f"Parent directory {current} is unavailable"
        if stat.S_ISLNK(metadata.st_mode):
            return False, f"Parent directory {current} is a symbolic link"
        if not stat.S_ISDIR(metadata.st_mode):
            return False, f"Parent path {current} is not a directory"
    return True, "Reviewed parent path contains no symbolic links"


def _inspect_source(root: Path, path: str) -> dict[str, Any]:
    try:
        mapped = _mapped_path(root, path)
    except ValueError as exc:
        return {"source_state": "blocked", "status": "blocked", "detail": str(exc)}
    parent_ready, parent_detail = _safe_parent(mapped, root)
    if not parent_ready:
        return {"source_state": "blocked", "status": "blocked", "detail": parent_detail}
    try:
        metadata = mapped.lstat()
    except FileNotFoundError:
        return {
            "source_state": "absent",
            "status": "ready",
            "detail": f"{path} is absent; rollback must remove a newly created file",
        }
    except OSError as exc:
        return {
            "source_state": "blocked",
            "status": "blocked",
            "detail": f"Could not inspect {path}: {exc.strerror or exc}",
        }
    if stat.S_ISLNK(metadata.st_mode):
        return {
            "source_state": "blocked",
            "status": "blocked",
            "detail": f"{path} is a symbolic link",
        }
    if not stat.S_ISREG(metadata.st_mode):
        return {
            "source_state": "blocked",
            "status": "blocked",
            "detail": f"{path} is not a regular configuration file",
        }
    if metadata.st_size > MAX_CHECKPOINT_SOURCE_BYTES:
        return {
            "source_state": "blocked",
            "status": "blocked",
            "detail": f"{path} exceeds the reviewed checkpoint size limit",
        }
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(mapped, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or opened_metadata.st_dev != metadata.st_dev
                or opened_metadata.st_ino != metadata.st_ino
            ):
                raise OSError("source changed during inspection")
            while chunk := os.read(descriptor, 64 * 1024):
                digest.update(chunk)
            final_metadata = os.fstat(descriptor)
            if (
                final_metadata.st_size != opened_metadata.st_size
                or final_metadata.st_mtime_ns != opened_metadata.st_mtime_ns
                or final_metadata.st_ctime_ns != opened_metadata.st_ctime_ns
            ):
                raise OSError("source changed while it was being inspected")
        finally:
            os.close(descriptor)
    except OSError as exc:
        return {
            "source_state": "blocked",
            "status": "blocked",
            "detail": f"Could not safely read {path}: {exc}",
        }
    return {
        "source_state": "regular_file",
        "source_digest": f"sha256:{digest.hexdigest()}",
        "size_bytes": opened_metadata.st_size,
        "mode": f"{stat.S_IMODE(opened_metadata.st_mode):04o}",
        "uid": opened_metadata.st_uid,
        "gid": opened_metadata.st_gid,
        "status": "ready",
        "detail": f"{path} can be checkpointed with content and metadata before mutation",
    }


def compile_recovery_plan(contract: dict[str, Any], *, root: Path = Path("/")) -> dict[str, Any]:
    """Compile deterministic backup and rollback requirements without writing anything."""

    entries: list[dict[str, Any]] = []
    path_counts: dict[str, int] = {}
    for record in contract["actions"]:
        snapshot = record["action_snapshot"]
        rollback_by_path: dict[str, list[int]] = {}
        for rollback_index, operation in enumerate(snapshot["rollback"]):
            if operation["kind"] == "restore_backup" and operation["path"] is not None:
                rollback_by_path.setdefault(operation["path"], []).append(rollback_index)
        for operation_index, operation in enumerate(snapshot["operations"]):
            path = operation["path"]
            if operation["backup_required"] is not True or path is None:
                continue
            rollback_indexes = rollback_by_path.get(path, [])
            rollback_index = rollback_indexes[0] if len(rollback_indexes) == 1 else -1
            source = _inspect_source(root, path)
            if len(rollback_indexes) != 1:
                source = {
                    "source_state": "blocked",
                    "status": "blocked",
                    "detail": f"{path} does not have exactly one reviewed restore operation",
                }
            entry = {
                "checkpoint_id": _checkpoint_id(
                    plan_id=record["plan_id"],
                    action_digest=record["action_digest"],
                    operation_index=operation_index,
                    rollback_index=rollback_index,
                    path=path,
                ),
                "plan_id": record["plan_id"],
                "action_digest": record["action_digest"],
                "operation_index": operation_index,
                "rollback_index": rollback_index,
                "path": path,
                "backup_created": False,
                **source,
            }
            entries.append(entry)
            path_counts[path] = path_counts.get(path, 0) + 1

    for entry in entries:
        if path_counts[entry["path"]] > 1:
            entry.update(
                source_state="blocked",
                status="blocked",
                detail=(
                    f"{entry['path']} is targeted by multiple actions; "
                    "a combined reviewed action is required"
                ),
            )
            for key in ("source_digest", "size_bytes", "mode", "uid", "gid"):
                entry.pop(key, None)

    ready = bool(entries) and all(entry["status"] == "ready" for entry in entries)
    return {
        "schema_version": "1.0",
        "kind": "remediation-recovery-plan",
        "status": "ready" if ready else "blocked",
        "backup_before_write": True,
        "automatic_rollback_required": True,
        "stop_on_failure": True,
        "journal_state": "planned",
        "entries": entries,
        "rollback_order": [entry["checkpoint_id"] for entry in reversed(entries)],
        "execution_enabled": False,
        "changes_applied": False,
    }
