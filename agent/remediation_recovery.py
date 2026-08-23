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
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAX_CHECKPOINT_SOURCE_BYTES = 8 * 1024 * 1024
MAX_CHECKPOINT_STORE_BYTES = 256 * 1024 * 1024
CHECKPOINT_BLOB_MAGIC = b"LSACPK1\0"
SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


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


def validate_recovery_plan_binding(contract: dict[str, Any], plan: dict[str, Any]) -> None:
    """Reject a platform-supplied recovery plan that diverges from reviewed operations."""

    expected: list[dict[str, Any]] = []
    for record in contract["actions"]:
        rollback_by_path: dict[str, list[int]] = {}
        for rollback_index, operation in enumerate(record["action_snapshot"]["rollback"]):
            if operation["kind"] == "restore_backup" and operation["path"] is not None:
                rollback_by_path.setdefault(operation["path"], []).append(rollback_index)
        for operation_index, operation in enumerate(record["action_snapshot"]["operations"]):
            path = operation["path"]
            if operation["backup_required"] is not True or path is None:
                continue
            indexes = rollback_by_path.get(path, [])
            identity = {
                "plan_id": record["plan_id"],
                "action_digest": record["action_digest"],
                "operation_index": operation_index,
                "rollback_index": indexes[0] if len(indexes) == 1 else -1,
                "path": path,
            }
            expected.append({"checkpoint_id": _checkpoint_id(**identity), **identity})
    entries = plan.get("entries")
    if (
        plan.get("status") != "ready"
        or plan.get("execution_enabled") is not False
        or plan.get("changes_applied") is not False
        or not isinstance(entries, list)
        or len(entries) != len(expected)
    ):
        raise RuntimeError("recovery plan safety lock or coverage is invalid")
    for entry, expected_entry in zip(entries, expected, strict=True):
        if any(entry.get(key) != value for key, value in expected_entry.items()):
            raise RuntimeError("recovery plan diverges from the reviewed action")
    checkpoint_ids = [entry["checkpoint_id"] for entry in entries]
    if len(set(checkpoint_ids)) != len(checkpoint_ids) or plan.get("rollback_order") != list(
        reversed(checkpoint_ids)
    ):
        raise RuntimeError("recovery plan rollback ordering is invalid")


def _atomic_bytes(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(),
    )


def _require_private_directory(path: Path, description: str) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError(f"{description} is not owned by the agent or is not root-only")


def _read_private_file(path: Path, description: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise RuntimeError(f"{description} is not owned by the agent or is not root-only")
        return b"".join(iter(lambda: os.read(descriptor, 64 * 1024), b""))
    finally:
        os.close(descriptor)


def _checkpoint_key(path: Path) -> bytes:
    try:
        key = _read_private_file(path, "checkpoint encryption key")
    except FileNotFoundError:
        key = AESGCM.generate_key(bit_length=256)
        _atomic_bytes(path, key)
    if len(key) != 32:
        raise RuntimeError("checkpoint encryption key is invalid or not root-only")
    return key


def _read_source_for_checkpoint(root: Path, entry: dict[str, Any]) -> bytes:
    mapped = _mapped_path(root, entry["path"])
    parent_ready, detail = _safe_parent(mapped, root)
    if not parent_ready:
        raise RuntimeError(detail)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(mapped, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_CHECKPOINT_SOURCE_BYTES:
            raise RuntimeError("checkpoint source is not a reviewed regular file")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise RuntimeError("checkpoint source changed while it was being read")
        expected = {
            "source_digest": f"sha256:{digest.hexdigest()}",
            "size_bytes": before.st_size,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "uid": before.st_uid,
            "gid": before.st_gid,
        }
        if any(entry.get(name) != value for name, value in expected.items()):
            raise RuntimeError("checkpoint source changed after recovery planning")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_absent_source_for_checkpoint(root: Path, entry: dict[str, Any]) -> None:
    mapped = _mapped_path(root, entry["path"])
    parent_ready, detail = _safe_parent(mapped, root)
    if not parent_ready:
        raise RuntimeError(detail)
    try:
        mapped.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("checkpoint source changed after recovery planning")


def create_encrypted_checkpoints(
    *,
    checkpoint_job_id: str,
    validation_id: str,
    contract_digest: str,
    recovery_plan: dict[str, Any],
    state_dir: Path,
    root: Path = Path("/"),
) -> dict[str, Any]:
    """Persist encrypted local checkpoints only; never modify or restore host configuration."""

    if not SAFE_JOB_ID.fullmatch(checkpoint_job_id) or not SAFE_JOB_ID.fullmatch(validation_id):
        raise RuntimeError("checkpoint job identity is invalid")
    if recovery_plan.get("status") != "ready" or recovery_plan.get("execution_enabled") is not False:
        raise RuntimeError("recovery plan is not eligible for checkpointing")
    checkpoint_root = state_dir / "remediation-checkpoints"
    checkpoint_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_private_directory(checkpoint_root, "checkpoint storage root")
    job_dir = checkpoint_root / checkpoint_job_id
    job_dir.mkdir(exist_ok=True, mode=0o700)
    _require_private_directory(job_dir, "checkpoint job directory")
    journal_path = job_dir / "journal.json"
    recovery_plan_digest = hashlib.sha256(_canonical(recovery_plan)).hexdigest()
    if journal_path.exists():
        journal = json.loads(
            _read_private_file(journal_path, "checkpoint journal").decode("utf-8")
        )
        if (
            journal.get("checkpoint_job_id") != checkpoint_job_id
            or journal.get("validation_id") != validation_id
            or journal.get("contract_digest") != contract_digest
            or journal.get("recovery_plan_digest") != recovery_plan_digest
        ):
            raise RuntimeError("existing checkpoint journal identity is invalid")
        if journal.get("state") in {"checkpointed", "blocked"}:
            return journal
    else:
        journal = {
            "schema_version": "1.0",
            "kind": "remediation-checkpoint-journal",
            "checkpoint_job_id": checkpoint_job_id,
            "validation_id": validation_id,
            "contract_digest": contract_digest,
            "recovery_plan_digest": recovery_plan_digest,
            "recovery_plan": recovery_plan,
            "state": "checkpointing",
            "checkpoint_results": [],
            "error": None,
            "execution_enabled": False,
            "changes_applied": False,
        }
        _atomic_json(journal_path, journal)
    key = _checkpoint_key(state_dir / "remediation-checkpoints.key")
    cipher = AESGCM(key)
    completed = {item["checkpoint_id"] for item in journal["checkpoint_results"]}
    try:
        for entry in recovery_plan["entries"]:
            if entry["checkpoint_id"] in completed:
                continue
            result = {
                "checkpoint_id": entry["checkpoint_id"],
                "source_state": entry["source_state"],
                "status": "ready",
                "backup_created": False,
                "encrypted_blob_digest": None,
                "encrypted_size_bytes": None,
                "error": None,
            }
            if entry["source_state"] == "regular_file":
                plaintext = _read_source_for_checkpoint(root, entry)
                aad_document = {
                    "checkpoint_job_id": checkpoint_job_id,
                    "contract_digest": contract_digest,
                    "checkpoint_id": entry["checkpoint_id"],
                    "path": entry["path"],
                    "source_digest": entry["source_digest"],
                }
                nonce = os.urandom(12)
                encrypted = cipher.encrypt(nonce, plaintext, _canonical(aad_document))
                blob = CHECKPOINT_BLOB_MAGIC + nonce + encrypted
                current_store_bytes = sum(
                    path.stat().st_size
                    for path in (state_dir / "remediation-checkpoints").rglob("*.bin")
                    if path.is_file() and not path.is_symlink()
                )
                if current_store_bytes + len(blob) > MAX_CHECKPOINT_STORE_BYTES:
                    raise RuntimeError("encrypted checkpoint store reached its 256 MiB safety limit")
                blob_path = job_dir / f"{entry['checkpoint_id']}.bin"
                _atomic_bytes(blob_path, blob)
                verified = cipher.decrypt(
                    blob[len(CHECKPOINT_BLOB_MAGIC) : len(CHECKPOINT_BLOB_MAGIC) + 12],
                    blob[len(CHECKPOINT_BLOB_MAGIC) + 12 :],
                    _canonical(aad_document),
                )
                if hashlib.sha256(verified).hexdigest() != entry["source_digest"].split(":", 1)[1]:
                    raise RuntimeError("encrypted checkpoint verification failed")
                result.update(
                    backup_created=True,
                    encrypted_blob_digest=f"sha256:{hashlib.sha256(blob).hexdigest()}",
                    encrypted_size_bytes=len(blob),
                )
            elif entry["source_state"] == "absent":
                _verify_absent_source_for_checkpoint(root, entry)
            else:
                raise RuntimeError("checkpoint source state is invalid")
            journal["checkpoint_results"].append(result)
            _atomic_json(journal_path, journal)
        journal["state"] = "checkpointed"
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        journal["state"] = "blocked"
        journal["error"] = str(exc)[:1000]
        completed = {item["checkpoint_id"] for item in journal["checkpoint_results"]}
        for entry in recovery_plan["entries"]:
            if entry["checkpoint_id"] in completed:
                continue
            journal["checkpoint_results"].append(
                {
                    "checkpoint_id": entry["checkpoint_id"],
                    "source_state": entry["source_state"],
                    "status": "blocked",
                    "backup_created": False,
                    "encrypted_blob_digest": None,
                    "encrypted_size_bytes": None,
                    "error": journal["error"],
                }
            )
    _atomic_json(journal_path, journal)
    return journal
