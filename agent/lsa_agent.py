#!/usr/bin/env python3
"""LSA unified Linux agent.

The agent only executes the locally installed, versioned LSA scanner. Policy data can
select controls and schedules, but it is never interpreted as a shell command.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import platform
import random
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from .integrity import verify_manifest
    from .remediation_recovery import (
        compile_recovery_plan,
        create_encrypted_checkpoints,
        validate_recovery_plan_binding,
        verify_encrypted_checkpoints,
    )
    from .remediation_contract import (
        RemediationContractError,
        dry_run_remediation_contract,
        sign_validation_receipt,
        validate_remediation_contract_preview,
    )
except ImportError:  # executed directly by the systemd unit
    from integrity import verify_manifest
    from remediation_recovery import (
        compile_recovery_plan,
        create_encrypted_checkpoints,
        validate_recovery_plan_binding,
        verify_encrypted_checkpoints,
    )
    from remediation_contract import (
        RemediationContractError,
        dry_run_remediation_contract,
        sign_validation_receipt,
        validate_remediation_contract_preview,
    )


VERSION = "0.11.1"
DEFAULT_CONFIG = Path("/etc/lsa-agent/config.json")
DEFAULT_STATE_DIR = Path("/var/lib/lsa-agent")
AGENT_CAPABILITIES = (
    "audit",
    "runtime-integrity",
    "policy-rollback-protection",
    "signed-change-set-planning-v1",
    "remediation-contract-validation-v1",
    "remediation-dry-run-v1",
    "remediation-recovery-planning-v1",
    "remediation-checkpoint-v1",
    "remediation-recovery-verification-v1",
    "signed-platform-control-v1",
    "platform-key-rotation-v1",
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_text(path: Path, value: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def platform_url(config: dict[str, Any]) -> str:
    value = str(config["platform_url"]).rstrip("/")
    if urlparse(value).scheme != "https" and not config.get("allow_insecure_development", False):
        raise RuntimeError("platform_url must use HTTPS")
    return value


def state_paths(config: dict[str, Any]) -> tuple[Path, Path]:
    root = Path(config.get("state_dir", DEFAULT_STATE_DIR))
    return root / "state.json", root / "agent-key.pem"


def runtime_integrity(config: dict[str, Any]) -> str:
    scanner_dir = Path(config.get("scanner_dir", "/opt/lsa-agent/scanner")).resolve()
    install_root = scanner_dir.parent
    manifest_path = Path(config.get("integrity_manifest", install_root / "integrity-manifest.json"))
    return f"sha256:{verify_manifest(install_root, manifest_path)}"


def accept_policy_version(state: dict[str, Any], policy: dict[str, Any]) -> int:
    value = policy.get("policy_version")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError("server returned an invalid policy version")
    highest = state.get("highest_policy_version", state.get("policy_version", 0))
    if not isinstance(highest, int) or isinstance(highest, bool) or highest < 0:
        raise RuntimeError("local policy rollback state is invalid")
    if value < highest:
        raise RuntimeError(f"policy rollback rejected: received {value}, highest accepted {highest}")
    state["policy_version"] = value
    state["highest_policy_version"] = max(value, highest)
    return value


def ensure_private_key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("agent key is not Ed25519")
        return key
    key = Ed25519PrivateKey.generate()
    content = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return key


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def canonical_envelope(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_platform_command_key(config: dict[str, Any]) -> tuple[Ed25519PublicKey, bytes]:
    path = Path(config.get("platform_command_key_file", "/etc/lsa-agent/platform-command-key.pub"))
    try:
        raw = base64.b64decode(path.read_text(encoding="utf-8").strip(), validate=True)
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except FileNotFoundError as exc:
        raise RuntimeError(f"pinned platform identity is missing: {path}") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError(f"pinned platform identity is invalid: {path}") from exc


def _envelope_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise RuntimeError(f"platform envelope {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"platform envelope {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(f"platform envelope {field} must include a timezone")
    return parsed.astimezone(UTC)


def verify_platform_envelope(
    envelope: dict[str, Any],
    signature: str,
    trust: dict[str, Any],
    pinned_key: Ed25519PublicKey,
    pinned_raw: bytes,
    *,
    expected_kind: str,
    expected_identity_fingerprint: str,
    state: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    pinned_fingerprint = hashlib.sha256(pinned_raw).hexdigest()
    if trust.get("algorithm") != "Ed25519":
        raise RuntimeError("platform trust algorithm is unsupported")
    if trust.get("fingerprint") != pinned_fingerprint:
        raise RuntimeError("platform identity does not match the pinned key")
    try:
        advertised_raw = base64.b64decode(str(trust.get("public_key", "")), validate=True)
        signature_raw = base64.b64decode(signature, validate=True)
        if advertised_raw != pinned_raw or len(signature_raw) != 64:
            raise ValueError
        pinned_key.verify(signature_raw, canonical_envelope(envelope))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise RuntimeError("platform envelope signature is invalid") from exc

    if envelope.get("schema_version") != "1.0" or envelope.get("kind") != expected_kind:
        raise RuntimeError("platform envelope type is invalid")
    if envelope.get("key_id") != trust.get("key_id"):
        raise RuntimeError("platform envelope key binding is invalid")
    sequence = envelope.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise RuntimeError("platform envelope sequence is invalid")
    prior_sequence = (state or {}).get("platform_envelope_sequence", 0)
    if not isinstance(prior_sequence, int) or sequence <= prior_sequence:
        raise RuntimeError("platform envelope replay or rollback rejected")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    issued_at = _envelope_time(envelope.get("issued_at"), "issued_at")
    expires_at = _envelope_time(envelope.get("expires_at"), "expires_at")
    if issued_at > current + timedelta(minutes=5):
        raise RuntimeError("platform envelope was issued too far in the future")
    if expires_at <= current or expires_at <= issued_at:
        raise RuntimeError("platform envelope is expired")
    if expires_at - issued_at > timedelta(minutes=10):
        raise RuntimeError("platform envelope validity window is too long")

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise RuntimeError("platform envelope payload is invalid")
    if envelope.get("agent_id") != payload.get("agent_id"):
        raise RuntimeError("platform envelope agent binding is invalid")
    if state and envelope.get("agent_id") != state.get("agent_id"):
        raise RuntimeError("platform envelope belongs to another agent")
    if payload.get("agent_identity_fingerprint") != expected_identity_fingerprint:
        raise RuntimeError("platform envelope belongs to another agent identity")
    if payload.get("execution_enabled") is not False:
        raise RuntimeError("platform envelope does not preserve the audit-only safety lock")
    payload["platform_envelope_sequence"] = sequence
    payload["platform_command_key_id"] = trust["key_id"]
    payload["platform_command_key_version"] = trust["key_version"]
    payload["platform_command_key_fingerprint"] = pinned_fingerprint
    return payload


def verify_control_response(
    result: dict[str, Any],
    config: dict[str, Any],
    state: dict[str, Any],
    *,
    expected_kind: str,
) -> dict[str, Any]:
    pinned_key, pinned_raw = load_platform_command_key(config)
    try:
        trust = result["platform_trust"]
        advertised_fingerprint = trust.get("fingerprint")
        pending = state.get("pending_platform_trust")
        verification_key = pinned_key
        verification_raw = pinned_raw
        if advertised_fingerprint != hashlib.sha256(pinned_raw).hexdigest():
            if not isinstance(pending, dict) or pending.get("fingerprint") != advertised_fingerprint:
                raise RuntimeError("platform identity does not match the pinned or staged key")
            try:
                verification_raw = base64.b64decode(str(pending["public_key"]), validate=True)
                if len(verification_raw) != 32:
                    raise ValueError
                verification_key = Ed25519PublicKey.from_public_bytes(verification_raw)
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError("staged platform identity is invalid") from exc
        payload = verify_platform_envelope(
            result["platform_envelope"],
            result["platform_signature"],
            trust,
            verification_key,
            verification_raw,
            expected_kind=expected_kind,
            expected_identity_fingerprint=str(state["agent_identity_fingerprint"]),
            state=state,
        )
        apply_platform_key_rotation(payload, config, state, verification_raw)
        return payload
    except (KeyError, TypeError) as exc:
        raise RuntimeError(f"platform did not return a signed {expected_kind} response") from exc


def apply_platform_key_rotation(
    payload: dict[str, Any],
    config: dict[str, Any],
    state: dict[str, Any],
    signer_raw: bytes,
) -> None:
    rotation = payload.get("platform_key_rotation")
    if rotation is None:
        state.pop("pending_platform_trust", None)
        return
    if not isinstance(rotation, dict):
        raise RuntimeError("platform key rotation metadata is invalid")
    phase = rotation.get("phase")
    signer_fingerprint = hashlib.sha256(signer_raw).hexdigest()
    if phase == "staged":
        proposal = rotation.get("proposal")
        next_key = proposal.get("next_key") if isinstance(proposal, dict) else None
        if (
            not isinstance(proposal, dict)
            or proposal.get("schema_version") != "1.0"
            or proposal.get("kind") != "platform-key-rotation"
            or proposal.get("previous_key_id") != state.get("platform_command_key_id")
            or not isinstance(next_key, dict)
            or next_key.get("algorithm") != "Ed25519"
            or next_key.get("key_id") == state.get("platform_command_key_id")
            or not isinstance(next_key.get("key_version"), int)
            or next_key["key_version"] <= state.get("platform_command_key_version", 0)
        ):
            raise RuntimeError("platform key rotation proposal is invalid")
        try:
            next_raw = base64.b64decode(str(next_key["public_key"]), validate=True)
            previous_signature = base64.b64decode(
                str(rotation["previous_key_signature"]), validate=True
            )
            next_signature = base64.b64decode(
                str(rotation["next_key_signature"]), validate=True
            )
            if (
                len(next_raw) != 32
                or next_key.get("fingerprint") != hashlib.sha256(next_raw).hexdigest()
                or signer_fingerprint != state.get("platform_command_key_fingerprint")
            ):
                raise ValueError
            canonical = canonical_envelope(proposal)
            Ed25519PublicKey.from_public_bytes(signer_raw).verify(previous_signature, canonical)
            Ed25519PublicKey.from_public_bytes(next_raw).verify(next_signature, canonical)
        except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("platform key rotation proof is invalid") from exc
        state["pending_platform_trust"] = next_key
        return
    if phase == "activated":
        next_key = rotation.get("next_key")
        pending = state.get("pending_platform_trust")
        try:
            next_raw = base64.b64decode(str(next_key["public_key"]), validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("platform key activation descriptor is invalid") from exc
        if (
            not isinstance(next_key, dict)
            or next_key.get("algorithm") != "Ed25519"
            or next_raw != signer_raw
            or next_key.get("fingerprint") != signer_fingerprint
            or next_key.get("key_id") != payload.get("platform_command_key_id")
            or next_key.get("key_version") != payload.get("platform_command_key_version")
            or (
                state.get("platform_command_key_fingerprint") != signer_fingerprint
                and (not isinstance(pending, dict) or pending.get("fingerprint") != signer_fingerprint)
            )
        ):
            raise RuntimeError("platform key activation is not acknowledged locally")
        key_path = Path(
            config.get("platform_command_key_file", "/etc/lsa-agent/platform-command-key.pub")
        )
        atomic_text(key_path, str(next_key["public_key"]).strip() + "\n")
        state["platform_command_key_id"] = next_key["key_id"]
        state["platform_command_key_version"] = next_key["key_version"]
        state["platform_command_key_fingerprint"] = signer_fingerprint
        state.pop("pending_platform_trust", None)
        return
    raise RuntimeError("platform key rotation phase is invalid")


def os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def machine_id_hash() -> str:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
    fallback = f"{socket.getfqdn()}:{platform.node()}"
    return f"sha256:{hashlib.sha256(fallback.encode()).hexdigest()}"


def ip_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            value = item[4][0].split("%", 1)[0]
            parsed = ipaddress.ip_address(value)
            if not parsed.is_loopback:
                addresses.add(str(parsed))
    except socket.gaierror:
        pass
    return sorted(addresses)


def memory_mb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        return None
    return None


def uptime_seconds() -> int | None:
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def inventory(config: dict[str, Any]) -> dict[str, Any]:
    release = os_release()
    release_id = release.get("ID", "").lower()
    if release_id == "ubuntu":
        family = "ubuntu"
    elif release_id == "debian":
        family = "debian"
    elif release_id in {"rhel", "rocky", "almalinux", "ol", "centos"}:
        family = "rhel"
    else:
        raise RuntimeError(f"unsupported Linux distribution: {release_id or 'unknown'}")
    hostname = socket.gethostname()
    return {
        "name": config.get("agent_name", hostname),
        "public_key": "",
        "agent_version": VERSION,
        "capabilities": ["audit"],
        "hostname": hostname,
        "fqdn": socket.getfqdn(),
        "machine_id_hash": machine_id_hash(),
        "operating_system": release.get("PRETTY_NAME", platform.system()),
        "os_family": family,
        "os_version": release.get("VERSION_ID", platform.release()),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "ip_addresses": ip_addresses(),
        "tags": config.get("tags", {}),
        "system_info": {
            "cpu_cores": os.cpu_count(),
            "memory_mb": memory_mb(),
            "uptime_seconds": uptime_seconds(),
            "timezone": datetime.now().astimezone().tzname(),
        },
    }


def http_client(config: dict[str, Any]) -> httpx.Client:
    return httpx.Client(base_url=platform_url(config), verify=False, timeout=120.0)


def signed_headers(key: Ed25519PrivateKey, agent_id: str, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(datetime.now(UTC).timestamp()))
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{method}\n{path}\n{timestamp}\n{body_hash}".encode()
    return {
        "X-LSA-Agent-ID": agent_id,
        "X-LSA-Agent-Timestamp": timestamp,
        "X-LSA-Agent-Signature": base64.b64encode(key.sign(message)).decode(),
        "X-LSA-Platform-Control": "signed-v1",
    }


def enroll(config: dict[str, Any], token: str) -> None:
    state_path, key_path = state_paths(config)
    if state_path.exists():
        raise RuntimeError(f"agent is already enrolled: {state_path}")
    key = ensure_private_key(key_path)
    pinned_key, pinned_raw = load_platform_command_key(config)
    payload = inventory(config)
    payload["public_key"] = public_key_b64(key)
    identity_fingerprint = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    with http_client(config) as client:
        response = client.post(
            "/api/v1/agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        response.raise_for_status()
        result = response.json()
    try:
        state = verify_platform_envelope(
            result["platform_envelope"],
            result["platform_signature"],
            result["platform_trust"],
            pinned_key,
            pinned_raw,
            expected_kind="agent-enrollment",
            expected_identity_fingerprint=identity_fingerprint,
        )
    except (KeyError, TypeError) as exc:
        raise RuntimeError("platform did not return a signed enrollment proof") from exc
    if state.get("signed_control_required") is not True:
        raise RuntimeError("platform did not require signed control responses")
    apply_platform_key_rotation(state, config, state, pinned_raw)
    state["enrolled_at"] = datetime.now(UTC).isoformat()
    state["highest_policy_version"] = state.get("policy_version", 0)
    atomic_json(state_path, state)
    print("Platform identity verified")
    print(f"Fingerprint: SHA256:{state['platform_command_key_fingerprint']}")
    print(f"Enrolled agent {state['agent_id']} for host {state['host_id']}")


def signed_get(config: dict[str, Any], state: dict[str, Any], key: Ed25519PrivateKey, path: str) -> Any:
    with http_client(config) as client:
        response = client.get(path, headers=signed_headers(key, state["agent_id"], "GET", path, b""))
        response.raise_for_status()
        return response.json()


def signed_post(config: dict[str, Any], state: dict[str, Any], key: Ed25519PrivateKey, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = signed_headers(key, state["agent_id"], "POST", path, body)
    headers["Content-Type"] = "application/json"
    with http_client(config) as client:
        response = client.post(path, headers=headers, content=body)
        response.raise_for_status()
        return response.json()


def signed_control_get(
    config: dict[str, Any],
    state: dict[str, Any],
    key: Ed25519PrivateKey,
    path: str,
    kind: str,
) -> dict[str, Any]:
    result = signed_get(config, state, key, path)
    payload = verify_control_response(result, config, state, expected_kind=kind)
    state["platform_envelope_sequence"] = payload.pop("platform_envelope_sequence")
    atomic_json(state_paths(config)[0], state)
    return payload


def signed_control_post(
    config: dict[str, Any],
    state: dict[str, Any],
    key: Ed25519PrivateKey,
    path: str,
    payload: dict[str, Any],
    kind: str,
) -> dict[str, Any]:
    result = signed_post(config, state, key, path, payload)
    verified = verify_control_response(result, config, state, expected_kind=kind)
    state["platform_envelope_sequence"] = verified.pop("platform_envelope_sequence")
    atomic_json(state_paths(config)[0], state)
    return verified


def run_scanner(config: dict[str, Any], state: dict[str, Any], key_path: Path, policy: dict[str, Any]) -> None:
    if policy.get("enforcement_enabled") is not False:
        raise RuntimeError("server did not provide the required audit-only enforcement lock")
    scanner_dir = Path(config.get("scanner_dir", "/opt/lsa-agent/scanner")).resolve()
    playbook = scanner_dir / "playbooks" / "scan.yml"
    if not playbook.is_file():
        raise RuntimeError(f"scanner playbook not found: {playbook}")
    state_root = Path(config.get("state_dir", DEFAULT_STATE_DIR))
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_path = state_root / "ingestion-token"
    token_path.write_text(state["ingestion_token"], encoding="utf-8")
    os.chmod(token_path, 0o600)
    settings = policy.get("settings", {})
    extra_vars = {
        "lsa_host_id": state["host_id"],
        "lsa_platform_url": platform_url(config),
        "lsa_delivery_mode": "upload_and_keep",
        "lsa_output_root": str(state_root / "reports"),
        "lsa_ingest_token_file": str(token_path),
        "lsa_signing_key_file": str(key_path),
        "lsa_signing_key_id": state["signing_key_id"],
        "lsa_profile": settings.get("profile", "level2_server"),
        "lsa_policy_default_mode": policy.get("default_mode", "audit"),
        "lsa_policy_control_modes": policy.get("control_modes", {}),
        "lsa_validate_certs": False,
    }
    with tempfile.TemporaryDirectory(prefix="lsa-agent-", dir=state_root) as temporary:
        temporary_path = Path(temporary)
        ansible_home = temporary_path / "ansible-home"
        ansible_local_temp = temporary_path / "ansible-local"
        ansible_remote_temp = temporary_path / "ansible-remote"
        for runtime_path in (ansible_home, ansible_local_temp, ansible_remote_temp):
            runtime_path.mkdir(mode=0o700)
            os.chmod(runtime_path, 0o700)
        inventory_path = temporary_path / "inventory.ini"
        variables_path = temporary_path / "policy.json"
        inventory_path.write_text("[managed]\nlocalhost ansible_connection=local\n", encoding="utf-8")
        variables_path.write_text(json.dumps(extra_vars), encoding="utf-8")
        command = [
            config.get("ansible_playbook", "ansible-playbook"),
            "-i",
            str(inventory_path),
            str(playbook),
            "--extra-vars",
            f"@{variables_path}",
        ]
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(scanner_dir / "ansible.cfg")
        environment["ANSIBLE_HOME"] = str(ansible_home)
        environment["ANSIBLE_LOCAL_TEMP"] = str(ansible_local_temp)
        environment["ANSIBLE_REMOTE_TEMP"] = str(ansible_remote_temp)
        environment["ANSIBLE_REMOTE_TMP"] = str(ansible_remote_temp)
        subprocess.run(command, cwd=scanner_dir, env=environment, check=True)


def _scan_due(state: dict[str, Any]) -> bool:
    value = state.get("next_scan_at")
    if not value:
        return True
    try:
        return datetime.now(UTC) >= datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True


def process_remediation_validation(
    config: dict[str, Any],
    state: dict[str, Any],
    key: Ed25519PrivateKey,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    validation = payload.get("validation")
    if validation is None:
        return None
    if not isinstance(validation, dict) or set(validation) != {
        "validation_id",
        "change_set_id",
        "contract_digest",
        "contract",
    }:
        raise RuntimeError("platform returned an invalid remediation validation wrapper")
    validation_id = validation["validation_id"]
    change_set_id = validation["change_set_id"]
    contract_digest = validation["contract_digest"]
    contract = validation["contract"]
    if not all(isinstance(value, str) and value for value in (validation_id, change_set_id)):
        raise RuntimeError("remediation validation identity is invalid")
    if not isinstance(contract, dict) or not isinstance(contract_digest, str):
        raise RuntimeError("remediation validation contract is invalid")
    calculated_digest = hashlib.sha256(
        json.dumps(
            contract,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    if calculated_digest != contract_digest:
        raise RuntimeError("remediation validation contract digest is invalid")
    cached_receipts = state.setdefault("remediation_validation_receipts", {})
    cached = cached_receipts.get(validation_id) if isinstance(cached_receipts, dict) else None
    if (
        isinstance(cached, dict)
        and cached.get("contract_digest") == contract_digest
        and isinstance(cached.get("receipt"), dict)
        and isinstance(cached.get("signature"), str)
    ):
        receipt = cached["receipt"]
        receipt_signature = cached["signature"]
    else:
        error: str | None = None
        action_results: list[dict[str, Any]] = []
        recovery_plan: dict[str, Any] | None = None
        status = "blocked"
        try:
            pinned_key, pinned_raw = load_platform_command_key(config)
            validate_remediation_contract_preview(
                contract,
                pinned_platform_key=pinned_key,
                pinned_platform_raw=pinned_raw,
                expected_platform_key_id=str(state["platform_command_key_id"]),
                expected_agent_id=str(state["agent_id"]),
                expected_host_id=str(state["host_id"]),
            )
            dry_run = dry_run_remediation_contract(contract)
            status = str(dry_run["status"])
            action_results = list(dry_run["action_results"])
            recovery_plan = compile_recovery_plan(contract)
            if recovery_plan["status"] != "ready":
                status = "blocked"
        except RemediationContractError as exc:
            error = f"Contract validation failed: {exc}"
        receipt = {
            "schema_version": "1.0",
            "kind": "remediation-validation-receipt",
            "validation_id": validation_id,
            "change_set_id": change_set_id,
            "contract_digest": contract_digest,
            "agent_id": str(state["agent_id"]),
            "host_id": str(state["host_id"]),
            "status": status,
            "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "execution_enabled": False,
            "changes_applied": False,
            "agent_version": VERSION,
            "agent_integrity_digest": str(state["integrity_manifest_sha256"]),
            "action_results": action_results,
            "recovery_plan": recovery_plan,
            "error": error,
        }
        receipt_signature = sign_validation_receipt(key, receipt)
        if not isinstance(cached_receipts, dict):
            cached_receipts = {}
            state["remediation_validation_receipts"] = cached_receipts
        cached_receipts[validation_id] = {
            "contract_digest": contract_digest,
            "receipt": receipt,
            "signature": receipt_signature,
        }
        while len(cached_receipts) > 50:
            cached_receipts.pop(next(iter(cached_receipts)))
        atomic_json(state_paths(config)[0], state)
    path = f"/api/v1/agent/remediation-validations/{validation_id}/receipt"
    acknowledgement = signed_control_post(
        config,
        state,
        key,
        path,
        {"receipt": receipt, "signature": receipt_signature},
        "remediation-validation-receipt",
    )
    if acknowledgement.get("accepted") is not True:
        raise RuntimeError("platform did not accept the remediation validation receipt")
    return {
        "validation_id": validation_id,
        "status": receipt["status"],
        "changes_applied": False,
    }


def process_remediation_checkpoint(
    config: dict[str, Any],
    state: dict[str, Any],
    key: Ed25519PrivateKey,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    checkpoint = payload.get("checkpoint")
    if checkpoint is None:
        return None
    expected_keys = {
        "checkpoint_job_id",
        "validation_id",
        "change_set_id",
        "contract_digest",
        "contract",
        "recovery_plan",
    }
    if not isinstance(checkpoint, dict) or set(checkpoint) != expected_keys:
        raise RuntimeError("platform returned an invalid remediation checkpoint wrapper")
    checkpoint_job_id = checkpoint["checkpoint_job_id"]
    validation_id = checkpoint["validation_id"]
    change_set_id = checkpoint["change_set_id"]
    contract_digest = checkpoint["contract_digest"]
    contract = checkpoint["contract"]
    recovery_plan = checkpoint["recovery_plan"]
    if not all(
        isinstance(value, str) and value
        for value in (checkpoint_job_id, validation_id, change_set_id, contract_digest)
    ) or not isinstance(contract, dict) or not isinstance(recovery_plan, dict):
        raise RuntimeError("remediation checkpoint identity is invalid")
    calculated_digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if calculated_digest != contract_digest:
        raise RuntimeError("remediation checkpoint contract digest is invalid")
    cached_receipts = state.setdefault("remediation_checkpoint_receipts", {})
    cached = cached_receipts.get(checkpoint_job_id) if isinstance(cached_receipts, dict) else None
    if (
        isinstance(cached, dict)
        and cached.get("contract_digest") == contract_digest
        and isinstance(cached.get("receipt"), dict)
        and isinstance(cached.get("signature"), str)
    ):
        receipt = cached["receipt"]
        signature = cached["signature"]
    else:
        journal: dict[str, Any]
        try:
            pinned_key, pinned_raw = load_platform_command_key(config)
            validate_remediation_contract_preview(
                contract,
                pinned_platform_key=pinned_key,
                pinned_platform_raw=pinned_raw,
                expected_platform_key_id=str(state["platform_command_key_id"]),
                expected_agent_id=str(state["agent_id"]),
                expected_host_id=str(state["host_id"]),
            )
            validate_recovery_plan_binding(contract, recovery_plan)
            journal = create_encrypted_checkpoints(
                checkpoint_job_id=checkpoint_job_id,
                validation_id=validation_id,
                contract_digest=contract_digest,
                recovery_plan=recovery_plan,
                state_dir=Path(config.get("state_dir", DEFAULT_STATE_DIR)),
                root=Path(config.get("inspection_root", "/")),
            )
        except (
            AttributeError,
            KeyError,
            RemediationContractError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            journal = {
                "state": "blocked",
                "checkpoint_results": [
                    {
                        "checkpoint_id": entry["checkpoint_id"],
                        "source_state": entry["source_state"],
                        "status": "blocked",
                        "backup_created": False,
                        "encrypted_blob_digest": None,
                        "encrypted_size_bytes": None,
                        "error": str(exc)[:1000],
                    }
                    for entry in recovery_plan.get("entries", [])
                    if isinstance(entry, dict)
                ],
                "error": str(exc)[:1000],
            }
        status = "ready" if journal["state"] == "checkpointed" else "blocked"
        receipt = {
            "schema_version": "1.0",
            "kind": "remediation-checkpoint-receipt",
            "checkpoint_job_id": checkpoint_job_id,
            "validation_id": validation_id,
            "change_set_id": change_set_id,
            "contract_digest": contract_digest,
            "agent_id": str(state["agent_id"]),
            "host_id": str(state["host_id"]),
            "status": status,
            "journal_state": journal["state"],
            "journal_digest": hashlib.sha256(
                json.dumps(
                    journal,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode()
            ).hexdigest(),
            "storage_scope": "agent_local_encrypted",
            "encryption": "AES-256-GCM",
            "prepared_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "agent_version": VERSION,
            "agent_integrity_digest": str(state["integrity_manifest_sha256"]),
            "checkpoint_results": journal["checkpoint_results"],
            "error": journal.get("error"),
            "execution_enabled": False,
            "changes_applied": False,
        }
        signature = sign_validation_receipt(key, receipt)
        if not isinstance(cached_receipts, dict):
            cached_receipts = {}
            state["remediation_checkpoint_receipts"] = cached_receipts
        cached_receipts[checkpoint_job_id] = {
            "contract_digest": contract_digest,
            "receipt": receipt,
            "signature": signature,
        }
        while len(cached_receipts) > 50:
            cached_receipts.pop(next(iter(cached_receipts)))
        atomic_json(state_paths(config)[0], state)
    path = f"/api/v1/agent/remediation-checkpoints/{checkpoint_job_id}/receipt"
    acknowledgement = signed_control_post(
        config,
        state,
        key,
        path,
        {"receipt": receipt, "signature": signature},
        "remediation-checkpoint-receipt",
    )
    if acknowledgement.get("accepted") is not True:
        raise RuntimeError("platform did not accept the remediation checkpoint receipt")
    return {
        "checkpoint_job_id": checkpoint_job_id,
        "status": receipt["status"],
        "changes_applied": False,
    }


def process_recovery_verification(
    config: dict[str, Any],
    state: dict[str, Any],
    key: Ed25519PrivateKey,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    verification = payload.get("verification")
    if verification is None:
        return None
    expected_keys = {
        "verification_job_id",
        "checkpoint_job_id",
        "validation_id",
        "change_set_id",
        "contract_digest",
        "contract",
        "recovery_plan",
        "checkpoint_journal_digest",
    }
    if not isinstance(verification, dict) or set(verification) != expected_keys:
        raise RuntimeError("platform returned an invalid recovery verification wrapper")
    identities = {
        name: verification[name]
        for name in (
            "verification_job_id",
            "checkpoint_job_id",
            "validation_id",
            "change_set_id",
            "contract_digest",
            "checkpoint_journal_digest",
        )
    }
    if not all(isinstance(value, str) and value for value in identities.values()):
        raise RuntimeError("recovery verification identity is invalid")
    contract = verification["contract"]
    recovery_plan = verification["recovery_plan"]
    if not isinstance(contract, dict) or not isinstance(recovery_plan, dict):
        raise RuntimeError("recovery verification contract is invalid")
    calculated_digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if calculated_digest != identities["contract_digest"]:
        raise RuntimeError("recovery verification contract digest is invalid")
    cached_receipts = state.setdefault("recovery_verification_receipts", {})
    cached = (
        cached_receipts.get(identities["verification_job_id"])
        if isinstance(cached_receipts, dict)
        else None
    )
    if (
        isinstance(cached, dict)
        and cached.get("contract_digest") == identities["contract_digest"]
        and cached.get("checkpoint_journal_digest")
        == identities["checkpoint_journal_digest"]
        and isinstance(cached.get("receipt"), dict)
        and isinstance(cached.get("signature"), str)
    ):
        receipt = cached["receipt"]
        signature = cached["signature"]
    else:
        try:
            pinned_key, pinned_raw = load_platform_command_key(config)
            validate_remediation_contract_preview(
                contract,
                pinned_platform_key=pinned_key,
                pinned_platform_raw=pinned_raw,
                expected_platform_key_id=str(state["platform_command_key_id"]),
                expected_agent_id=str(state["agent_id"]),
                expected_host_id=str(state["host_id"]),
            )
            validate_recovery_plan_binding(contract, recovery_plan)
            verification_result = verify_encrypted_checkpoints(
                checkpoint_job_id=identities["checkpoint_job_id"],
                validation_id=identities["validation_id"],
                contract_digest=identities["contract_digest"],
                recovery_plan=recovery_plan,
                expected_journal_digest=identities["checkpoint_journal_digest"],
                state_dir=Path(config.get("state_dir", DEFAULT_STATE_DIR)),
            )
        except (
            AttributeError,
            KeyError,
            RemediationContractError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            verification_result = {
                "state": "blocked",
                "verification_results": [
                    {
                        "checkpoint_id": entry["checkpoint_id"],
                        "source_state": entry["source_state"],
                        "status": "blocked",
                        "encrypted_blob_digest": None,
                        "encrypted_size_bytes": None,
                        "error": str(exc)[:1000],
                    }
                    for entry in recovery_plan.get("entries", [])
                    if isinstance(entry, dict)
                ],
                "error": str(exc)[:1000],
            }
        status = "ready" if verification_result["state"] == "verified" else "blocked"
        receipt = {
            "schema_version": "1.0",
            "kind": "remediation-recovery-verification-receipt",
            **identities,
            "agent_id": str(state["agent_id"]),
            "host_id": str(state["host_id"]),
            "status": status,
            "verification_state": verification_result["state"],
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "agent_version": VERSION,
            "agent_integrity_digest": str(state["integrity_manifest_sha256"]),
            "verification_results": verification_result["verification_results"],
            "error": verification_result.get("error"),
            "execution_enabled": False,
            "changes_applied": False,
        }
        signature = sign_validation_receipt(key, receipt)
        if not isinstance(cached_receipts, dict):
            cached_receipts = {}
            state["recovery_verification_receipts"] = cached_receipts
        cached_receipts[identities["verification_job_id"]] = {
            "contract_digest": identities["contract_digest"],
            "checkpoint_journal_digest": identities["checkpoint_journal_digest"],
            "receipt": receipt,
            "signature": signature,
        }
        while len(cached_receipts) > 50:
            cached_receipts.pop(next(iter(cached_receipts)))
        atomic_json(state_paths(config)[0], state)
    acknowledgement = signed_control_post(
        config,
        state,
        key,
        f"/api/v1/agent/remediation-recovery-verifications/{identities['verification_job_id']}/receipt",
        {"receipt": receipt, "signature": signature},
        "remediation-recovery-verification-receipt",
    )
    if acknowledgement.get("accepted") is not True:
        raise RuntimeError("platform did not accept the recovery verification receipt")
    return {
        "verification_job_id": identities["verification_job_id"],
        "status": receipt["status"],
        "changes_applied": False,
    }


def agent_cycle(config: dict[str, Any], *, always_scan: bool = False) -> dict[str, Any]:
    if os.geteuid() != 0 and not config.get("allow_unprivileged_development", False):
        raise RuntimeError("LSA agent must run as root to read protected audit evidence")
    state_path, key_path = state_paths(config)
    state = read_json(state_path)
    key = ensure_private_key(key_path)
    integrity_digest = runtime_integrity(config)
    policy = signed_control_get(
        config, state, key, "/api/v1/agent/policy", "agent-policy"
    )
    policy_version = accept_policy_version(state, policy)
    capabilities = list(AGENT_CAPABILITIES)
    heartbeat = signed_control_post(
        config,
        state,
        key,
        "/api/v1/agent/heartbeat",
        {
            "agent_version": VERSION,
            "capabilities": capabilities,
            "policy_version": policy_version,
            "platform_key_ack_fingerprint": (
                state.get("pending_platform_trust", {}).get("fingerprint")
                if isinstance(state.get("pending_platform_trust"), dict)
                else None
            ),
        },
        "agent-heartbeat",
    )
    state["integrity_manifest_sha256"] = integrity_digest
    validation_result: dict[str, Any] | None = None
    try:
        validation_payload = signed_control_get(
            config,
            state,
            key,
            "/api/v1/agent/remediation-validations/next",
            "remediation-validation",
        )
        validation_result = process_remediation_validation(
            config,
            state,
            key,
            validation_payload,
        )
    except (httpx.HTTPError, RuntimeError) as exc:
        print(
            f"LSA agent remediation dry-run cycle failed without applying changes: {exc}",
            file=sys.stderr,
            flush=True,
        )
    checkpoint_result: dict[str, Any] | None = None
    try:
        checkpoint_payload = signed_control_get(
            config,
            state,
            key,
            "/api/v1/agent/remediation-checkpoints/next",
            "remediation-checkpoint",
        )
        checkpoint_result = process_remediation_checkpoint(
            config,
            state,
            key,
            checkpoint_payload,
        )
    except (httpx.HTTPError, RuntimeError) as exc:
        print(
            f"LSA agent checkpoint cycle failed without applying changes: {exc}",
            file=sys.stderr,
            flush=True,
        )
    verification_result: dict[str, Any] | None = None
    try:
        verification_payload = signed_control_get(
            config,
            state,
            key,
            "/api/v1/agent/remediation-recovery-verifications/next",
            "remediation-recovery-verification",
        )
        verification_result = process_recovery_verification(
            config,
            state,
            key,
            verification_payload,
        )
    except (httpx.HTTPError, RuntimeError) as exc:
        print(
            f"LSA agent recovery verification cycle failed without applying changes: {exc}",
            file=sys.stderr,
            flush=True,
        )
    task_payload = signed_control_get(
        config, state, key, "/api/v1/agent/tasks/next", "agent-task"
    )
    task = task_payload.get("task")
    should_scan = always_scan or task is not None or _scan_due(state)
    if should_scan:
        try:
            run_scanner(config, state, key_path, policy)
            completed_at = datetime.now(UTC)
            state["last_scan_at"] = completed_at.isoformat()
            settings = policy.get("settings", {})
            interval = int(settings.get("schedule_minutes", 60)) * 60
            jitter = random.randint(0, max(0, int(settings.get("jitter_seconds", 300))))
            state["next_scan_at"] = datetime.fromtimestamp(completed_at.timestamp() + interval + jitter, UTC).isoformat()
            if task is not None:
                signed_control_post(config, state, key, f"/api/v1/agent/tasks/{task['id']}/complete", {
                    "status": "completed",
                    "result": {"completed_at": completed_at.isoformat(), "policy_version": policy["policy_version"]},
                    "error": None,
                }, "agent-task-completion")
        except Exception as exc:
            if task is not None:
                try:
                    signed_control_post(config, state, key, f"/api/v1/agent/tasks/{task['id']}/complete", {
                        "status": "failed",
                        "result": {},
                        "error": str(exc)[:4000],
                    }, "agent-task-completion")
                except (httpx.HTTPError, RuntimeError) as report_error:
                    print(f"LSA agent could not report failed audit task: {report_error}", file=sys.stderr, flush=True)
            raise
    atomic_json(state_path, state)
    return {
        "policy": policy,
        "heartbeat": heartbeat,
        "validation": validation_result,
        "checkpoint": checkpoint_result,
        "recovery_verification": verification_result,
        "task": task,
        "scanned": should_scan,
    }


def run_once(config: dict[str, Any]) -> dict[str, Any]:
    return agent_cycle(config, always_scan=True)


def daemon(config: dict[str, Any]) -> None:
    while True:
        try:
            agent_cycle(config)
            interval = max(15, int(config.get("poll_seconds", 60)))
        except Exception as exc:  # keep a supervised agent alive across transient failures
            print(f"LSA agent cycle failed: {exc}", file=sys.stderr, flush=True)
            interval = 60
        time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Linux Security Auditor unified agent")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)
    enroll_parser = subparsers.add_parser("enroll", help="enroll with a one-time token")
    enrollment_source = enroll_parser.add_mutually_exclusive_group(required=True)
    enrollment_source.add_argument("--token")
    enrollment_source.add_argument("--token-file", type=Path)
    subparsers.add_parser("once", help="poll policy and run one audit")
    subparsers.add_parser("daemon", help="continuously poll and audit")
    arguments = parser.parse_args()
    try:
        config = read_json(arguments.config)
        print(
            "WARNING: LSA agent server certificate verification is disabled; "
            "HTTPS traffic is encrypted and platform control responses are authenticated with "
            "the pinned application-layer signing key.",
            file=sys.stderr,
        )
        if arguments.command == "enroll":
            token = arguments.token
            if arguments.token_file:
                token = arguments.token_file.read_text(encoding="utf-8").strip()
            if not token:
                raise ValueError("enrollment token is empty")
            enroll(config, token)
        elif arguments.command == "once":
            run_once(config)
        else:
            daemon(config)
        return 0
    except (OSError, ValueError, RuntimeError, httpx.HTTPError, subprocess.CalledProcessError) as exc:
        print(f"lsa-agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
