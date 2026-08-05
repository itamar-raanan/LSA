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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from .integrity import verify_manifest
except ImportError:  # executed directly by the systemd unit
    from integrity import verify_manifest


VERSION = "0.4.1"
DEFAULT_CONFIG = Path("/etc/lsa-agent/config.json")
DEFAULT_STATE_DIR = Path("/var/lib/lsa-agent")


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
    }


def enroll(config: dict[str, Any], token: str) -> None:
    state_path, key_path = state_paths(config)
    if state_path.exists():
        raise RuntimeError(f"agent is already enrolled: {state_path}")
    key = ensure_private_key(key_path)
    payload = inventory(config)
    payload["public_key"] = public_key_b64(key)
    with http_client(config) as client:
        response = client.post(
            "/api/v1/agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        response.raise_for_status()
        state = response.json()
    state["enrolled_at"] = datetime.now(UTC).isoformat()
    state["highest_policy_version"] = state.get("policy_version", 0)
    atomic_json(state_path, state)
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


def run_scanner(config: dict[str, Any], state: dict[str, Any], key_path: Path, policy: dict[str, Any]) -> None:
    if policy.get("enforcement_enabled") is not False:
        raise RuntimeError("server did not provide the required audit-only enforcement lock")
    scanner_dir = Path(config.get("scanner_dir", "/opt/lsa-agent/scanner")).resolve()
    playbook = scanner_dir / "playbooks" / "scan.yml"
    if not playbook.is_file():
        raise RuntimeError(f"scanner playbook not found: {playbook}")
    state_root = Path(config.get("state_dir", DEFAULT_STATE_DIR))
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
        subprocess.run(command, cwd=scanner_dir, env=environment, check=True)


def _scan_due(state: dict[str, Any]) -> bool:
    value = state.get("next_scan_at")
    if not value:
        return True
    try:
        return datetime.now(UTC) >= datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True


def agent_cycle(config: dict[str, Any], *, always_scan: bool = False) -> dict[str, Any]:
    if os.geteuid() != 0 and not config.get("allow_unprivileged_development", False):
        raise RuntimeError("LSA agent must run as root to read protected audit evidence")
    state_path, key_path = state_paths(config)
    state = read_json(state_path)
    key = ensure_private_key(key_path)
    integrity_digest = runtime_integrity(config)
    policy = signed_get(config, state, key, "/api/v1/agent/policy")
    policy_version = accept_policy_version(state, policy)
    capabilities = ["audit", "runtime-integrity", "policy-rollback-protection"]
    heartbeat = signed_post(
        config,
        state,
        key,
        "/api/v1/agent/heartbeat",
        {
            "agent_version": VERSION,
            "capabilities": capabilities,
            "policy_version": policy_version,
        },
    )
    state["integrity_manifest_sha256"] = integrity_digest
    task = signed_get(config, state, key, "/api/v1/agent/tasks/next")
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
                signed_post(config, state, key, f"/api/v1/agent/tasks/{task['id']}/complete", {
                    "status": "completed",
                    "result": {"completed_at": completed_at.isoformat(), "policy_version": policy["policy_version"]},
                    "error": None,
                })
        except Exception as exc:
            if task is not None:
                try:
                    signed_post(config, state, key, f"/api/v1/agent/tasks/{task['id']}/complete", {
                        "status": "failed",
                        "result": {},
                        "error": str(exc)[:4000],
                    })
                except httpx.HTTPError as report_error:
                    print(f"LSA agent could not report failed audit task: {report_error}", file=sys.stderr, flush=True)
            raise
    atomic_json(state_path, state)
    return {"policy": policy, "heartbeat": heartbeat, "task": task, "scanned": should_scan}


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
            "HTTPS traffic is encrypted but the platform identity is not authenticated.",
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
