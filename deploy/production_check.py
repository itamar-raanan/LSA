#!/usr/bin/env python3
"""Secret-safe preflight checks for the supported internal production profile."""

from __future__ import annotations

import base64
import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlparse


EXAMPLE_ENCRYPTION_KEY = "DEOXPmN1UnYYmJOHcse7e1p96ltyDlfPsNq0fh-39m4="
PLACEHOLDER_MARKERS = ("replace-", "change-", "example-password", "demo", "changeme")


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"line {number} is not KEY=VALUE syntax")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or any(character.isspace() for character in key):
            raise ValueError(f"line {number} has an invalid key")
        values[key] = value.strip().strip("\"").strip("'")
    return values


def _secret_error(values: dict[str, str], key: str, minimum: int) -> str | None:
    value = values.get(key, "")
    if len(value) < minimum:
        return f"{key} must contain at least {minimum} characters"
    if any(marker in value.lower() for marker in PLACEHOLDER_MARKERS):
        return f"{key} still contains a development placeholder"
    return None


def _non_local_hostname(value: str) -> bool:
    normalized = value.strip().lower().rstrip(".")
    if normalized in {"", "localhost"}:
        return False
    try:
        return not ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return "." in normalized or normalized.replace("-", "").isalnum()


def validate(values: dict[str, str], *, release: bool = True) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    for key, minimum in (
        ("LSA_POSTGRES_PASSWORD", 24),
        ("LSA_S3_ACCESS_KEY", 16),
        ("LSA_S3_SECRET_KEY", 32),
        ("LSA_SESSION_SECRET", 32),
        ("LSA_BOOTSTRAP_PASSWORD", 16),
    ):
        if error := _secret_error(values, key, minimum):
            errors.append(error)
    encryption_key = values.get("LSA_SETTINGS_ENCRYPTION_KEY", "")
    try:
        decoded = base64.urlsafe_b64decode(encryption_key.encode())
    except Exception:  # noqa: BLE001 - a malformed secret must become a bounded finding
        decoded = b""
    if len(decoded) != 32 or encryption_key == EXAMPLE_ENCRYPTION_KEY:
        errors.append("LSA_SETTINGS_ENCRYPTION_KEY must be a newly generated Fernet key")
    if values.get("LSA_SEED_DEMO", "").lower() != "false":
        errors.append("LSA_SEED_DEMO must be false")
    if values.get("LSA_REQUIRE_SIGNED_BUNDLES", "").lower() != "true":
        errors.append("LSA_REQUIRE_SIGNED_BUNDLES must be true")
    if values.get("LSA_AGENT_NETWORK_SCOPE", "").lower() != "internal":
        errors.append("LSA_AGENT_NETWORK_SCOPE must explicitly be internal")
    if values.get("LSA_AGENT_FIREWALL_ACKNOWLEDGED", "").lower() != "true":
        errors.append("LSA_AGENT_FIREWALL_ACKNOWLEDGED must be true after firewall review")
    if values.get("LSA_MANAGEMENT_TLS_INSTALLED", "").lower() != "true":
        finding = "LSA_MANAGEMENT_TLS_INSTALLED must be true after trusted certificate installation"
        (errors if release else warnings).append(finding)
    if values.get("LSA_VOLUME_ENCRYPTION_ACKNOWLEDGED", "").lower() != "true":
        errors.append("LSA_VOLUME_ENCRYPTION_ACKNOWLEDGED must be true after storage review")
    if values.get("LSA_BACKUP_RESTORE_DRILL_ACKNOWLEDGED", "").lower() != "true":
        finding = "LSA_BACKUP_RESTORE_DRILL_ACKNOWLEDGED must be true after a successful drill"
        (errors if release else warnings).append(finding)
    bootstrap_email = values.get("LSA_BOOTSTRAP_EMAIL", "").lower()
    if not bootstrap_email or bootstrap_email.endswith("@example.com") or bootstrap_email.endswith("@lsa.local"):
        errors.append("LSA_BOOTSTRAP_EMAIL must be an operational administrator address")
    if not _non_local_hostname(values.get("LSA_TLS_HOST", "")):
        errors.append("LSA_TLS_HOST must be the non-local management DNS name")
    agent_url = urlparse(values.get("LSA_AGENT_PUBLIC_URL", ""))
    if (
        agent_url.scheme != "https"
        or not agent_url.hostname
        or not _non_local_hostname(agent_url.hostname)
        or agent_url.path not in {"", "/"}
        or agent_url.query
        or agent_url.fragment
    ):
        errors.append("LSA_AGENT_PUBLIC_URL must be a non-local HTTPS origin without a path")
    if values.get("LSA_S3_SERVER_SIDE_ENCRYPTION", "none") == "none":
        warnings.append("Object-level encryption is disabled; encrypted host storage is required")
    if values.get("LSA_TLS_BIND", "127.0.0.1") == "0.0.0.0":
        warnings.append("Management listens on every interface; restrict it with the host firewall")
    if values.get("LSA_AGENT_TLS_BIND", "127.0.0.1") == "0.0.0.0":
        warnings.append("Agent gateway listens on every interface; allow only managed internal networks")
    return errors, warnings


def main(argv: list[str]) -> int:
    staging = "--staging" in argv[1:]
    positional = [argument for argument in argv[1:] if not argument.startswith("--")]
    path = Path(positional[0] if positional else "deploy/.env")
    try:
        if path.stat().st_mode & 0o077:
            raise ValueError(f"{path} must be readable and writable only by its owner (chmod 600)")
        values = read_env(path)
        errors, warnings = validate(values, release=not staging)
    except (OSError, ValueError) as exc:
        print(f"PRODUCTION CHECK FAILED: {exc}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"FAILED: {error}", file=sys.stderr)
        print(f"PRODUCTION CHECK FAILED: {len(errors)} blocking condition(s)", file=sys.stderr)
        return 1
    label = "STAGING" if staging else "PRODUCTION"
    print(f"{label} CHECK PASSED: internal audit-only deployment gates are satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
