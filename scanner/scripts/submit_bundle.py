#!/usr/bin/env python3
"""Submit an LSA bundle without exposing its ingestion token in Ansible output."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx


def response_detail(response: httpx.Response) -> str:
    """Return a bounded, human-readable API error without request credentials."""
    try:
        payload: Any = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = response.text
    if isinstance(payload, dict) and "detail" in payload:
        payload = payload["detail"]
    if not isinstance(payload, str):
        payload = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return " ".join(payload.split())[:2000] or "No error detail returned"


def submit(
    platform_url: str,
    token_path: Path,
    bundle_path: Path,
    *,
    verify_tls: bool = True,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError("ingestion token file is empty")
    if not bundle_path.is_file():
        raise RuntimeError(f"report bundle does not exist: {bundle_path}")

    endpoint = f"{platform_url.rstrip('/')}/api/v1/ingest/bundles"
    with (
        httpx.Client(verify=verify_tls, timeout=120.0, transport=transport) as client,
        bundle_path.open("rb") as bundle,
    ):
        response = client.post(
            endpoint,
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (bundle_path.name, bundle, "application/zip")},
        )
    if response.status_code != 202:
        raise RuntimeError(
            f"console rejected signed report bundle (HTTP {response.status_code}): "
            f"{response_detail(response)}"
        )
    try:
        payload = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("console accepted the bundle but returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("console accepted the bundle but returned an invalid response")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform_url")
    parser.add_argument("token_file", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--no-verify-tls", action="store_true")
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                submit(
                    args.platform_url,
                    args.token_file,
                    args.bundle,
                    verify_tls=not args.no_verify_tls,
                ),
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, RuntimeError, httpx.HTTPError) as exc:
        print(f"LSA upload failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
