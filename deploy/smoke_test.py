#!/usr/bin/env python3
"""Exercise the externally visible Docker platform using only the standard library."""

import hashlib
import io
import json
import sys
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path


def request(url: str, method: str = "GET", data: bytes | None = None, headers=None):
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, headers=headers or {}, method=method),
            timeout=30,
        ) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.code} {exc.read().decode()}") from exc


def json_request(url: str, payload: dict, token: str | None = None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, _, body = request(url, "POST", json.dumps(payload).encode(), headers)
    return status, json.loads(body)


def bundle_bytes(report_path: Path) -> bytes:
    report = report_path.read_bytes()
    manifest = json.dumps(
        {
            "schema_version": "1.0",
            "report_id": json.loads(report)["report_id"],
            "files": {"report.json": hashlib.sha256(report).hexdigest()},
            "signature": None,
        },
        indent=2,
        sort_keys=True,
    ).encode()
    checksums = (
        f"{hashlib.sha256(manifest).hexdigest()}  manifest.json\n"
        f"{hashlib.sha256(report).hexdigest()}  report.json\n"
    ).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("report.json", report)
        bundle.writestr("manifest.json", manifest)
        bundle.writestr("checksums.sha256", checksums)
    return output.getvalue()


def multipart_file(name: str, content: bytes) -> tuple[bytes, str]:
    boundary = f"lsa-smoke-{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, boundary


def smoke(base_url: str, email: str, password: str) -> None:
    status, login = json_request(
        f"{base_url}/api/v1/auth/login",
        {"email": email, "password": password},
    )
    if status != 200:
        raise RuntimeError("Bootstrap login was not accepted")
    session = login["access_token"]
    status, token = json_request(
        f"{base_url}/api/v1/ingestion-tokens",
        {"name": "Docker evidence smoke test"},
        session,
    )
    if status != 201:
        raise RuntimeError("Ingestion token could not be issued")

    artifact = bundle_bytes(Path("tests/fixtures/report.json"))
    body, boundary = multipart_file("docker-smoke-report.zip", artifact)
    status, _, response_body = request(
        f"{base_url}/api/v1/ingest/bundles",
        "POST",
        body,
        {
            "Authorization": f"Bearer {token['token']}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    if status != 202:
        raise RuntimeError("Evidence bundle was not accepted")
    report_id = json.loads(response_body)["report_id"]

    status, headers, downloaded = request(
        f"{base_url}/api/v1/reports/{report_id}/artifact",
        headers={"Authorization": f"Bearer {session}"},
    )
    if status != 200 or downloaded != artifact:
        raise RuntimeError("Vault download did not match the original artifact")
    if headers.get("X-LSA-Artifact-SHA256") != hashlib.sha256(artifact).hexdigest():
        raise RuntimeError("Vault download checksum header is invalid")
    print("Docker evidence-vault smoke test passed")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: smoke_test.py BASE_URL ADMIN_EMAIL ADMIN_PASSWORD")
    smoke(sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3])
