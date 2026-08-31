#!/usr/bin/env python3
"""Exercise the externally visible Docker platform and signed ingestion flow."""

import argparse
import base64
import getpass
import hashlib
import io
import json
import ssl
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path


TLS_CONTEXT = ssl.create_default_context()


def request(url: str, method: str = "GET", data: bytes | None = None, headers=None):
    context = TLS_CONTEXT if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, headers=headers or {}, method=method),
            timeout=30,
            context=context,
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


def bundle_bytes(report_path: Path, signing_key=None, signing_key_id: str | None = None) -> bytes:
    report_payload = json.loads(report_path.read_text())
    report_payload["report_id"] = str(uuid.uuid4())
    report_payload["generated_at"] = datetime.now(UTC).isoformat()
    report = json.dumps(report_payload, indent=2, sort_keys=True).encode()
    manifest = json.dumps(
        {
            "schema_version": "1.0",
            "report_id": report_payload["report_id"],
            "files": {"report.json": hashlib.sha256(report).hexdigest()},
            "signature": (
                {"algorithm": "ed25519", "key_id": signing_key_id}
                if signing_key is not None and signing_key_id is not None
                else None
            ),
        },
        indent=2,
        sort_keys=True,
    ).encode()
    files = {"manifest.json": manifest, "report.json": report}
    if signing_key is not None:
        files["signature.sig"] = base64.b64encode(signing_key.sign(manifest))
    checksums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in sorted(files.items())
    ).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
        bundle.writestr("checksums.sha256", checksums)
    return output.getvalue()


def multipart_file(name: str, content: bytes) -> tuple[bytes, str]:
    boundary = f"lsa-smoke-{uuid.uuid4().hex}"
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
            "Content-Type: application/zip\r\n\r\n"
        ).encode()
        + content
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return body, boundary


def smoke(base_url: str, email: str, password: str) -> None:
    status, login = json_request(
        f"{base_url}/api/v1/auth/login",
        {"email": email, "password": password},
    )
    if status != 200:
        raise RuntimeError("Bootstrap login was not accepted")
    session = login["access_token"]
    status, _, package_body = request(
        f"{base_url}/api/v1/agent-packages",
        headers={"Authorization": f"Bearer {session}"},
    )
    packages = json.loads(package_body)
    formats = {package["package_format"] for package in packages}
    if status != 200 or formats != {"deb", "rpm", "tar.gz"}:
        raise RuntimeError(f"Expected native and universal agent packages, received {formats}")
    for package in packages:
        status, package_headers, package_data = request(
            f"{base_url}/api/v1/agent-packages/{package['id']}/download",
            headers={"Authorization": f"Bearer {session}"},
        )
        if status != 200 or hashlib.sha256(package_data).hexdigest() != package["sha256"]:
            raise RuntimeError(f"Agent package {package['id']} failed checksum validation")
        if package_headers.get("X-LSA-Agent-SHA256") != package["sha256"]:
            raise RuntimeError(f"Agent package {package['id']} omitted its checksum header")
        if package_headers.get("X-LSA-Agent-Version") != package["version"]:
            raise RuntimeError(f"Agent package {package['id']} returned a stale version")
        if "no-store" not in package_headers.get("Cache-Control", ""):
            raise RuntimeError(f"Agent package {package['id']} permits stale download caching")
        if package["package_format"] == "deb" and not package_data.startswith(b"!<arch>\n"):
            raise RuntimeError("Debian agent package has an invalid archive header")
        if package["package_format"] == "rpm" and not package_data.startswith(b"\xed\xab\xee\xdb"):
            raise RuntimeError("RPM agent package has an invalid lead header")

    status, token = json_request(
        f"{base_url}/api/v1/ingestion-tokens",
        {"name": "Docker evidence smoke test"},
        session,
    )
    if status != 201:
        raise RuntimeError("Ingestion token could not be issued")

    signing_key = None
    signing_key_id = None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signing_key = Ed25519PrivateKey.generate()
        public_key = signing_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        status, registered = json_request(
            f"{base_url}/api/v1/signing-keys",
            {
                "name": f"Production acceptance {uuid.uuid4().hex[:8]}",
                "public_key": base64.b64encode(public_key).decode(),
                "host_id": None,
            },
            session,
        )
        if status != 201:
            raise RuntimeError("Acceptance signing key could not be registered")
        signing_key_id = registered["id"]
    except ImportError:
        print("WARNING: cryptography is unavailable; attempting an unsigned lab bundle")

    artifact = bundle_bytes(
        Path("tests/fixtures/report.json"),
        signing_key=signing_key,
        signing_key_id=signing_key_id,
    )
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
    print("Docker agent-package and evidence-vault smoke tests passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exercise an externally visible LSA deployment")
    parser.add_argument("base_url")
    parser.add_argument("email")
    parser.add_argument("password", nargs="?", help="omit to receive a hidden interactive prompt")
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument("--ca-file", help="PEM CA bundle used to verify management TLS")
    trust.add_argument(
        "--insecure",
        action="store_true",
        help="disable management TLS verification for an isolated lab only",
    )
    arguments = parser.parse_args()
    if arguments.insecure:
        TLS_CONTEXT = ssl._create_unverified_context()
    elif arguments.ca_file:
        TLS_CONTEXT = ssl.create_default_context(cafile=arguments.ca_file)
    password = arguments.password or getpass.getpass("LSA administrator password: ")
    smoke(arguments.base_url.rstrip("/"), arguments.email, password)
