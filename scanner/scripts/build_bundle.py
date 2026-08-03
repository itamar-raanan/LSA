#!/usr/bin/env python3
"""Build a deterministic, portable LSA report bundle with optional Ed25519 signing."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import io
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render_html(report: dict) -> bytes:
    host = report["host"]
    summary = report["summary"]
    rows = "".join(
        f"<tr><td>{html.escape(f['control_id'])}</td><td>{html.escape(f['title'])}</td>"
        f"<td>{html.escape(f['severity'])}</td><td>{html.escape(f['status'])}</td></tr>"
        for f in report["findings"]
    )
    application_rows = "".join(
        f"<tr><td>{html.escape(item['name'])}</td><td>{html.escape(item['kind'])}</td>"
        f"<td>{html.escape(item.get('version') or '')}</td><td>{html.escape(item['status'])}</td>"
        f"<td>{html.escape(item['source'])}</td></tr>"
        for item in report.get("applications", [])
    )
    document = f"""<!doctype html><html><head><meta charset=\"utf-8\"><title>LSA report — {html.escape(host['hostname'])}</title>
<style>body{{font:15px system-ui;max-width:1100px;margin:48px auto;padding:0 24px;color:#202622}}table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;border-bottom:1px solid #d9dedb;text-align:left}}code{{font-family:monospace}}</style></head>
<body><p>Linux Security Auditor</p><h1>{html.escape(host['hostname'])}</h1><p>{html.escape(host['operating_system'])} {html.escape(host['os_version'])}</p>
<h2>Summary</h2><p>Pass <strong>{summary['pass']}</strong> · Fail <strong>{summary['fail']}</strong> · Manual <strong>{summary['manual']}</strong></p>
<h2>Findings</h2><table><thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Application inventory</h2><table><thead><tr><th>Name</th><th>Type</th><th>Version</th><th>Status</th><th>Source</th></tr></thead><tbody>{application_rows}</tbody></table></body></html>"""
    return document.encode()


def render_csv(report: dict) -> bytes:
    output = io.StringIO()
    fieldnames = ["control_id", "module", "category", "title", "severity", "status", "expected", "actual"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows({key: finding.get(key, "") for key in fieldnames} for finding in report["findings"])
    return output.getvalue().encode()


def render_applications_csv(report: dict) -> bytes:
    output = io.StringIO()
    fieldnames = [
        "kind",
        "name",
        "version",
        "architecture",
        "source",
        "publisher",
        "description",
        "status",
        "enabled",
        "running",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(
        {key: application.get(key, "") for key in fieldnames}
        for application in report.get("applications", [])
    )
    return output.getvalue().encode()


def build(
    report_path: Path,
    output_dir: Path,
    signing_key_path: Path | None = None,
    signing_key_id: str | None = None,
) -> Path:
    if (signing_key_path is None) != (signing_key_id is None):
        raise ValueError("signing_key_path and signing_key_id must be provided together")
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    files = {
        "report.json": report_bytes,
        "report.html": render_html(report),
        "report.csv": render_csv(report),
        "applications.csv": render_applications_csv(report),
        "metadata/host.json": json.dumps(report["host"], indent=2).encode(),
        "metadata/scanner.json": json.dumps(report["scanner"], indent=2).encode(),
    }
    manifest = {
        "schema_version": "1.0",
        "report_id": report["report_id"],
        "generated_at": report["generated_at"],
        "files": {name: sha256(content) for name, content in files.items()},
        "signature": (
            {"algorithm": "ed25519", "key_id": signing_key_id}
            if signing_key_id is not None
            else None
        ),
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    files["manifest.json"] = manifest_bytes
    if signing_key_path is not None:
        private_key = serialization.load_pem_private_key(signing_key_path.read_bytes(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("signing key must be an Ed25519 private key")
        files["signature.sig"] = base64.b64encode(private_key.sign(manifest_bytes))
    files["checksums.sha256"] = "".join(f"{sha256(content)}  {name}\n" for name, content in sorted(files.items())).encode()
    safe_time = report["generated_at"].replace(":", "").replace("-", "")
    bundle_path = output_dir / f"lsa-report-{report['host']['hostname']}-{safe_time}.zip"
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
    return bundle_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_json", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--key-id")
    args = parser.parse_args()
    try:
        print(
            build(
                args.report_json,
                args.output_directory,
                args.signing_key,
                args.key_id,
            )
        )
    except ValueError as exc:
        parser.error(str(exc))
