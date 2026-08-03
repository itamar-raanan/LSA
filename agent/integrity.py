#!/usr/bin/env python3
"""Build and verify the immutable portion of an LSA agent installation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path


MANIFEST_VERSION = 1
EXCLUDED_PARTS = {"__pycache__", "tests"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def managed_files(root: Path, directories: Iterable[str] = ("agent", "scanner")) -> list[Path]:
    files: list[Path] = []
    for directory in directories:
        base = root / directory
        if not base.is_dir():
            raise RuntimeError(f"managed agent directory is missing: {base}")
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root)
            if not path.is_file() or path.is_symlink():
                continue
            if EXCLUDED_PARTS.intersection(relative.parts) or path.suffix in EXCLUDED_SUFFIXES:
                continue
            files.append(path)
    requirements = root / "requirements.txt"
    if requirements.is_file():
        files.append(requirements)
    return sorted(set(files))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict[str, object]:
    root = root.resolve()
    files = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in managed_files(root)
    }
    return {
        "manifest_version": MANIFEST_VERSION,
        "algorithm": "sha256",
        "files": files,
    }


def write_manifest(root: Path, output: Path) -> None:
    payload = build_manifest(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def verify_manifest(root: Path, manifest_path: Path) -> str:
    root = root.resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"agent integrity manifest cannot be read: {exc}") from exc
    if manifest.get("manifest_version") != MANIFEST_VERSION or manifest.get("algorithm") != "sha256":
        raise RuntimeError("agent integrity manifest has an unsupported format")
    entries = manifest.get("files")
    if not isinstance(entries, dict) or not entries:
        raise RuntimeError("agent integrity manifest contains no files")
    failures: list[str] = []
    for relative, expected in sorted(entries.items()):
        if not isinstance(relative, str) or not isinstance(expected, str):
            failures.append("invalid manifest entry")
            continue
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            failures.append(f"path escapes installation root: {relative}")
            continue
        if not candidate.is_file() or candidate.is_symlink():
            failures.append(f"missing or unsafe file: {relative}")
        elif sha256_file(candidate) != expected:
            failures.append(f"digest mismatch: {relative}")
    if failures:
        detail = "; ".join(failures[:20])
        raise RuntimeError(f"agent runtime integrity verification failed: {detail}")
    return hashlib.sha256(manifest_path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--root", type=Path, required=True)
        child.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "build":
        write_manifest(arguments.root, arguments.manifest)
        print(arguments.manifest)
    else:
        print(f"sha256:{verify_manifest(arguments.root, arguments.manifest)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
