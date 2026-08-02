#!/usr/bin/env python3
"""Generate an Ed25519 private key and print its LSA registration metadata."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(output_path: Path) -> dict[str, str]:
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite existing key: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(private_bytes)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "private_key_path": str(output_path),
        "public_key": base64.b64encode(public_bytes).decode(),
        "fingerprint": hashlib.sha256(public_bytes).hexdigest(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args.output), indent=2))
    except FileExistsError as exc:
        parser.error(str(exc))
