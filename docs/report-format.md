# Report format v1

Every scanner emits the same normalized JSON document. The formal schema is in `packages/contracts/report-v1.schema.json`.

Required sections are `scanner`, `host`, `scan`, `summary`, and `findings`. Finding control IDs must be stable across scans; LSA uses them to determine new, persistent, and resolved state.

An offline bundle contains:

```text
manifest.json
report.json
report.html
report.csv
checksums.sha256
metadata/host.json
metadata/scanner.json
signature.sig          # present for signed bundles
```

For unsigned bundles, the manifest records `signature: null`. Signed bundles declare `{"algorithm": "ed25519", "key_id": "…"}` and `signature.sig` contains the base64 Ed25519 signature over the exact `manifest.json` bytes. `checksums.sha256` covers the manifest, signature, and every report artifact.

Generate a controller key locally; the command creates a mode-0600 private key and prints the public key and SHA-256 fingerprint:

```bash
python3 scanner/scripts/generate_signing_key.py /secure/path/lsa-signing-key.pem
```

Register only the printed public key in **Signing keys**, then configure the scanner with the returned platform ID:

```yaml
lsa_signing_key_file: /secure/path/lsa-signing-key.pem
lsa_signing_key_id: 7f2f43b5-…
```

When both values are present, the scanner uploads the signed ZIP bundle instead of the unsigned JSON projection. Keep the private key outside inventory and source control. Set `LSA_REQUIRE_SIGNED_BUNDLES=true` on the API to reject unsigned ZIP bundles.
