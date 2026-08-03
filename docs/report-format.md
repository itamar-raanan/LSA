# Report format v1

Every scanner emits the same normalized JSON document. The formal schema is in `packages/contracts/report-v1.schema.json`.

Required sections are `scanner`, `host`, `scan`, `summary`, and `findings`. Finding control IDs must be stable across scans; LSA uses them to determine new, persistent, and resolved state.

The host section includes the OS distribution, version, kernel, architecture, addresses, and optional `system_info` inventory. Current scanners report CPU model and core count, total memory, uptime, virtualization type and role, hardware vendor and product, and timezone. Older version 1.0 reports without `system_info` remain valid.

The optional top-level `applications` array contains the read-only software inventory collected by scanner 0.6.0 and newer. Package entries come from `dpkg` or `rpm` and include name, version, architecture, source, and publisher when available. Service entries come from systemd and include unit name, description, active state, and boot-enabled state. The scanner does not collect process arguments, environment variables, open files, or application configuration. Older version 1.0 reports without `applications` remain valid and do not clear previously reported inventory.

An offline bundle contains:

```text
manifest.json
report.json
report.html
report.csv
applications.csv
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

Accepted ZIP bytes are preserved unchanged in the evidence vault. The report record stores the tenant-isolated object key, exact object version, byte length, SHA-256 digest, storage time, and retention deadline. Downloads are served only after the stored object is re-hashed and matches the ingestion digest.
