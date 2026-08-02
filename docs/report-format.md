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
```

`signature.sig` is reserved for the signing milestone. The manifest records `signature: null` until signing is configured.

