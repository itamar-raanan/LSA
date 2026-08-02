# Evidence vault

Every accepted ZIP bundle is preserved byte-for-byte in tenant-isolated object storage. PostgreSQL remains the source of truth for report metadata and records the exact S3 object key and version, original filename, content type, byte length, SHA-256 digest, storage timestamp, retention deadline, and deletion timestamp.

## Storage backends

Docker deployments use the S3 backend with private MinIO. The API creates the bucket with Object Lock enabled. Objects use a unique key shaped like:

```text
tenants/{tenant_id}/reports/{report_id}/{random_object_id}.zip
```

AWS S3 deployments default to SSE-S3 (`AES256`). The bundled MinIO deployment sets `LSA_S3_SERVER_SIDE_ENCRYPTION=none` because current MinIO releases require KMS configuration for object-level SSE. Protect the evidence volume at the host or storage layer, or configure MinIO KMS before changing this setting to `AES256`.

Development and tests may use the filesystem backend. Files are mode 0600 and path traversal outside the configured artifact root is rejected.

## Integrity and isolation

Bundle validation happens before vault storage. On every download, LSA reads the exact stored object version, computes SHA-256 again, compares its byte length and ingestion digest, and refuses delivery on any mismatch. Successful downloads and integrity failures create audit events.

Users can access evidence only through a report that belongs to their tenant. S3 credentials and object keys are never exposed to the browser; downloads pass through the authenticated API.

## Retention

`LSA_ARTIFACT_RETENTION_DAYS` sets the deadline when evidence is ingested. The Docker default is 365 days. A positive retention period is also applied as S3 Object Lock in `COMPLIANCE` mode, preventing mutation or deletion of the stored version before its deadline.

Set the value to `0` only when an external storage policy owns retention. LSA then records no application deadline and does not apply an object-retention timestamp.

Administrators may delete one artifact after its deadline:

```text
DELETE /api/v1/reports/{report_id}/artifact
```

They may purge all expired artifacts for their tenant:

```text
POST /api/v1/artifacts/purge-expired
```

Deletion preserves the report, findings, checksum, object identity, and audit history. Only the original ZIP becomes unavailable.

## Downloads

The console exposes an **Evidence** action in report history. The API returns the original filename and an `X-LSA-Artifact-SHA256` response header after integrity verification:

```text
GET /api/v1/reports/{report_id}/artifact
```

A missing object or integrity mismatch returns a conflict response instead of potentially corrupted evidence.
