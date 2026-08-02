# Architecture

Linux Security Auditor is an ingestion-only platform. Customer-controlled Linux hosts or Ansible controllers collect evidence, create a portable report, and optionally submit it over HTTPS. The platform never opens connections to audited servers.

## Trust boundaries

1. The scanner is trusted to collect local evidence but not to read platform data.
2. Ingestion tokens can submit reports only. A per-host token is restricted to its bound host; a controller token is tenant-scoped.
3. The API validates identity, structure, size, duplicates, and safe archive paths before persistence.
4. Original artifacts are conceptually immutable. Normalized findings are projections used by the console.
5. Human sessions and ingestion credentials use separate authentication paths.

## Report processing

`receive → authenticate → validate → resolve host → compare → persist → audit → aggregate`

The canonical contract lives in `packages/contracts/report-v1.schema.json`. A report ID is immutable and globally unique. Host UUIDs are platform-generated; a hash of `/etc/machine-id` provides a secondary binding signal without exposing the raw machine identifier.

## Supported systems

- Debian 12 and 13
- Ubuntu 22.04 and 24.04
- RHEL family 8 and 9

The v0.1 scanner implementation focuses on Debian 13. The shared contract and plugin boundaries already admit the other supported families.

## Security invariants

- No SSH credentials or remote execution paths exist in the platform.
- Ingestion token hashes—not raw tokens—are stored.
- Report bundles must not contain API tokens.
- Duplicate report IDs are rejected.
- ZIP paths are checked before reading content.
- Every accepted report creates an audit event.
- Production deployments must replace all development secrets and terminate TLS before the API.

