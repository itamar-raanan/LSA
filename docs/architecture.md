# Architecture

Linux Security Auditor is an ingestion-only platform. Customer-controlled Linux hosts or Ansible controllers collect evidence, create a portable report, and optionally submit it over HTTPS. The platform never opens connections to audited servers.

## Trust boundaries

1. The scanner is trusted to collect local evidence but not to read platform data.
2. Ingestion tokens can submit reports only. A per-host token is restricted to its bound host; a controller token is tenant-scoped. Administrators can set expirations and revoke credentials immediately.
3. Registered Ed25519 public keys establish scanner provenance. Keys may be tenant-wide or host-scoped, expiring, and immediately revocable.
4. The API validates identity, structure, size, checksums, signatures, duplicates, and safe archive paths before persistence.
5. Original artifacts are conceptually immutable. Normalized findings are projections used by the console.
6. Human sessions and ingestion credentials use separate authentication paths.

## Report processing

`receive → authenticate → validate archive → resolve signing key → verify signature and host scope → resolve host → compare → persist provenance → audit → aggregate`

The canonical contract lives in `packages/contracts/report-v1.schema.json`. A report ID is immutable and globally unique. Host UUIDs are platform-generated; a hash of `/etc/machine-id` provides a secondary binding signal without exposing the raw machine identifier.

## Supported systems

- Debian 12 and 13
- Ubuntu 22.04 and 24.04
- RHEL family 8 and 9

The v0.3 scanner implementation focuses on Debian 13 with 32 executable controls and explicit production-server, minimal-server, router, and container profiles. The shared contract and plugin boundaries already admit the other supported families.

## Security invariants

- No SSH credentials or remote execution paths exist in the platform.
- Ingestion token hashes—not raw tokens—are stored.
- Expired or revoked ingestion tokens cannot submit evidence.
- Report bundles must not contain API tokens.
- Duplicate report IDs are rejected.
- ZIP paths, expanded size, manifest declarations, and every listed checksum are validated before ingestion.
- Signed bundles are accepted only when the referenced key is trusted, active, unexpired, correctly scoped, and cryptographically verifies the exact manifest bytes.
- Private signing keys remain on customer-controlled scanner controllers; LSA stores only public keys and fingerprints.
- Every accepted report creates an audit event.
- Production deployments must replace all development secrets and terminate TLS before the API.
