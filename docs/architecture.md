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

## Container topology

The supported platform deployment uses Docker Compose. A single Nginx web gateway serves the compiled console and proxies `/api`, `/docs`, and health traffic to the private API container. The API, PostgreSQL, and MinIO communicate only on an internal Docker network; neither data service has a published host port. The API applies Alembic migrations before starting and Compose health gates each dependency.

Only the TLS web gateway publishes a host port, bound to `127.0.0.1:8443` by default. No plaintext HTTP listener is published. Platform state lives in named PostgreSQL and evidence-object volumes; certificate keys are encrypted in PostgreSQL and materialized into a restricted gateway volume.

## Identity and access

LSA keeps one local bootstrap administrator as a break-glass account. Regular console users can be created just in time after successful OpenID Connect or RADIUS authentication, or pre-provisioned against an immutable provider subject before their first sign-in. Supported OIDC presets are Microsoft Entra ID, Okta, Google Workspace, and ADFS; generic standards-based OpenID Connect is also available.

OIDC uses authorization code flow with PKCE, state, and nonce. The callback validates token signature, issuer, audience, expiry, and nonce before binding a user to the provider subject. Group claims map to `admin`, `analyst`, or `auditor`, defaulting to `auditor`. RADIUS maps a configured Access-Accept reply attribute to the same roles and belongs on a trusted internal network or protected tunnel.

Browser tokens carry a database-backed session ID. Disabling a user or logging out revokes active sessions immediately. Provider secrets and TLS private keys are encrypted with `LSA_SETTINGS_ENCRYPTION_KEY`; settings APIs and audit events never return their values.

Deleting a host is a logical deletion: it removes the asset from active fleet, dashboard, and finding views and revokes host-scoped ingestion and signing credentials. Historical reports and retained evidence remain preserved.

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
- Production deployments must replace all development secrets and install a trusted TLS certificate before exposure.
