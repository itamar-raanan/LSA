# Architecture

Linux Security Auditor is an ingestion-only platform with two collection approaches. Ansible controllers can create portable offline reports, while the unified Linux agent can periodically collect and submit evidence. Both use the same normalized control engine and report contract. The platform never opens connections to audited servers.

## Collection approaches

### Offline report

An operator runs the Ansible scanner from a customer-controlled controller. The result can remain offline as a signed ZIP or be submitted through the ingestion API. This mode is suitable for isolated hosts, approval-driven assessments, and environments that prohibit resident agents.

### Managed agent

The unified agent runs on the audited host and makes outbound HTTPS connections to the dedicated agent gateway on TCP 8444. Enrollment consumes a one-time, expiring group token. The agent generates an Ed25519 private key locally; the platform stores only its public key and returns host-scoped ingestion credentials. The agent then signs policy and heartbeat requests, executes the locally installed scanner, signs its evidence bundle, and uploads it through the existing ingestion boundary.

Each agent belongs to exactly one group. Each group points to one policy, and every policy update creates an immutable version. A policy has a default mode and optional per-control modes: `disabled`, `audit`, `manual`, or `remediate`. In the current foundation, `manual` and `remediate` are staged intent only: the API returns `enforcement_enabled: false`, the agent requires that lock, and every enabled control remains read-only.

## Trust boundaries

1. The scanner is trusted to collect local evidence but not to read platform data.
2. Ingestion tokens can submit reports only. A per-host token is restricted to its bound host; a controller token is tenant-scoped. Administrators can set expirations and revoke credentials immediately.
3. Registered Ed25519 public keys establish scanner provenance. Keys may be tenant-wide or host-scoped, expiring, and immediately revocable.
4. The API validates identity, structure, size, checksums, signatures, duplicates, and safe archive paths before persistence.
5. Original artifacts are conceptually immutable. Normalized findings are projections used by the console.
6. Human sessions and ingestion credentials use separate authentication paths.
7. Agent policy and heartbeat calls require a timestamped Ed25519 signature from the enrolled host identity.
8. Policy documents contain identifiers, modes, and bounded scheduling settings—not commands or executable content.

## Report processing

`receive → authenticate → validate archive → resolve signing key → verify signature and host scope → resolve host → compare → persist provenance → audit → aggregate`

The canonical contract lives in `packages/contracts/report-v1.schema.json`. A report ID is immutable and globally unique. Host UUIDs are platform-generated; a hash of `/etc/machine-id` provides a secondary binding signal without exposing the raw machine identifier.

## Data workspace API

The Hosts, Findings, and Applications collection endpoints support optional database-side workspace parameters: `page`, `page_size`, `search`, `sort`, `direction`, and endpoint-specific filters. Paged requests keep the established JSON body shape and expose `X-Total-Count`, `X-Page`, and `X-Page-Size`; callers that omit pagination continue to receive the original complete or bounded collection response.

Lightweight `/hosts/facets` and `/findings/facets` endpoints provide fleet risk totals and finding category aggregates independently of the current page. This keeps category rails, risk tabs, and headline metrics accurate without downloading every record. Management-to-API CORS explicitly exposes the pagination headers, and composite database indexes cover the tenant, active-state, category, severity, score, and observation fields used by analyst queues.

## Remediation planning

Remediation begins as a management-plane review record, not an agent instruction. An administrator can create a plan only from an open finding in a host's latest report. The plan snapshots what was observed, what the control expects, the human-readable guidance, affected file paths, and restart or reboot impact. Plans move through `pending_approval`, `approved`, `rejected`, or `canceled`; every transition records the actor, timestamp, reason where applicable, version, and audit event.

Approval is intentionally non-executable. Every response states `execution_enabled: false` and `execution_status: not_supported`. The API refuses to approve a plan after a newer host report makes its source snapshot stale. No remediation plan is translated into an agent task, and the signed agent protocol remains limited to the allow-listed `audit` task. See [remediation planning](remediation-planning.md) for the state model and staged delivery boundary.

The management API also loads a versioned declarative remediation action catalog at startup. Catalog entries use a closed vocabulary of typed configuration, reload, validation, backup, and rollback operations; executable command or script payload fields are rejected. A supported plan snapshots its matching action ID, version, normalized document, and SHA-256 digest. Snapshot integrity is checked again at approval, but no action is sent through the agent gateway or converted into work.

Approved catalog-backed plans can be compiled into a canonical change-set envelope that snapshots the exact action digests, target agent and policy identities, canary rollout, maintenance window, and bounded batch settings. Authorization recalculates readiness from live evidence and requires a different administrator from both the requester and each plan approver. A tenant Ed25519 change-signing key then signs the envelope; its private material is encrypted with the settings cipher. Signed change sets remain management-plane governance records: they do not create `AgentTask` rows, are not exposed by the agent gateway, and cannot be consumed by the audit-only agent.

Stage 4A adds a management-only, target-specific validation preview around an authorized change set. The pinned platform-control key endorses the tenant change-signing public key, allowing agent code to validate the complete trust chain without accepting an arbitrary signer. The contract is explicitly non-dispatchable and validation-only; no remediation gateway route or executor exists. The threat model and prerequisites for later dry-run and write-capable stages are documented in [remediation execution threat model](remediation-execution-threat-model.md).

Capability freshness is tracked separately from general agent activity and advances only when a signed enrollment or heartbeat supplies the capability list. Policy reads and task polling may refresh online status but cannot make an old capability attestation current. Change-set creation locks the selected plan rows through the active-ownership check and insert so concurrent requests cannot place one plan in multiple active envelopes.

## Container topology

The supported platform deployment uses Docker Compose. A single Nginx web gateway serves the compiled console and proxies `/api`, `/docs`, and health traffic to the private API container. The API, PostgreSQL, and MinIO communicate only on an internal Docker network; neither data service has a published host port. The API applies Alembic migrations before starting and Compose health gates each dependency.

Only the TLS gateway publishes host ports: management is bound to `127.0.0.1:8443` and the restricted agent data plane to `127.0.0.1:8444` by default. No plaintext HTTP listener is published. The agent listener exposes only managed-agent control routes and report ingestion; it does not serve the console, management APIs, or documentation. Platform state lives in named PostgreSQL and evidence-object volumes; certificate keys are encrypted in PostgreSQL and materialized into a restricted gateway volume.

## Identity and access

LSA keeps one local bootstrap administrator as a break-glass account. Regular console users can be created just in time after successful OpenID Connect or RADIUS authentication, or pre-provisioned against an immutable provider subject before their first sign-in. Supported OIDC presets are Microsoft Entra ID, Okta, Google Workspace, and ADFS; generic standards-based OpenID Connect is also available.

OIDC uses authorization code flow with PKCE, state, and nonce. The callback validates token signature, issuer, audience, expiry, and nonce before binding a user to the provider subject. Group claims map to `admin`, `analyst`, or `auditor`, defaulting to `auditor`. RADIUS maps a configured Access-Accept reply attribute to the same roles and belongs on a trusted internal network or protected tunnel.

Browser tokens carry a database-backed session ID. Disabling a user or logging out revokes active sessions immediately. Provider secrets and TLS private keys are encrypted with `LSA_SETTINGS_ENCRYPTION_KEY`; settings APIs and audit events never return their values.

Deleting a host is a logical deletion: it removes the asset from active fleet, dashboard, and finding views and revokes host-scoped ingestion and signing credentials. Historical reports and retained evidence remain preserved.

## Supported systems

- Debian 12 and 13
- Ubuntu 22.04 and 24.04
- RHEL family 8 and 9

The v0.6 scanner runs on Debian 12/13, Ubuntu 22.04/24.04, and RHEL, Rocky Linux, or AlmaLinux 8/9. Debian 13 combines 334 benchmark controls with 56 non-overlapping portable checks for 390 findings. The benchmark contains 322 automated read-only checks and 12 explicit manual reviews. The full portable catalog contains 98 controls; 42 controls declare an exact Debian benchmark overlap and are suppressed while that benchmark is active. Other supported systems execute all 98 portable controls. Agent-only self-protection controls return not applicable during offline scans or on hosts where the agent is not installed.

## Security invariants

- No SSH credentials or remote execution paths exist in the platform.
- Agents initiate every connection; the server has no host connection mechanism.
- One-time enrollment tokens expire within 30 days and cannot be reused.
- Agent private keys remain local with mode `0600`; revoking an agent also revokes its exact ingestion token and signing key.
- Agent packages contain a deterministic SHA-256 runtime manifest. The installer validates it before copying files, and the agent validates it before every policy and scan cycle.
- An enrolled agent persists the highest accepted policy version and rejects lower versions; restoring server policy creates a new higher version instead of rolling agents back.
- Policy versions are immutable, and one effective group eliminates policy precedence ambiguity.
- Remediation enforcement is hard-disabled in this release even when remediation intent is staged in a policy.
- Remediation plan approval records a human decision only; it never creates an agent task or transmits executable content.
- Signed change sets require current evidence, exact action integrity, current policy identity, fresh agent capability attestation, canary and rate boundaries, rollback metadata, a bounded maintenance window, and four-eyes authorization.
- Change-set Ed25519 signatures cover canonical immutable payloads; signing and cancellation never dispatch work.
- Scanner audit tasks may read privileged host state but cannot run package, service, account, permission, mount, firewall, kernel, or filesystem mutation commands; automated tests enforce this boundary.
- Portable controls carry a unique semantic key, canonical finding category, and explicit benchmark-overlap metadata. Runtime and unit assertions reject duplicate IDs, duplicate semantics, unknown overlap references, and unmapped categories.
- Ingestion token hashes—not raw tokens—are stored.
- Expired or revoked ingestion tokens cannot submit evidence.
- Report bundles must not contain API tokens.
- Duplicate report IDs are rejected.
- ZIP paths, expanded size, manifest declarations, and every listed checksum are validated before ingestion.
- Signed bundles are accepted only when the referenced key is trusted, active, unexpired, correctly scoped, and cryptographically verifies the exact manifest bytes.
- Private signing keys remain on customer-controlled scanner controllers; LSA stores only public keys and fingerprints.
- Every accepted report creates an audit event.
- Production deployments must replace all development secrets and install a trusted TLS certificate before exposure.
