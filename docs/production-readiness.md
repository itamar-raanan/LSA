# Internal production readiness

LSA's supported initial production profile is a single-node, audit-only deployment
on a managed internal network. Management clients use trusted TLS on TCP 8443.
Agents use the isolated TCP 8444 gateway with HTTPS encryption and pinned Ed25519
application identity; agent certificate and hostname verification intentionally
remain disabled for this internal profile.

## Enforced preflight

`make up` runs the secret-safe production check before Compose. The check reports
only setting names and findings; it never prints configured values.

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
# Replace every credential and deployment identity, then start the restricted stage:
make staging-check
make stage-up
```

The gate requires:

- unique PostgreSQL, MinIO, session, settings-encryption, and bootstrap credentials;
- an operational administrator address and non-local management/agent DNS names;
- demo seeding disabled and signed evidence required;
- explicit confirmation that TCP 8444 permits managed internal networks only;
- a trusted management certificate installed on TCP 8443;
- encrypted storage or KMS protection for the PostgreSQL and evidence volumes; and
- a completed restore drill using matching database and evidence snapshots.

Acknowledgement values describe completed operational work. Setting one to `true`
without performing its review does not make the deployment safe.

The staging check defers only the trusted-certificate installation and restore-drill
acknowledgements so those tasks can be completed against a restricted first boot.
Keep both listeners on administrative or managed internal networks during this
stage. After installing management TLS and completing the restore drill, set both
acknowledgements to `true`, run `make production-check`, and use `make up` for the
approved production lifecycle.

## Internal network boundary

Allow TCP 8444 only from managed server networks or the organization's VPN. Deny
internet, guest, user, and untrusted VLAN access. TCP 8443 should be limited to
administrative networks. PostgreSQL, MinIO, and the API container must remain
unpublished.

The platform-control signature protects agent commands from substitution, but the
internal-network restriction remains part of the confidentiality boundary while
agent certificate verification is disabled.

## Backup and restore acceptance

1. Record a common backup window.
2. Create a PostgreSQL custom-format dump as documented in
   [Docker deployment](docker-deployment.md#backups).
3. Snapshot or replicate the `lsa-evidence` volume from the same window.
4. Restore both into an isolated empty deployment.
5. Confirm `/ready`, administrator login, host/report counts, and download/hash
   verification for retained evidence.
6. Record the drill date, recovery time, responsible operator, and storage location.
7. Only then set `LSA_BACKUP_RESTORE_DRILL_ACKNOWLEDGED=true`.

## Acceptance test

Run the smoke test using normal management certificate verification. Omit the
password to receive a hidden prompt:

```bash
.venv/bin/python deploy/smoke_test.py \
  https://lsa.internal.example:8443 \
  security-admin@internal.example \
  --ca-file /path/to/management-ca.pem
```

`--insecure` exists only for an isolated localhost lab and must not be used for the
production acceptance record. With signed evidence enforced, complete acceptance
also includes enrolling agent 0.11.2, receiving its signed report, running a second
cycle after reboot, and confirming that the Applications and Findings workspaces
reflect the new report.

## Release decision

The initial release is approved only for posture monitoring, evidence retention,
inventory, vulnerability correlation, policy management, and read-only remediation
readiness. Host remediation execution, restore, service control, and configuration
mutation remain unavailable and must not be represented as production features.
