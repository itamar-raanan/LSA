# Linux Security Auditor

Linux Security Auditor (LSA) is an ingestion-first Linux security and compliance platform. Customer-controlled offline scans or outbound-only agents produce normalized evidence; LSA validates it, maintains a persistent profile for each host, and presents fleet-wide risk, compliance, findings, and history from one console.

LSA does **not** SSH to servers, store privileged server credentials, or execute scans remotely. Managed agents initiate every connection and execute only locally installed, versioned controls.

## Current v0.1 foundation

- FastAPI ingestion and fleet API
- PostgreSQL-compatible tenant, host, report, finding, token, and audit models
- Online JSON and offline ZIP report ingestion
- Admin-managed host enrollment, revocable host-scoped tokens, and machine-identity binding
- Outbound-only unified Linux agent with one-time enrollment and local Ed25519 identity
- Single-group agent assignment, immutable policy versions, heartbeat, and per-control audit scope
- Monitor and staged Remediation policy templates with server and agent enforcement locked to audit-only
- Complete manifest, checksum, and optional Ed25519 signature verification for offline bundles
- New, persistent, and resolved finding comparison
- React fleet dashboard, enrollment, token lifecycle management, host profiles, report history, comparisons, findings, and upload
- Deduplicated 358-control Debian 13 audit surface: 334 benchmark controls plus 24 non-overlapping portable Linux checks, with no host remediation
- A 62-control portable Linux audit for Debian 12, Ubuntu 22.04/24.04, and RHEL-family 8/9
- Versioned report JSON Schema
- Ansible report generation and submission role
- Offline HTML, CSV, JSON, checksum, manifest, and ZIP generation
- Admin-managed signing-key registration, host scoping, expiry, revocation, and provenance history
- Immutable original-evidence vault with object lock, retention enforcement, verified downloads, and deletion audit events
- Production-style Docker Compose stack with PostgreSQL, a MinIO evidence vault, automatic migrations, health checks, and a same-origin web gateway
- Backend and frontend tests plus GitHub Actions CI

## Quick start

Requirements: Docker Engine with the Compose plugin.

```bash
cp deploy/.env.example deploy/.env
# Replace every placeholder secret in deploy/.env.
make up
```

Open `https://localhost:8443` and sign in with the bootstrap email and password from `deploy/.env`. The first boot uses a self-signed localhost certificate. The API documentation is available at `https://localhost:8443/docs`.

The database and immutable evidence objects are stored in named Docker volumes. Migrations run automatically before the API starts, and Compose waits for PostgreSQL, MinIO, the API, and the web gateway to become healthy. Use `make logs`, `make ps`, and `make down` for routine operation.

For direct local development and testing, install Python 3.12+ and Node.js 22+:

```bash
make install
cp .env.example .env
make test
```

The seeded development ingestion token is `lsa_ingest_demo_secret`. It is intentionally local-only and must never be used in production.

See [docs/docker-deployment.md](docs/docker-deployment.md) for production exposure, TLS, backup, restore, upgrades, and troubleshooting.

See [docs/evidence-vault.md](docs/evidence-vault.md) for object storage, integrity verification, retention, and deletion behavior.

## Enroll a host

Sign in as an administrator, open **Linux hosts**, and choose **Enroll host**. LSA creates a persistent host UUID and a scoped ingestion token. The raw token is shown once; store it in a mode-0600 file on the Ansible controller and assign the displayed host UUID to `lsa_host_id` in inventory.

The first accepted report binds that platform identity to the host's hashed machine ID. Later reports with a different machine ID are rejected. Tokens can also be issued, listed, and revoked through the `/api/v1/ingestion-tokens` endpoints.

Administrators can manage scanner credentials from **Ingestion tokens**. Prefer host-scoped tokens with an expiry. Revocation is immediate, while accepted reports and host history remain immutable.

For cryptographic report provenance, generate an Ed25519 key on the controller with `scanner/scripts/generate_signing_key.py`, register only its public key under **Signing keys**, and add the returned key ID plus private-key path to the scanner variables. See [docs/report-format.md](docs/report-format.md) for the complete signed-bundle workflow.

## Enroll a managed agent

Open **Agents** in the primary console navigation, choose **Install agent**, and download the versioned universal Linux package. The console displays the package SHA-256 and an installation command for the current platform URL. Assign a policy to a group and create a short-lived one-time enrollment token, then transfer the package to the host and run:

```bash
tar -xzf lsa-agent-0.1.0-linux-universal.tar.gz
cd lsa-agent-0.1.0
sudo ./install.sh --platform-url 'https://lsa.example.com:8443' --token 'lsa_enroll_...'
```

The installer places the runtime and audit controls under `/opt/lsa-agent`, creates an isolated Python environment, writes the root-only configuration, enrolls the host, and enables the systemd service. The agent generates its signing key on the host, polls over outbound HTTPS on port 8443, and runs the same scanner roles used by offline mode. See [agent/README.md](agent/README.md) for installation and trust details.

## Submit a JSON report

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${LSA_INGEST_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @report.json \
  https://localhost:8443/api/v1/ingest/reports
```

## Run the scanner

Copy `scanner/inventory.example.ini`, assign each host its platform UUID, then run:

```bash
cd scanner
ansible-playbook -i inventory.ini playbooks/scan.yml \
  -e lsa_delivery_mode=upload_and_keep
```

Delivery modes are `offline`, `upload`, and `upload_and_keep`. The last mode is the production default because it preserves a local artifact even after successful submission.

The scanner performs read-only checks on Debian 12/13, Ubuntu 22.04/24.04, and RHEL, Rocky Linux, or AlmaLinux 8/9. Debian 13 combines the complete 334-control benchmark with 24 portable controls that are not already covered by the benchmark. The other supported systems run the 62-control portable catalog. On Debian 13, 38 semantic overlaps are explicitly suppressed so the same posture is never checked or reported twice. Select an LSA deployment profile (`production_server`, `minimal_server`, `router`, or `container`) or a direct benchmark profile (`level1_server`, `level2_server`, `level1_workstation`, or `level2_workstation`) with `lsa_profile`.

GitHub Actions also executes the complete scanner inside an official Debian 13 container, validates the normalized report, verifies the portable bundle, and ingests it through the API.

## Repository map

- `apps/api` — API, data model, ingestion, migrations, tests
- `apps/web` — React fleet console
- `scanner` — Ansible scanner, report builder, submission flow
- `agent` — outbound Linux agent runtime and systemd service
- `packages/contracts` — versioned machine-readable contracts
- `deploy` — local deployment composition
- `docs` — architecture and report-format documentation

See [docs/architecture.md](docs/architecture.md) for trust boundaries and design decisions.
