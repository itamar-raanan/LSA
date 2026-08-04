# Linux Security Auditor

## 1. Platform overview

Linux Security Auditor (LSA) is an ingestion-first Linux security and compliance platform. It turns read-only host observations into a persistent, fleet-wide view of security posture, compliance, findings, evidence, and change over time.

LSA supports two collection models:

- **Offline reports** are produced by a customer-controlled Ansible scanner. They can stay inside an isolated environment or be transferred to LSA as signed report bundles.
- **Managed agents** run on Linux hosts, collect the same supported evidence, and communicate with LSA over outbound HTTPS.

Both models feed the same validation, normalization, evidence, and finding pipeline. This gives administrators one console for hosts, groups, policies, control coverage, findings, report history, credentials, and cryptographic provenance regardless of how the data was collected.

```mermaid
flowchart LR
    O["Offline Ansible scanner"] -->|"Signed ZIP or JSON report"| I["LSA ingestion pipeline"]
    A["Managed Linux agent"] -->|"Outbound HTTPS on 8443"| I
    I --> V["Validate, verify, and normalize"]
    V --> D[("PostgreSQL inventory and findings")]
    V --> E[("Immutable evidence vault")]
    S["Vulnerability sync worker"] -->|"HTTPS"| OSV["OSV API"]
    S -->|"HTTPS"| K["CISA KEV catalog"]
    S --> D
    D --> C["Web console and API"]
    E --> C
```

LSA does **not** SSH to managed servers, store their privileged credentials, or initiate connections to them. Scans execute inside the customer's environment, and managed agents initiate every platform connection. Remediation is represented in the policy model but is currently locked to audit-only operation on both the server and client.

The current control surface includes:

- A deduplicated 390-control Debian 13 audit: 334 benchmark controls plus 56 non-overlapping portable Linux checks.
- A 98-control portable Linux audit for Debian 12, Ubuntu 22.04/24.04, and RHEL, Rocky Linux, or AlmaLinux 8/9.
- Deployment and benchmark profiles that determine which applicable controls are evaluated.
- New, persistent, and resolved finding comparison across report history.

## 2. Server side and architecture

The server is delivered as a Docker Compose stack. Only the TLS gateway is published; the application and data services remain on the internal Docker network.

| Component | Responsibility | Exposure |
| --- | --- | --- |
| **TLS gateway and web console** | Terminates HTTPS, serves the React console, and proxies API, documentation, and health requests | TCP 8443 only |
| **FastAPI service** | Authentication, fleet management, groups, policies, enrollment, ingestion, validation, findings, and audit events | Internal network |
| **PostgreSQL** | Tenants, users, sessions, hosts, groups, policies, reports, findings, credentials, tasks, and audit metadata | Internal network |
| **MinIO evidence vault** | Retention-enforced storage of original report artifacts with integrity verification | Internal network |
| **Alembic migrations** | Applies versioned database changes before the API starts | Startup job |
| **Vulnerability sync worker** | Queries OSV for observed Package URLs, enriches matching CVEs with CISA KEV, and writes the local advisory cache | Outbound HTTPS only |

### Server resource requirements

The following values are planning baselines for the bundled single-node Docker Compose deployment, not tested capacity limits. Production sizing must account for host count, audit frequency, concurrent ingestion, report size, retention, and console/API traffic.

| Resource | Evaluation or small lab | Recommended production starting point |
| --- | --- | --- |
| **CPU** | 2 vCPU | 4 vCPU; add capacity for concurrent report ingestion |
| **Memory** | 4 GiB RAM | 8 GiB RAM; monitor PostgreSQL, API workers, and MinIO under real load |
| **System and database disk** | 20 GiB free in addition to evidence storage | 50 GiB or more on SSD-backed storage, with database growth monitored |
| **Evidence storage** | 10 GiB or enough for the test retention period | Size separately from measured bundle size, audit frequency, host count, and retention |
| **Network** | Inbound TCP 8443 from administrators, scanners, and agents; outbound HTTPS from the intelligence worker | Stable TLS endpoint on TCP 8443 plus DNS and time synchronization |

Estimate raw evidence capacity with:

```text
host count × reports per host per day × average bundle size × retention days
```

Add at least 20% working headroom, plus separate capacity for PostgreSQL, container images, backups, and filesystem or object-store overhead. For example, 1,000 hosts uploading one 1 MiB bundle daily with 365-day retention require roughly 430 GiB after 20% headroom. The default maximum upload is 25 MiB and the default artifact retention is 365 days; actual bundles are normally much smaller, so measure them in the intended control profile before final sizing.

The server host also requires Docker Engine with the Compose plugin. It must be able to resolve DNS, maintain accurate time, reach configured identity or RADIUS providers, and reach an external S3 endpoint when the bundled MinIO service is replaced. Image and dependency access is required during installation or upgrades unless an internal registry or offline mirror is provided.

### Server data flow

1. The gateway accepts a request over HTTPS on port 8443 and routes it to the console or API.
2. The API authenticates the user, offline-scanner token, or agent identity and applies tenant and resource authorization.
3. Report ingestion validates identity binding, schema, size, safe archive paths, checksums, duplicate submissions, and optional Ed25519 signatures.
4. The original artifact is preserved in the evidence vault while normalized hosts, reports, controls, and findings are stored in PostgreSQL.
5. The console reads those normalized projections to present fleet status, findings, compliance, evidence history, groups, and policies.
6. A dedicated egress worker periodically queries OSV only for observed package identities, enriches CVEs found in CISA's Known Exploited Vulnerabilities catalog, and stores tenant-scoped application exposure matches. The API itself remains on the internal Docker network.

### Identity and security foundation

- Local bootstrap authentication plus OIDC presets for Microsoft Entra ID, Okta, Google Workspace, AD FS, and generic providers.
- RADIUS authentication and administrator-created local users for environments that require both external and break-glass access.
- Administrator, analyst, and auditor roles with server-side authorization.
- Database-backed sessions, security audit events, encrypted secrets, and encrypted TLS private keys.
- Host-scoped, expiring, immediately revocable ingestion tokens.
- One-time group enrollment tokens and host-generated Ed25519 identities for managed agents.
- Administrator-managed signing keys with host scope, expiry, revocation, and provenance history.
- Immutable policy versions and restore history; restoring an earlier policy publishes a new version.
- Original-evidence retention, verified download, and deletion audit events.

See [the architecture document](docs/architecture.md) for trust boundaries and design decisions, [the Docker deployment guide](docs/docker-deployment.md) for production operations, and [the evidence-vault guide](docs/evidence-vault.md) for integrity and retention behavior.

## 3. Client side: offline reports and managed agents

The offline scanner and managed agent share normalized contracts and control logic, but they serve different operating environments.

| | Offline report | Managed agent |
| --- | --- | --- |
| **Runtime** | Ansible from a customer-controlled controller | Installed service on each Linux host |
| **Connectivity** | None required for scanning; upload is optional | Outbound HTTPS to LSA on port 8443 |
| **Platform connection** | Signed ZIP transfer or token-authenticated JSON/ZIP upload | Enrolled Ed25519 machine identity |
| **Policy source** | Scanner inventory and variables | Group policy retrieved from LSA |
| **Reporting** | HTML, findings CSV, application CSV, JSON, checksum, manifest, and ZIP | Signed heartbeat, policy state, audit task, application inventory, and report exchange |
| **Best fit** | Isolated, air-gapped, approval-driven, or occasional audits | Continuous fleet visibility and centrally managed audit scope |

### Offline reports

The Ansible scanner collects security observations, installed package versions, and systemd service state without changing host configuration. Each enrolled host has a persistent platform UUID and may use a host-scoped ingestion token. For stronger provenance, the controller can sign bundles with an Ed25519 private key while LSA stores only the registered public key.

Delivery modes are:

- `offline` — build and retain the report bundle without contacting LSA.
- `upload` — submit the report to LSA.
- `upload_and_keep` — submit the report and retain the local artifact; this is the production default.

The offline workflow is appropriate when an agent cannot be installed, the target network has no route to the platform, or report transfer requires an explicit approval step.

### Managed agents

The unified Linux agent is available as Debian/Ubuntu (`.deb`), RHEL-family (`.rpm`), and universal (`.tar.gz`) packages downloadable from the console. Package installation stages the agent without starting it. A one-time enrollment command then creates a root-only configuration, generates the host signing key, assigns the agent to exactly one group, and enables its systemd service.

Agent sizing is per managed host. The figures below describe available headroom during an audit, not the total resources the host must have for its other workloads.

| Resource | Minimum baseline | Recommended headroom |
| --- | --- | --- |
| **CPU** | 1 available vCPU | 2 available vCPU during larger audit profiles |
| **Memory** | 512 MiB available | 1 GiB available during an audit |
| **Disk** | 500 MiB free for runtime, virtual environment, controls, state, and initial reports | 1 GiB or more, plus capacity for retained report history |
| **Network** | Outbound TCP 8443 to the LSA platform | Reliable DNS, time synchronization, and TLS trust for the platform certificate |

The host requires Python 3.11 or newer, `venv` support, systemd, and root privileges so read-only controls can inspect protected system state. Enrollment installs constrained Python dependencies into `/opt/lsa-agent/venv`, so it also requires access to the dependency source or an internal/offline package mirror. No inbound agent port is required.

Audit bundles retained by the agent under `/var/lib/lsa-agent/reports` consume additional disk over time. Plan that capacity as `average bundle size × retained audits`, and monitor or rotate the directory according to the organization's evidence policy. CPU and memory use peak while the local Ansible audit is running; the polling daemon is otherwise lightweight.

Every group has an effective policy. Policies can select controls by category and set their intended mode, allowing different fleets to have different audit scopes. Publishing a change creates an immutable version. The current safety lock permits audit execution only; write/remediation behavior remains disabled.

Agents poll the platform rather than accepting inbound connections. Their signed heartbeats drive online, stale, and offline status. Each audit uses the shared scanner to report the same package and service inventory as offline mode. On-demand audits are persisted, allow-listed tasks consumed on the next poll—not remote shell commands.

See [the agent guide](agent/README.md) for package installation, enrollment, certificate trust, and service operation, and [the report-format guide](docs/report-format.md) for normalized and signed report contracts.

## Quick start

Requirements: Docker Engine with the Compose plugin.

```bash
cp deploy/.env.example deploy/.env
# Replace every placeholder secret in deploy/.env.
make up
```

Open `https://localhost:8443` and sign in with the bootstrap email and password from `deploy/.env`. The first boot uses a self-signed localhost certificate. API documentation is available at `https://localhost:8443/docs`.

The database and evidence objects are stored in named Docker volumes. Migrations run automatically before the API starts, and Compose waits for PostgreSQL, MinIO, the API, and the web gateway to become healthy. Use `make logs`, `make ps`, and `make down` for routine operation.

### Vulnerability intelligence

Open **Applications** to review package inventory, affected versions, matching advisories, fixed versions, CISA KEV priority, and the hosts exposed to each vulnerability. Administrators can queue an immediate refresh from this page. The `vulnerability-sync` container also refreshes automatically every 12 hours by default; configure the interval with `LSA_VULNERABILITY_REFRESH_HOURS`.

Online synchronization sends only versioned Package URLs for active package inventory to OSV. It does not send hostnames, IP addresses, tags, findings, or credentials. The worker has outbound access, while the API, PostgreSQL, and MinIO remain attached only to the internal backend network.

For an air-gapped LSA server, create a scoped snapshot on a connected workstation from one or more offline `report.json` files:

```bash
.venv/bin/python scanner/scripts/build_vulnerability_snapshot.py \
  /path/to/report.json \
  --output vulnerability-snapshot.json
```

Transfer the JSON through the approved media workflow, then choose **Import Snapshot** on the **Applications** page. Imported data follows the same correlation and audit path as online synchronization. Snapshot files contain public advisory data plus the Package URLs present in the input reports; handle them according to the organization's software-inventory policy.

For direct local development and testing, install Python 3.12+ and Node.js 22+:

```bash
make install
cp .env.example .env
make test
```

The seeded development ingestion token is `lsa_ingest_demo_secret`. It is intentionally local-only and must never be used in production.

## Offline scanner workflow

### Enroll a host

Sign in as an administrator, open **Linux hosts**, and choose **Enroll host**. LSA creates a persistent host UUID and a scoped ingestion token. The raw token is shown once; store it in a mode-0600 file on the Ansible controller and assign the displayed host UUID to `lsa_host_id` in inventory.

The first accepted report binds that platform identity to the host's hashed machine ID. Later reports with a different machine ID are rejected. Administrators can issue, list, and revoke credentials from **Ingestion tokens** or through the `/api/v1/ingestion-tokens` endpoints. Prefer host-scoped tokens with an expiry.

For cryptographic provenance, generate an Ed25519 key with `scanner/scripts/generate_signing_key.py`, register only its public key under **Signing keys**, and add the returned key ID and private-key path to the scanner variables.

### Run the scanner

Copy `scanner/inventory.example.ini`, assign each host its platform UUID, then run:

```bash
cd scanner
ansible-playbook -i inventory.ini playbooks/scan.yml \
  -e lsa_delivery_mode=upload_and_keep
```

Select an LSA deployment profile (`production_server`, `minimal_server`, `router`, or `container`) or a direct benchmark profile (`level1_server`, `level2_server`, `level1_workstation`, or `level2_workstation`) with `lsa_profile`.

### Submit a JSON report directly

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${LSA_INGEST_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @report.json \
  https://localhost:8443/api/v1/ingest/reports
```

## Managed agent workflow

Open **Agents** in the primary console navigation, choose **Install agent**, and download the package for the target distribution. Assign a policy to a group and create a short-lived, one-time enrollment token. On Debian or Ubuntu, for example:

```bash
sudo apt install ./lsa-agent_0.4.0_all.deb
sudo lsa-agent-enroll --platform-url 'https://lsa.example.com:8443' --token 'lsa_enroll_...'
```

The **Agents** workspace opens on **All hosts**. Select a group in the left fleet rail to view its hosts and effective policy. From there, administrators can publish categorized control overrides, request an audit, move agents to another group, or revoke them.

Agent 0.4 verifies a package-generated SHA-256 manifest before each cycle and refuses to run a scan when its runtime or local control catalog has changed. It also remembers the highest accepted group-policy version and rejects policy rollback. Package transport checksums remain available in the console; the runtime manifest protects the installed executable and scanner content after download.

## Repository map

- `apps/api` — API, data model, ingestion, migrations, and tests
- `apps/web` — React fleet console
- `scanner` — Ansible scanner, report builder, and submission flow
- `agent` — outbound Linux agent runtime, packages, and systemd service
- `packages/contracts` — versioned machine-readable contracts
- `deploy` — Docker Compose deployment
- `docs` — architecture, deployment, evidence, and report-format documentation

GitHub Actions runs backend and frontend tests and executes the complete scanner inside an official Debian 13 container. It validates the normalized report, verifies the portable bundle, and ingests it through the API.
