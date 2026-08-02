# Linux Security Auditor

Linux Security Auditor (LSA) is an ingestion-first Linux security and compliance platform. Customer-controlled Ansible scans produce normalized evidence; LSA validates it, maintains a persistent profile for each host, and presents fleet-wide risk, compliance, findings, and history from one console.

LSA does **not** SSH to servers, store privileged server credentials, or execute scans remotely.

## Current v0.1 foundation

- FastAPI ingestion and fleet API
- PostgreSQL-compatible tenant, host, report, finding, token, and audit models
- Online JSON and offline ZIP report ingestion
- Duplicate detection and host-scoped token enforcement
- New, persistent, and resolved finding comparison
- React fleet dashboard, host profiles, findings queue, and report upload
- Versioned report JSON Schema
- Ansible report generation and submission role
- Offline HTML, CSV, JSON, checksum, manifest, and ZIP generation
- Docker Compose development stack
- Backend and frontend tests plus GitHub Actions CI

## Quick start

Requirements: Python 3.12+, Node.js 22+, and optionally Docker.

```bash
make install
cp .env.example .env
make test
make dev
```

Open `http://localhost:5173`. Development login:

```text
admin@lsa.local
lsa-dev-password
```

The seeded development ingestion token is `lsa_ingest_demo_secret`. It is intentionally local-only and must never be used in production.

API documentation is available at `http://localhost:8000/docs`.

## Submit a JSON report

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${LSA_INGEST_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @report.json \
  http://localhost:8000/api/v1/ingest/reports
```

## Run the scanner

Copy `scanner/inventory.example.ini`, assign each host its platform UUID, then run:

```bash
cd scanner
ansible-playbook -i inventory.ini playbooks/scan.yml \
  -e lsa_delivery_mode=upload_and_keep
```

Delivery modes are `offline`, `upload`, and `upload_and_keep`. The last mode is the production default because it preserves a local artifact even after successful submission.

## Repository map

- `apps/api` — API, data model, ingestion, migrations, tests
- `apps/web` — React fleet console
- `scanner` — Ansible scanner, report builder, submission flow
- `packages/contracts` — versioned machine-readable contracts
- `deploy` — local deployment composition
- `docs` — architecture and report-format documentation

See [docs/architecture.md](docs/architecture.md) for trust boundaries and design decisions.

