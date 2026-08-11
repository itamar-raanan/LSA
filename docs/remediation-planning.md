# Remediation planning

LSA remediation is being introduced in security-gated stages. The current stage adds a versioned, code-reviewed declarative action catalog to the review and approval ledger without giving the platform or agent any ability to change a host.

## Current workflow

1. An administrator selects an open finding from the host's latest accepted report.
2. LSA creates a `pending_approval` plan containing an immutable snapshot of the finding's current state, required state, guidance, affected paths, and operational impact.
3. An administrator approves, rejects, or cancels the plan. A reason is mandatory for rejection and cancellation.
4. LSA records every transition in the tenant audit log.
5. The plan remains a management record. Approval does not dispatch work to an agent.

The API exposes these management routes:

- `GET /api/v1/remediation-plans`
- `POST /api/v1/remediation-plans`
- `GET /api/v1/remediation-plans/{plan_id}`
- `POST /api/v1/remediation-plans/{plan_id}/approve`
- `POST /api/v1/remediation-plans/{plan_id}/reject`
- `POST /api/v1/remediation-plans/{plan_id}/cancel`
- `GET /api/v1/remediation-actions`
- `GET /api/v1/remediation-actions/{action_id}`

Authenticated users can review plans. Mutations require the administrator role. Only one pending or approved plan can exist for the same finding. A newer report makes the source snapshot stale and blocks approval; the reviewer must create a new plan from the current finding.

## Declarative action catalog

The catalog currently defines reviewed actions for direct root SSH login, empty-password SSH authentication, IPv4 forwarding, and setuid core dumps. Every action declares:

- a stable action ID, integer version, and SHA-256 digest;
- the exact controls and operating-system versions it supports;
- typed parameters whose defaults remain inside an explicit allow-list;
- fail-closed automated or manual preconditions;
- structured configuration operations selected from a closed operation vocabulary;
- post-change validation, backup requirements, rollback operations, and availability impact.

The catalog cannot contain shell, script, command, executable, or argument payload fields. Paths must be normalized absolute paths beneath reviewed system configuration prefixes. API startup fails if the catalog is malformed, maps an unknown control, duplicates a current control mapping, omits validation or rollback, or references an unapproved operation field.

When a plan is created for a supported host and control, LSA stores an immutable copy of the matching action with its ID, version, and digest. Approval revalidates that snapshot and its digest. An unsupported host is labeled `unsupported_system`; a control without an action is labeled `not_cataloged`. Both can still use the non-executable review ledger, but neither silently receives an action.

## State model

```text
                         ┌──────────┐
                    ┌───▶│ rejected │
                    │    └──────────┘
┌──────────────────┐│
│ pending_approval │┼──────────────▶┌──────────┐
└──────────────────┘│               │ approved │
                    │               └────┬─────┘
                    │                    │
                    └──────────┬─────────┘
                               ▼
                         ┌──────────┐
                         │ canceled │
                         └──────────┘
```

Terminal plans cannot be reopened. Creating a replacement produces a new plan and preserves the earlier decision history.

## Safety invariants

- `execution_enabled` is always `false` and `execution_status` is always `not_supported`.
- Plans contain review data, not an agent command payload.
- Catalog actions contain declarative data only and always return `execution_enabled: false` with `execution_status: catalog_only`.
- A plan's action snapshot is digest-checked before approval and never refreshed from a later catalog version.
- Plan APIs are available only on the management listener; the agent gateway allow-list does not expose them.
- The agent task schema accepts only `task_type: audit`.
- Policies and plans never contain arbitrary scripts.
- Approval is blocked when the source report is no longer current.
- Tenant scoping is applied to every read and mutation.
- Every state transition produces an audit event.

## Delivery roadmap

### Stage 1 — planning and approval (complete)

Create, review, approve, reject, and cancel non-executable plans. Present the observed and required state clearly and detect stale evidence.

### Stage 2 — declarative action catalog (complete)

Define versioned, code-reviewed remediation actions for individual controls. Each action must declare supported operating systems, exact parameters, preconditions, validation, expected file or service impact, and rollback behavior. Arbitrary shell content remains prohibited.

### Stage 3 — signed change sets and canaries (next)

Compile approved plans into signed declarative change sets. Require fresh evidence, policy authorization, maintenance windows, agent capability attestation, canary scope, rate limits, and explicit rollback checkpoints. Add four-eyes approval as an enforceable tenant policy before execution is available.

### Stage 4 — constrained execution

Add a separate remediation capability to the agent with least-privilege execution, action-level allow-listing, tamper-evident receipts, post-change verification, automatic stop conditions, and rollback. This stage requires a new threat model and must not reuse the audit task payload.
