# Remediation planning

LSA remediation is being introduced in security-gated stages. The current stage provides a review and approval ledger without giving the platform or agent any ability to change a host.

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

Authenticated users can review plans. Mutations require the administrator role. Only one pending or approved plan can exist for the same finding. A newer report makes the source snapshot stale and blocks approval; the reviewer must create a new plan from the current finding.

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
- Plan APIs are available only on the management listener; the agent gateway allow-list does not expose them.
- The agent task schema accepts only `task_type: audit`.
- Policies and plans never contain arbitrary scripts.
- Approval is blocked when the source report is no longer current.
- Tenant scoping is applied to every read and mutation.
- Every state transition produces an audit event.

## Delivery roadmap

### Stage 1 — planning and approval (current)

Create, review, approve, reject, and cancel non-executable plans. Present the observed and required state clearly and detect stale evidence.

### Stage 2 — declarative action catalog

Define versioned, code-reviewed remediation actions for individual controls. Each action must declare supported operating systems, exact parameters, preconditions, validation, expected file or service impact, and rollback behavior. Arbitrary shell content remains prohibited.

### Stage 3 — signed change sets and canaries

Compile approved plans into signed declarative change sets. Require fresh evidence, policy authorization, maintenance windows, agent capability attestation, canary scope, rate limits, and explicit rollback checkpoints. Add four-eyes approval as an enforceable tenant policy before execution is available.

### Stage 4 — constrained execution

Add a separate remediation capability to the agent with least-privilege execution, action-level allow-listing, tamper-evident receipts, post-change verification, automatic stop conditions, and rollback. This stage requires a new threat model and must not reuse the audit task payload.
