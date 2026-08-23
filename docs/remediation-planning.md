# Remediation planning

LSA remediation is being introduced in security-gated stages. The current stage compiles approved, catalog-backed plans into immutable signed change sets, delivers read-only preflight contracts, and records signed recovery readiness. It still gives neither the platform nor the agent any ability to change a host.

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
- `GET /api/v1/remediation-change-sets`
- `POST /api/v1/remediation-change-sets`
- `GET /api/v1/remediation-change-sets/{change_set_id}`
- `GET /api/v1/remediation-change-sets/{change_set_id}/execution-contract-preview/{agent_id}`
- `GET /api/v1/remediation-change-sets/{change_set_id}/validation-jobs`
- `POST /api/v1/remediation-change-sets/{change_set_id}/validation-jobs`
- `GET /api/v1/remediation-change-sets/{change_set_id}/checkpoint-jobs`
- `POST /api/v1/remediation-change-sets/{change_set_id}/checkpoint-jobs`
- `GET /api/v1/remediation-change-sets/{change_set_id}/recovery-verification-jobs`
- `POST /api/v1/remediation-change-sets/{change_set_id}/recovery-verification-jobs`
- `POST /api/v1/remediation-change-sets/{change_set_id}/authorize`
- `POST /api/v1/remediation-change-sets/{change_set_id}/cancel`

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

## Signed change sets

An administrator can compile one or more approved catalog-backed plans into a pending change set. The canonical envelope snapshots plan and action identities, target agents, group and policy versions, required capability, canary membership, maintenance window, batch size, batch interval, and explicit non-execution safeguards. A SHA-256 digest covers the canonical JSON document.

Authorization is fail closed. LSA recalculates the following gates from current state:

- action snapshot and digest integrity;
- current source evidence within the policy age limit;
- current group and policy authorization;
- recent agent attestation of the exact `signed-change-set-planning-v1` capability, which declares support for governance evidence only and does not declare write execution;
- at least one bounded canary host;
- policy-constrained target, canary, batch, and interval limits;
- a future maintenance window lasting between 30 minutes and 8 hours;
- reviewed backup, validation, and rollback metadata;
- a four-eyes authorizer who is neither the requester nor an approver of an included plan.

If every gate passes, LSA signs the envelope with a tenant-specific Ed25519 change-signing key. The encrypted private key remains in platform settings storage; the response exposes the public key, fingerprint, payload digest, and signature so the governance record can be independently verified. Signing does not create an `AgentTask`, expose a gateway route, or make the envelope executable.

Change-set states are `pending_authorization`, `authorized`, and `canceled`. An authorized envelope is immutable. Cancellation retains its payload, signature, decision history, and audit evidence.

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
- Every change-set payload is canonicalized and digest-checked; an authorized envelope must also pass Ed25519 signature verification when read.
- Change-set authorization enforces fresh policy, evidence, agent capability, rollout, maintenance, rollback, and independent-review gates.
- Capability freshness uses the last signed heartbeat that actually supplied the capability list; policy and task polling cannot refresh this gate.
- Selected plan rows are locked while active ownership is checked and the envelope is inserted, preventing concurrent active change sets for the same plan.
- Tenant change-signing private keys are encrypted at rest and are created only when the first envelope is authorized.
- Plan APIs are available only on the management listener; the agent gateway allow-list does not expose them.
- Change-set APIs are also management-only and never create agent tasks.
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

### Stage 3 — signed change sets and canaries (complete)

Compile approved plans into signed declarative change sets. Require fresh evidence, policy authorization, maintenance windows, agent capability attestation, canary scope, rate limits, and explicit rollback checkpoints. Add four-eyes approval as an enforceable tenant policy before execution is available.

### Stage 4 — constrained execution

Add a separate remediation capability to the agent with least-privilege execution, action-level allow-listing, tamper-evident receipts, post-change verification, automatic stop conditions, and rollback. This stage requires a new threat model and must not reuse the audit task payload.

#### Stage 4A — validation-only execution contract

The first execution-stage increment defines the trust contract without enabling
execution. The management API can compile an authorized change set into a
target-specific validation preview. The current platform-control identity endorses
the change-signing key, and the agent contains fail-closed validation for the
endorsement, change-set signature and digest, target binding, action snapshot
digests, operation vocabulary, reviewed paths, backups, validation, and rollback.
The preview remains management-only, creates no agent task, and carries explicit
`execution_enabled: false` and `dispatch_enabled: false` locks. See
[the remediation execution threat model](remediation-execution-threat-model.md).

#### Stage 4B — read-only preflight and signed receipts

An administrator can explicitly queue one authorized target for validation. This
creates a `RemediationValidationJob`, not an `AgentTask`. The dedicated agent route
delivers the immutable contract inside the existing short-lived, agent-bound,
replay-protected platform envelope. The agent repeats every Stage 4A trust check,
then performs read-only operating-system, package, program, reviewed-path, and
validation-interface preflight checks. Manual confirmations remain blocked rather
than being guessed or bypassed.

The agent signs a canonical receipt with its enrolled Ed25519 identity. The receipt
binds the validation job, change set, contract digest, agent, host, agent version,
runtime-integrity digest, action results, and evaluation time. Both
`execution_enabled` and `changes_applied` are fixed to `false`. Receipt submission
is idempotent only for the identical signed document. Cancellation expires queued
or delivered validation jobs. No shell content, configuration writes, reloads,
audit task type changes, or privileged executor exist in this stage.

#### Stage 4C — deterministic recovery planning

Agent 0.9.0 extends the signed preflight receipt with a recovery plan derived from
the immutable contract. Each backup-required operation is paired with exactly one
reviewed restore operation and receives a deterministic checkpoint identity. For an
existing regular file, the agent records its SHA-256 digest, size, ownership, and
mode; an absent file is recorded explicitly so rollback can require removal of a
future created file. Rollback order is the exact reverse of checkpoint order.

The recovery planner safely opens regular files without following the final symbolic
link and rejects symbolic-link parents, non-regular files, sources larger than 8 MiB,
missing or ambiguous restore coverage, and multiple actions targeting the same path.
The platform independently reconstructs checkpoint identities and coverage before
accepting the agent signature. Older 0.8 receipts remain verifiable, while an agent
advertising `remediation-recovery-planning-v1` must include a valid plan unless the
contract itself failed validation.

This is still planning only. `backup_created`, `execution_enabled`, and
`changes_applied` remain `false`; the journal state is fixed to `planned`. There is
no backup store, mutation primitive, service controller, sysctl writer, subprocess,
or execution dispatch route.

#### Stage 4D — encrypted local checkpoints and durable journals

After a ready signed preflight, an administrator can explicitly queue a separate
checkpoint job for that exact validation receipt. The platform revalidates the
contract, recovery plan, agent capability, change-set authorization, and maintenance
window before delivery. The signed agent envelope binds the checkpoint job,
validation job, contract digest, and recovery plan.

Agent 0.10.0 revalidates the full contract and reconstructs the recovery-plan
binding before reading a source. It refuses source drift after preflight. Existing
regular files are encrypted with AES-256-GCM using a root-only, agent-local key;
authenticated data binds the job, contract, checkpoint, reviewed path, and original
digest. Absent paths receive a durable marker rather than an invented backup. An
atomic journal is persisted before work and after each checkpoint, making retries
idempotent after a crash. The local blob store is capped at 256 MiB.

The agent-signed receipt contains checkpoint identities, encrypted blob digests and
sizes, journal state, and errors. It never includes source content or the encryption
key. The platform independently verifies exact checkpoint coverage and evidence
shape. No decrypt-for-restore API, rollback operation, configuration write, service
reload, sysctl mutation, arbitrary command, or remediation executor exists.

#### Stage 4E — recovery-readiness verification

After a ready checkpoint receipt is accepted, an administrator can explicitly queue
a separate verification job. The job freezes the checkpoint, validation, change set,
contract, recovery plan, and accepted journal digest. Delivery remains agent-initiated
and platform-signed, and only agent 0.11.0 or later can attest the dedicated capability.

The agent requires the exact accepted local journal and root-only encryption key.
For every regular-file checkpoint it verifies the blob size and SHA-256 digest,
authenticates the AES-256-GCM tag and bound metadata, decrypts only in memory, and
compares the original source digest. Absent-source markers must have no blob. The
agent signs a metadata-only readiness receipt and caches it exactly for safe retries.

The platform verifies the receipt signature, identities, time window, complete
coverage, checkpoint journal binding, and equality with the accepted encrypted-blob
evidence. Missing keys, altered journals, corrupt blobs, failed authentication, or
digest drift block readiness. Checkpoints are retained; there is no automatic or
remote deletion while recovery evidence may be active. No plaintext leaves the
agent, and no restore, host mutation, service control, sysctl write, command, or
execution route exists.
