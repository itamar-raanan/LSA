# Remediation execution threat model

## Scope

This document defines the security boundary for Stage 4 remediation work. Stage 4A
added a validation-only protocol contract. Stage 4B can deliver that immutable
contract only through a separate signed validation route and accept an agent-signed
read-only preflight receipt. Stage 4C adds deterministic recovery planning to that
receipt. Stage 4D can create encrypted backup material only inside the agent's
private state directory after a separate explicit request. Stage 4E can authenticate
and decrypt that material in memory to prove recovery readiness. It does not create a
remediation task, write host configuration, restore a backup, reload a service,
change a kernel setting, or expose a privileged executor.

The protected outcome is narrower than “the platform requested a change.” A future
executor must prove that one exact, reviewed catalog action was independently
approved, signed, delivered to the intended enrolled agent, evaluated inside the
authorized maintenance and rollout boundaries, and either verified or rolled back
with a signed receipt.

## Assets

- Tenant and host isolation.
- Agent identity and its private signing key.
- The pinned platform-control public key.
- The tenant change-set signing key and its encrypted private material.
- Authorized change-set payloads, signatures, and digests.
- Immutable remediation action snapshots and their digests.
- Host configuration, backups, validation evidence, and rollback evidence.
- Administrator approvals, maintenance windows, canary assignments, and audit events.

## Trust boundaries

1. **Management browser to management API (TCP 8443).** Administrators create and
   authorize governance records. Authentication, tenant scoping, RBAC, and four-eyes
   review apply here.
2. **Management API to database.** The database stores policy, immutable action
   snapshots, signed change sets, target bindings, and audit history. Concurrent
   state transitions must use row locks and fail closed.
3. **Platform to agent gateway (TCP 8444).** The agent initiates outbound requests.
   Platform responses are signed by the pinned platform-control identity and are
   agent-bound, expiring, and replay protected.
4. **Agent validation boundary.** Untrusted network data becomes eligible for future
   execution only after schema, signature, digest, target, policy, rollout, time,
   action vocabulary, path, backup, validation, and rollback checks all pass.
5. **Future privileged executor.** This boundary does not exist in Stage 4A. It must
   be a separate module and capability, accept only validated typed operations, and
   never accept shell, script, command, executable, argument-vector, or arbitrary
   path fields.

## Adversaries and failure modes

| Threat | Required mitigation |
| --- | --- |
| Network attacker modifies or replaces a contract | Verify the authorized change-set signature and its SHA-256 digest. |
| Attacker substitutes their own change-signing key | Require a purpose-bound endorsement signed by the agent's pinned platform-control key. |
| Valid contract is sent to another host or tenant | Bind tenant, agent, host, group, policy version, rollout phase, and capability inside the signed change-set payload. |
| Old contract is replayed | Delivery uses platform-envelope sequence protection, a persistent validation-job state, a bounded lease, contract expiry, and idempotency only for an identical signed receipt. |
| Authorized action is replaced after review | Recalculate the immutable action snapshot digest and match its ID, version, control, plan, and host to the signed change set. |
| Payload smuggles executable content | Reject unknown schema fields and recursively reject shell, script, command, executable, argv, and args keys. |
| Catalog path escapes reviewed configuration roots | Accept normalized absolute paths only under explicit reviewed prefixes; Stage 4A permits `/etc/` only. |
| Service or sysctl operation runs without backup | Require every modified path to declare a backup and a matching restore operation. |
| Policy or evidence changes after authorization | Future dispatch must re-evaluate live policy, evidence freshness, agent attestation, and cancellation immediately before delivery. |
| Maintenance window or rollout is bypassed | Future agent validation must use trusted time and enforce canary, batch, interval, and window state before execution. |
| Agent crashes after a partial change | Future executor must persist a write-ahead checkpoint and backup receipt before the first mutation. |
| Validation fails after mutation | Stop, roll back automatically, validate rollback, sign the receipt, and block subsequent targets. |
| Platform or operator attempts arbitrary commands | No generic command task, subprocess payload, template expansion, or remote shell exists in the protocol. |
| Compromised root agent process changes the host | Out of scope for prevention; runtime integrity, signed receipts, audit correlation, and host isolation provide detection and containment evidence. |

## Stage 4A protocol invariants

- Contract schema is fixed at `1.0` and contract type is `remediation-validation`.
- `mode` is exactly `validate_only`.
- `execution_enabled` and `dispatch_enabled` are exactly `false`.
- Only an authorized, signature-verifiable change set can produce a preview.
- The platform-control key signs a purpose-bound endorsement of the tenant
  change-signing key.
- The target record must be present byte-for-byte in the signed change-set target
  collection.
- Every included action snapshot must match a signed plan identity and digest.
- Unknown root fields and executable-content keys are rejected.
- Stage 4A previews remain management-only; Stage 4B delivery is restricted to the dedicated signed validation route.
- No `AgentTask` row is created.
- The agent advertises `remediation-contract-validation-v1`, which explicitly does
  not authorize writes or execution.

## Stage 4B invariants

- Only an administrator can explicitly queue a validation job for an authorized target.
- The delivery and receipt routes require signed agent authentication and the exact validation capabilities.
- The platform envelope binds the contract to one agent and provides expiry and replay protection.
- The contract digest is recalculated before queueing, delivery, evaluation, and receipt acceptance.
- Local evaluation reads operating-system, package, program, path, and validation-interface state only.
- Manual or host-role confirmations remain blocked until an operator resolves them.
- The receipt uses canonical UTC `Z` timestamps and an independent agent Ed25519 signature.
- The receipt fixes `execution_enabled` and `changes_applied` to `false`.
- Cancellation closes queued and delivered validation jobs.
- `AgentTask.task_type` remains exactly `audit`.

## Stage 4C invariants

- Recovery plans are derived locally from the already validated immutable contract.
- Every backup-required operation maps to exactly one reviewed restore operation.
- Checkpoint identities bind the plan, action digest, operation index, rollback
  index, and reviewed path using canonical SHA-256.
- Existing sources are regular files opened without following the final symbolic
  link; their digest, size, owner, group, and mode are included in the signed receipt.
- Absent sources are explicit so a future rollback can remove a newly created file.
- Symbolic links, unsafe parents, non-regular files, sources over 8 MiB, ambiguous
  restore coverage, and overlapping target paths block readiness.
- Rollback order is the exact reverse of checkpoint order and is reconstructed by
  the platform before receipt acceptance.
- Agents advertising `remediation-recovery-planning-v1` must include a valid plan,
  except when the signed receipt reports that contract validation itself failed.
- `backup_created`, `execution_enabled`, and `changes_applied` remain false, and
  recovery journal state remains `planned`.
- The agent still contains no backup writer, restore primitive, configuration
  mutation, service controller, sysctl writer, or generic subprocess path.

## Stage 4D invariants

- Checkpoint preparation is a separate administrator action and job ledger, allowed
  only after a ready signed validation receipt with a valid recovery plan.
- Delivery binds one checkpoint job to one validation job, change set, agent, host,
  contract digest, and immutable recovery plan in a signed platform envelope.
- The agent repeats contract and recovery-plan validation and rejects any source
  whose digest or metadata changed after preflight.
- Regular-file content is encrypted with AES-256-GCM. Authenticated data binds job,
  contract, checkpoint, reviewed path, and original source digest.
- The encryption key is generated locally, stored root-only, and never sent to the
  platform. Receipts contain only encrypted blob digests and sizes.
- An atomic journal is written before checkpoint creation and after every completed
  entry. A repeated delivery returns the terminal journal and exact cached receipt.
- Absent paths create a journal marker and no blob. Symbolic links and non-regular
  files remain blocked.
- Encrypted blobs and journals live only beneath `/var/lib/lsa-agent`; total blob
  storage is capped at 256 MiB.
- The platform independently verifies exact checkpoint coverage and evidence shape
  before accepting the agent signature.
- `execution_enabled` and `changes_applied` remain false. There is no restore,
  configuration mutation, service control, sysctl write, or command execution path.

## Stage 4E invariants

- Recovery verification is a separate administrator action and job ledger allowed
  only for a ready, accepted encrypted checkpoint receipt.
- The signed delivery binds the verification job to the checkpoint, validation,
  change set, contract digest, immutable recovery plan, agent, host, and accepted
  journal digest.
- The agent refuses missing or permissive keys, altered journals, incomplete
  coverage, unexpected blobs for absent paths, and blob metadata drift.
- Every regular-file blob must match its accepted SHA-256 and size, authenticate its
  AES-256-GCM tag and bound metadata, and decrypt to the original source digest.
- Decrypted bytes remain in agent process memory and never enter a receipt, log,
  platform response, or host configuration path.
- The signed receipt reports exact checkpoint coverage and only encrypted-blob
  metadata. The platform compares it with the accepted checkpoint evidence.
- Checkpoint deletion is not automatic. A future cleanup operation must be explicit
  and prove that no active or recoverable change references the material.
- `execution_enabled` and `changes_applied` remain false. No restore, configuration
  mutation, service control, sysctl write, command, or execution route exists.

Actual mutation requires a later review covering privilege separation, durable and
encrypted write-ahead backup storage, idempotency, crash recovery, automatic
rollback, stop thresholds, and receipt reconciliation.
