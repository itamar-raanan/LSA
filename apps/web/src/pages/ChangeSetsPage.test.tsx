import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { RemediationChangeSet, RemediationCheckpointJob, RemediationValidationJob } from '../types'
import { ChangeSetsPage } from './ChangeSetsPage'

const { authorizeRemediationChangeSet, cancelRemediationChangeSet, createRemediationChangeSet, queueRemediationCheckpoint, queueRemediationValidation, remediationChangeSets, remediationCheckpointJobs, remediationPlans, remediationValidationJobs, session } = vi.hoisted(() => ({
  authorizeRemediationChangeSet: vi.fn(),
  cancelRemediationChangeSet: vi.fn(),
  createRemediationChangeSet: vi.fn(),
  remediationChangeSets: vi.fn(),
  remediationCheckpointJobs: vi.fn(),
  remediationPlans: vi.fn(),
  remediationValidationJobs: vi.fn(),
  queueRemediationValidation: vi.fn(),
  queueRemediationCheckpoint: vi.fn(),
  session: { userId: 'authorizer-1', role: 'admin' },
}))

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: session.userId, email: 'admin@lsa.local', name: 'Security Administrator', role: session.role } }),
}))

vi.mock('../api/client', () => ({
  api: { authorizeRemediationChangeSet, cancelRemediationChangeSet, createRemediationChangeSet, queueRemediationCheckpoint, queueRemediationValidation, remediationChangeSets, remediationCheckpointJobs, remediationPlans, remediationValidationJobs },
}))

const pendingChangeSet: RemediationChangeSet = {
  id: 'change-set-12345678', status: 'pending_authorization', payload_schema_version: '1.0',
  payload: { schema_version: '1.0', safeguards: { execution_enabled: false } },
  digest: 'd'.repeat(64), signature: null, signing_key_id: null, signing_key_fingerprint: null, signing_public_key: null,
  maintenance_window_start: '2026-08-12T10:00:00Z', maintenance_window_end: '2026-08-12T12:00:00Z',
  batch_size: 1, batch_interval_minutes: 15,
  plans: [{ plan_id: 'plan-1', hostname: 'web-01', host_id: 'host-1', control_id: 'CIS-DEBIAN13-5.1.1', title: 'Disable Direct Root SSH Login', action_id: 'linux.ssh.permit-root-login.disabled', action_version: 1, action_digest: 'a'.repeat(64), plan_approved_by: 'reviewer-1' }],
  targets: [{ host_id: 'host-1', hostname: 'web-01', agent_id: 'agent-1', group_id: 'group-1', group_name: 'Production Linux', policy_id: 'policy-1', policy_name: 'Monitor', policy_version: 4, rollout_phase: 'canary', required_capability: 'signed-change-set-planning-v1', capability_attested: true }],
  gates: [
    { code: 'action_integrity', status: 'passed', detail: 'Reviewed action identity and digest match.' },
    { code: 'agent_attestation', status: 'passed', detail: 'The canary agent recently attested the required capability.' },
    { code: 'canary_scope', status: 'passed', detail: 'A bounded canary scope is present.' },
    { code: 'evidence_freshness', status: 'passed', detail: 'Source evidence remains current.' },
    { code: 'four_eyes', status: 'passed', detail: 'The current administrator is independent.' },
    { code: 'maintenance_window', status: 'passed', detail: 'The window is bounded.' },
    { code: 'policy_authorization', status: 'passed', detail: 'Policy identity remains current.' },
    { code: 'rate_limit', status: 'passed', detail: 'Batch limits match policy.' },
    { code: 'rollback_checkpoint', status: 'passed', detail: 'Rollback metadata is present.' },
  ],
  requested_by: 'requester-1', requested_by_name: 'Request Administrator', requested_at: '2026-08-11T08:00:00Z',
  authorized_by: null, authorized_by_name: null, authorized_at: null,
  canceled_by: null, canceled_by_name: null, canceled_at: null, cancellation_reason: null,
  execution_enabled: false, execution_status: 'not_supported', execution_reason: 'This release retains signed governance records and cannot dispatch agent work.',
  created_at: '2026-08-11T08:00:00Z', updated_at: '2026-08-11T08:00:00Z',
}

const authorizedChangeSet: RemediationChangeSet = {
  ...pendingChangeSet,
  status: 'authorized',
  signature: 'signed-envelope',
  signing_key_id: 'key-1',
  signing_key_fingerprint: 'SHA256:change-signing-key',
  signing_public_key: 'public-key',
  authorized_by: 'authorizer-1',
  authorized_by_name: 'Security Administrator',
  authorized_at: '2026-08-11T09:00:00Z',
}

describe('Signed Change Sets', () => {
  beforeEach(() => {
    session.userId = 'authorizer-1'
    session.role = 'admin'
    remediationChangeSets.mockReset().mockResolvedValue([pendingChangeSet])
    remediationCheckpointJobs.mockReset().mockResolvedValue([])
    remediationPlans.mockReset().mockResolvedValue([])
    remediationValidationJobs.mockReset().mockResolvedValue([])
    queueRemediationValidation.mockReset()
    queueRemediationCheckpoint.mockReset()
    authorizeRemediationChangeSet.mockReset()
    cancelRemediationChangeSet.mockReset()
    createRemediationChangeSet.mockReset()
  })

  it('keeps readiness, canary scope, integrity, and the non-execution boundary together', async () => {
    render(<MemoryRouter initialEntries={['/findings?view=change-sets']}><ChangeSetsPage /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Signed Change Sets' })).toBeInTheDocument()
    expect(screen.getByText('Signing Does Not Enable Execution')).toBeInTheDocument()
    expect(screen.getByRole('complementary', { name: /Change Set change-set-12345678 Dossier/ })).toBeInTheDocument()
    expect(screen.getByText('9 Of 9 Passed')).toBeInTheDocument()
    expect(screen.getByText('Production Linux · Monitor V4')).toBeInTheDocument()
    expect(screen.getByText('Payload Digest')).toBeInTheDocument()
    expect(screen.getByText('This release retains signed governance records and cannot dispatch agent work.')).toBeInTheDocument()
  })

  it('requires an independent administrator and shows the resulting signature', async () => {
    session.userId = 'requester-1'
    const view = render(<MemoryRouter><ChangeSetsPage /></MemoryRouter>)
    expect(await screen.findByRole('button', { name: 'Authorize And Sign' })).toBeDisabled()
    expect(screen.getByText('A Different Administrator Must Authorize.')).toBeInTheDocument()

    view.unmount()
    session.userId = 'authorizer-1'
    remediationChangeSets.mockResolvedValue([pendingChangeSet])
    authorizeRemediationChangeSet.mockImplementation(async () => {
      remediationChangeSets.mockResolvedValue([authorizedChangeSet])
      return authorizedChangeSet
    })
    render(<MemoryRouter><ChangeSetsPage /></MemoryRouter>)

    fireEvent.click(await screen.findByRole('button', { name: 'Authorize And Sign' }))
    await waitFor(() => expect(authorizeRemediationChangeSet).toHaveBeenCalledWith('change-set-12345678'))
    expect(await screen.findByText('Signature Verified')).toBeInTheDocument()
    expect(screen.getByText('SHA256:change-signing-key')).toBeInTheDocument()
  })

  it('queues one explicit read-only preflight and shows its signed workflow state', async () => {
    const queued: RemediationValidationJob = {
      id: 'validation-1', change_set_id: pendingChangeSet.id, host_id: 'host-1', agent_id: 'agent-1', status: 'queued',
      contract_digest: 'c'.repeat(64), contract: {}, requested_by: 'authorizer-1', requested_by_name: 'Security Administrator', requested_at: '2026-08-11T09:05:00Z',
      delivered_at: null, lease_expires_at: null, completed_at: null, receipt: null, receipt_signature: null, error: null,
      execution_enabled: false, changes_applied: false,
    }
    remediationChangeSets.mockResolvedValue([authorizedChangeSet])
    queueRemediationValidation.mockImplementation(async () => {
      remediationValidationJobs.mockResolvedValue([queued])
      return queued
    })
    render(<MemoryRouter><ChangeSetsPage /></MemoryRouter>)

    fireEvent.click(await screen.findByRole('button', { name: 'Run Read-Only Preflight' }))

    await waitFor(() => expect(queueRemediationValidation).toHaveBeenCalledWith('change-set-12345678', 'agent-1'))
    expect(await screen.findByText('Queued')).toBeInTheDocument()
    expect(screen.getByText('Checkpointing Cannot Change Host Configuration.')).toBeInTheDocument()
  })

  it('summarizes signed recovery readiness without adding another workflow', async () => {
    remediationChangeSets.mockResolvedValue([authorizedChangeSet])
    remediationValidationJobs.mockResolvedValue([{
      id: 'validation-ready', change_set_id: pendingChangeSet.id, host_id: 'host-1', agent_id: 'agent-1', status: 'ready',
      contract_digest: 'c'.repeat(64), contract: {}, requested_by: 'authorizer-1', requested_by_name: 'Security Administrator', requested_at: '2026-08-11T09:05:00Z',
      delivered_at: '2026-08-11T09:06:00Z', lease_expires_at: null, completed_at: '2026-08-11T09:07:00Z', receipt_signature: 'signed-receipt', error: null,
      execution_enabled: false, changes_applied: false,
      receipt: {
        schema_version: '1.0', kind: 'remediation-validation-receipt', validation_id: 'validation-ready', change_set_id: pendingChangeSet.id,
        contract_digest: 'c'.repeat(64), agent_id: 'agent-1', host_id: 'host-1', status: 'ready', evaluated_at: '2026-08-11T09:07:00Z',
        execution_enabled: false, changes_applied: false, agent_version: '0.10.0', agent_integrity_digest: `sha256:${'a'.repeat(64)}`,
        action_results: [{ plan_id: 'plan-1', action_digest: 'a'.repeat(64), status: 'ready', checks: [{ code: 'path', status: 'passed', detail: 'Reviewed path is ready' }] }],
        recovery_plan: {
          schema_version: '1.0', kind: 'remediation-recovery-plan', status: 'ready', backup_before_write: true, automatic_rollback_required: true,
          stop_on_failure: true, journal_state: 'planned', rollback_order: ['b'.repeat(64)], execution_enabled: false, changes_applied: false,
          entries: [{ checkpoint_id: 'b'.repeat(64), plan_id: 'plan-1', action_digest: 'a'.repeat(64), operation_index: 0, rollback_index: 0,
            path: '/etc/ssh/sshd_config.d/90-lsa-hardening.conf', source_state: 'absent', source_digest: null, size_bytes: null, mode: null,
            uid: null, gid: null, status: 'ready', detail: 'Absent source can be restored by removal', backup_created: false }],
        },
        error: null,
      },
    } satisfies RemediationValidationJob])
    const queuedCheckpoint: RemediationCheckpointJob = {
      id: 'checkpoint-1', change_set_id: pendingChangeSet.id, validation_job_id: 'validation-ready', host_id: 'host-1', agent_id: 'agent-1', status: 'queued',
      contract_digest: 'c'.repeat(64), requested_by: 'authorizer-1', requested_by_name: 'Security Administrator', requested_at: '2026-08-11T09:08:00Z',
      delivered_at: null, lease_expires_at: null, completed_at: null, receipt: null, receipt_signature: null, error: null, execution_enabled: false, changes_applied: false,
    }
    queueRemediationCheckpoint.mockImplementation(async () => {
      remediationCheckpointJobs.mockResolvedValue([queuedCheckpoint])
      return queuedCheckpoint
    })

    render(<MemoryRouter><ChangeSetsPage /></MemoryRouter>)

    expect(await screen.findByText(/1 Recovery Checkpoint Ready/)).toHaveTextContent('1 Of 1 Actions Ready')
    expect(screen.getByText(/No Changes Applied/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Prepare Encrypted Checkpoint' }))
    await waitFor(() => expect(queueRemediationCheckpoint).toHaveBeenCalledWith('change-set-12345678', 'validation-ready'))
    expect(await screen.findByText('Encrypted Checkpoint Is Being Prepared')).toBeInTheDocument()
  })

  it('closes preparation without submitting a change set', async () => {
    render(<MemoryRouter><ChangeSetsPage /></MemoryRouter>)
    await screen.findByText('Not Evaluated')
    fireEvent.click(await screen.findByRole('button', { name: 'Prepare Change Set' }))
    const dialog = screen.getByRole('dialog', { name: 'Prepare A Change Set' })

    fireEvent.click(within(dialog).getByRole('button', { name: 'Keep Reviewing' }))

    expect(createRemediationChangeSet).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog', { name: 'Prepare A Change Set' })).not.toBeInTheDocument()
  })
})
