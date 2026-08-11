import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { RemediationPlan } from '../types'
import { RemediationReviewPage } from './RemediationReviewPage'

const { approveRemediationPlan, cancelRemediationPlan, remediationPlans, rejectRemediationPlan, scrollIntoView, session } = vi.hoisted(() => ({
  approveRemediationPlan: vi.fn(),
  cancelRemediationPlan: vi.fn(),
  remediationPlans: vi.fn(),
  rejectRemediationPlan: vi.fn(),
  scrollIntoView: vi.fn(),
  session: { role: 'admin' },
}))

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Administrator', role: session.role } }),
}))

vi.mock('../api/client', () => ({
  api: { approveRemediationPlan, cancelRemediationPlan, remediationPlans, rejectRemediationPlan },
}))

const pendingPlan: RemediationPlan = {
  id: 'plan-1', finding_id: 'finding-1', host_id: 'host-1', hostname: 'web-01', report_id: 'report-1',
  control_id: 'CIS-DEBIAN13-5.1.1', title: 'Ensure SSH Root Login Is Disabled', category: 'ssh', severity: 'high',
  current_state: 'PermitRootLogin yes', required_state: 'PermitRootLogin no',
  remediation_summary: 'Disable direct root login after confirming administrative recovery access.',
  affected_paths: ['/etc/ssh/sshd_config'], reboot_required: false, service_restart: true,
  rationale: 'Reduce privileged remote access.', status: 'pending_approval', version: 1,
  requested_by: 'user-1', requested_by_name: 'Security Administrator', requested_at: '2026-08-08T10:00:00Z',
  approved_by: null, approved_by_name: null, approved_at: null,
  rejected_by: null, rejected_by_name: null, rejected_at: null, rejection_reason: null,
  canceled_by: null, canceled_by_name: null, canceled_at: null, cancellation_reason: null,
  source_is_current: true, finding_still_open: true, action_catalog_status: 'not_cataloged', action: null,
  execution_enabled: false, execution_status: 'not_supported',
  execution_reason: 'This release records review decisions only and cannot change hosts.',
  created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:00Z',
}

const matchedPlan: RemediationPlan = {
  ...pendingPlan,
  action_catalog_status: 'matched',
  action: {
    action_id: 'linux.ssh.permit-root-login.disabled', version: 1, digest: 'a'.repeat(64), status: 'reviewed',
    control_ids: ['CIS-DEBIAN13-5.1.21'], title: 'Disable Direct Root SSH Login',
    description: 'Set the effective OpenSSH PermitRootLogin value to no after alternate administrative access is confirmed.',
    supported_systems: [{ family: 'debian', versions: ['13'] }], risk: 'high',
    parameters: [{ name: 'desired_value', type: 'enum', required: true, default: 'no', allowed_values: ['no'], minimum: null, maximum: null, description: 'Reviewed target value.' }],
    preconditions: [{ kind: 'manual_confirmation', resource: 'alternate_administrative_access', expected: 'confirmed', failure_mode: 'stop', description: 'Confirm a tested sudo-capable account.' }],
    operations: [{ kind: 'config_setting', resource: 'openssh_server', path: '/etc/ssh/sshd_config.d/90-lsa-hardening.conf', format: 'sshd_config', key: 'PermitRootLogin', value_from: 'desired_value', backup_required: true }],
    validation: [{ kind: 'effective_setting', resource: 'openssh_server', key: 'permitrootlogin', expected: 'no' }],
    rollback: [{ kind: 'restore_backup', resource: 'openssh_server', path: '/etc/ssh/sshd_config.d/90-lsa-hardening.conf', format: null, key: null, value_from: null, backup_required: false }],
    impact: { service_restart: true, reboot_required: false, availability: 'brief_connection_risk', notes: 'Reload OpenSSH after validation.' },
    execution_enabled: false, execution_status: 'catalog_only',
  },
}

describe('Remediation Review', () => {
  beforeEach(() => {
    session.role = 'admin'
    remediationPlans.mockReset().mockResolvedValue([pendingPlan])
    approveRemediationPlan.mockReset().mockImplementation(async () => {
      const approved: RemediationPlan = {
        ...pendingPlan,
        status: 'approved',
        version: 2,
        approved_by: 'user-1',
        approved_by_name: 'Security Administrator',
        approved_at: '2026-08-08T10:05:00Z',
      }
      remediationPlans.mockResolvedValue([approved])
      return approved
    })
    rejectRemediationPlan.mockReset()
    cancelRemediationPlan.mockReset()
    scrollIntoView.mockReset()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: scrollIntoView })
    Object.defineProperty(window, 'matchMedia', { configurable: true, value: vi.fn((query: string) => ({ matches: query === '(max-width: 760px)' })) })
    Object.defineProperty(window, 'requestAnimationFrame', { configurable: true, value: (callback: FrameRequestCallback) => { callback(0); return 1 } })
  })

  it('keeps evidence, safety, and the approval decision in one review desk', async () => {
    render(<MemoryRouter initialEntries={['/findings?view=remediation']}><RemediationReviewPage /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Remediation Review' })).toBeInTheDocument()
    expect(screen.getByText('Review And Approval Are Non-Executable')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Remediation Plan Status' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Pending Decision Awaiting Review 1/ })).toHaveAttribute('aria-pressed', 'true')
    expect(await screen.findByRole('complementary', { name: /Ensure SSH Root Login Is Disabled Review Dossier/ })).toBeInTheDocument()
    expect(screen.getByText('PermitRootLogin yes')).toBeInTheDocument()
    expect(screen.getByText('PermitRootLogin no')).toBeInTheDocument()
    expect(screen.getByText('/etc/ssh/sshd_config')).toBeInTheDocument()
    expect(screen.getByText('Approval Records Intent Only')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Approve Plan' }))
    const dialog = screen.getByRole('dialog', { name: 'Approve Plan?' })
    expect(dialog).toHaveTextContent('does not execute commands or modify the host')
    expect(approveRemediationPlan).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve Plan' }))

    await waitFor(() => expect(approveRemediationPlan).toHaveBeenCalledWith('plan-1'))
    expect(await screen.findByText('Approved By Security Administrator')).toBeInTheDocument()
  })

  it('blocks stale approval and leaves non-administrators read only', async () => {
    session.role = 'analyst'
    remediationPlans.mockResolvedValueOnce([{ ...pendingPlan, source_is_current: false }])
    render(<MemoryRouter initialEntries={['/findings?view=remediation&plan=plan-1']}><RemediationReviewPage /></MemoryRouter>)

    expect(await screen.findByText('Source Evidence Is No Longer Current')).toBeInTheDocument()
    expect(screen.getByText('Your Role Can Review This Plan But Cannot Change Its Decision.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve Plan' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reject Stale Plan' })).not.toBeInTheDocument()
  })

  it('keeps the decision dialog open and explains an API failure', async () => {
    approveRemediationPlan.mockRejectedValueOnce(new Error('Approval Conflict: The Source Finding Changed.'))
    render(<MemoryRouter initialEntries={['/findings?view=remediation']}><RemediationReviewPage /></MemoryRouter>)

    await screen.findByRole('complementary', { name: /Ensure SSH Root Login Is Disabled Review Dossier/ })
    fireEvent.click(screen.getByRole('button', { name: 'Approve Plan' }))
    const dialog = screen.getByRole('dialog', { name: 'Approve Plan?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve Plan' }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Approval Conflict: The Source Finding Changed.')
    expect(screen.getByRole('dialog', { name: 'Approve Plan?' })).toBeInTheDocument()
  })

  it('reveals and focuses the dossier after mobile plan selection', async () => {
    render(<MemoryRouter initialEntries={['/findings?view=remediation']}><RemediationReviewPage /></MemoryRouter>)

    const dossier = await screen.findByRole('complementary', { name: /Ensure SSH Root Login Is Disabled Review Dossier/ })
    fireEvent.click(screen.getByRole('button', { name: /Ensure SSH Root Login Is Disabled web-01/ }))

    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'start' })
    expect(dossier).toHaveFocus()
  })

  it('shows matched declarative safeguards before the procedure details', async () => {
    remediationPlans.mockResolvedValueOnce([matchedPlan])
    render(<MemoryRouter initialEntries={['/findings?view=remediation']}><RemediationReviewPage /></MemoryRouter>)

    expect(await screen.findByText('Reviewed Declarative Action')).toBeInTheDocument()
    expect(screen.getByText('Catalog Only · Non-Executable')).toBeInTheDocument()
    expect(screen.getByText(`SHA-256 ${'a'.repeat(64)}`)).toBeInTheDocument()
    expect(screen.getByText('Stop Conditions')).toBeInTheDocument()
    expect(screen.getByText('Confirm a tested sudo-capable account.')).toBeInTheDocument()
    const procedure = screen.getByText('Review Structured Procedure').closest('details')
    expect(procedure).not.toHaveAttribute('open')

    fireEvent.click(screen.getByText('Review Structured Procedure'))
    expect(procedure).toHaveAttribute('open')
    const reviewedChange = screen.getByText('Reviewed Change').closest('section')
    expect(reviewedChange).not.toBeNull()
    expect(within(reviewedChange!).getByText('Config Setting')).toBeInTheDocument()
    expect(within(reviewedChange!).getByText(/Reviewed Parameter: desired_value/)).toHaveTextContent('/etc/ssh/sshd_config.d/90-lsa-hardening.conf')
    expect(screen.getByText('Validation')).toBeInTheDocument()
    expect(screen.getByText('Rollback')).toBeInTheDocument()
  })
})
