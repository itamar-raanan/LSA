import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { FindingsPage } from './FindingsPage'
import { HostsPage } from './HostsPage'
import { HostDetailPage } from './HostDetailPage'

const host = {
  id: 'host-1', hostname: 'web-01', fqdn: 'web-01.example.com', operating_system: 'Debian', os_family: 'debian', os_version: '13', kernel: '6.12', architecture: 'x86_64', ip_addresses: ['10.0.0.10'], tags: {}, compliance_score: 91, security_score: 88, last_scan_at: '2026-08-01T12:00:00Z', finding_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, system_info: { cpu_model: 'Xeon Test', cpu_cores: 4, memory_mb: 8192, uptime_seconds: 90000, virtualization_type: 'kvm', virtualization_role: 'guest', system_vendor: 'QEMU', product_name: 'Standard PC', timezone: 'UTC' },
}

const finding = {
  id: 'finding-1', host_id: host.id, hostname: host.hostname, report_id: 'report-1', control_id: 'LSA-SSH-1', module: 'cis', category: 'ssh', title: 'Disable root login', severity: 'high', status: 'fail', lifecycle: 'new', expected: 'PermitRootLogin no', actual: 'PermitRootLogin yes in /etc/ssh/sshd_config', remediation_summary: 'Disable direct root SSH access after confirming sudo access for an administrative account.', remediation_commands: ["printf '%s\\n' 'PermitRootLogin no' > /etc/ssh/sshd_config.d/10-lsa-root-login.conf", 'systemctl reload ssh'], verification_commands: ['sshd -T | grep ^permitrootlogin'], reboot_required: false, service_restart: true,
}

const apiMock = vi.hoisted(() => ({
  hosts: vi.fn(),
  findings: vi.fn(),
  deleteHost: vi.fn(),
  host: vi.fn(),
  applications: vi.fn(),
  reports: vi.fn(),
}))

vi.mock('../api/client', () => ({ api: apiMock, ApiError: class ApiError extends Error {} }))
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ user: { id: 'admin', role: 'admin' } }) }))

function renderFindings(initialEntry = '/findings') {
  return render(<MemoryRouter initialEntries={[initialEntry]}><FindingsPage /></MemoryRouter>)
}

describe('Fleet console experience', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiMock.hosts.mockResolvedValue([host])
    apiMock.findings.mockResolvedValue([finding])
    apiMock.deleteHost.mockResolvedValue(undefined)
    apiMock.host.mockResolvedValue({ ...host, application_count: 2 })
    apiMock.applications.mockResolvedValue([
      { id: 'app-1', host_id: host.id, kind: 'package', name: 'openssl', version: '3.0.14-1', architecture: 'amd64', source: 'dpkg', publisher: null, description: null, status: 'installed', enabled: null, running: null, first_seen_at: '2026-08-01T12:00:00Z', last_seen_at: '2026-08-01T12:00:00Z', removed_at: null },
      { id: 'app-2', host_id: host.id, kind: 'service', name: 'ssh.service', version: null, architecture: null, source: 'systemd', publisher: null, description: 'OpenSSH server', status: 'active', enabled: true, running: true, first_seen_at: '2026-08-01T12:00:00Z', last_seen_at: '2026-08-01T12:00:00Z', removed_at: null },
    ])
    apiMock.reports.mockResolvedValue([])
  })

  it('opens the bottom-right host card with scanner OS inventory', async () => {
    render(<MemoryRouter><HostsPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'web-01' }))
    const hostCard = screen.getByRole('complementary', { name: 'web-01 details' })
    expect(hostCard).toBeInTheDocument()
    expect(hostCard.parentElement).toBe(document.body)
    expect(screen.getByText('Xeon Test')).toBeInTheDocument()
    expect(screen.getByText(/QEMU/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete host' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Close host details' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Minimize host details' }))
    expect(screen.queryByText('Xeon Test')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Restore web-01 details' }))
    expect(screen.getByText('Xeon Test')).toBeInTheDocument()
  })

  it('shows all 12 categories before revealing category findings', async () => {
    renderFindings()
    expect(await screen.findByRole('button', { name: /Mandatory Access/i })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { pressed: false })).toHaveLength(12)
    expect(screen.queryByText('Disable root login')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /SSH/ }))
    expect(screen.getByText('Disable root login')).toBeInTheDocument()
  })

  it('presents remediation as a current-to-required operator guide', async () => {
    renderFindings()
    fireEvent.click(await screen.findByRole('button', { name: /SSH/ }))
    fireEvent.click(screen.getByRole('button', { name: /Disable root login/ }))
    expect(screen.getByRole('complementary', { name: 'Disable root login details' })).toBeInTheDocument()
    expect(screen.getByText('Current State')).toBeInTheDocument()
    expect(screen.getByText('Required State')).toBeInTheDocument()
    expect(screen.getByText('Why This Setting Is Used')).toBeInTheDocument()
    expect(screen.getByText('/etc/ssh/sshd_config')).toBeInTheDocument()
    expect(screen.getByText('Apply Step 1')).toBeInTheDocument()
    expect(screen.getByText('Verify Step 1')).toBeInTheDocument()
    expect(screen.getByText('A service restart is required and may interrupt active sessions.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Close finding details' }))
    expect(screen.queryByRole('complementary', { name: 'Disable root login details' })).not.toBeInTheDocument()
  })

  it('restores finding and host investigation context from dashboard links', async () => {
    const findingView = renderFindings('/findings?category=ssh&finding=finding-1')
    expect(await screen.findByRole('complementary', { name: 'Disable root login details' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'SSH Findings' })).toBeInTheDocument()
    findingView.unmount()

    render(<MemoryRouter initialEntries={['/hosts?host=host-1']}><HostsPage /></MemoryRouter>)
    expect(await screen.findByRole('complementary', { name: 'web-01 details' })).toBeInTheDocument()
  })

  it('searches and filters a category queue without hiding the category catalog', async () => {
    apiMock.findings.mockResolvedValueOnce([finding, {
      ...finding,
      id: 'finding-2',
      control_id: 'LSA-SSH-2',
      title: 'Disable weak SSH ciphers',
      severity: 'critical',
      lifecycle: 'persistent',
      actual: 'aes128-cbc enabled',
    }])
    renderFindings()

    fireEvent.click(await screen.findByRole('button', { name: /SSH/ }))
    expect(screen.getByRole('table', { name: 'SSH Findings' })).toBeInTheDocument()
    expect(screen.getByText('Disable root login')).toBeInTheDocument()
    expect(screen.getByText('Disable weak SSH ciphers')).toBeInTheDocument()

    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by severity' }), { target: { value: 'critical' } })
    expect(screen.queryByText('Disable root login')).not.toBeInTheDocument()
    expect(screen.getByText('Disable weak SSH ciphers')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Accounts/ })).toBeInTheDocument()
  })

  it('shows searchable package and service inventory on the host record', async () => {
    render(<MemoryRouter initialEntries={['/hosts/host-1']}><Routes><Route path="/hosts/:hostId" element={<HostDetailPage />} /></Routes></MemoryRouter>)
    expect(await screen.findByText('openssl')).toBeInTheDocument()
    expect(screen.getByText('ssh.service')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Packages 1' })).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('Search name, version, publisher, or description'), { target: { value: 'openssl' } })
    expect(screen.getByText('openssl')).toBeInTheDocument()
    expect(screen.queryByText('ssh.service')).not.toBeInTheDocument()
  })
})
