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
  id: 'finding-1', host_id: host.id, hostname: host.hostname, report_id: 'report-1', control_id: 'LSA-SSH-1', module: 'cis', category: 'ssh', title: 'Disable root login', severity: 'high', status: 'fail', lifecycle: 'new', expected: 'no', actual: 'yes', remediation_summary: 'Disable it.', remediation_commands: [], reboot_required: false,
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
    render(<FindingsPage />)
    expect(await screen.findByRole('button', { name: /Mandatory access/ })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { pressed: false })).toHaveLength(12)
    expect(screen.queryByText('Disable root login')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /SSH/ }))
    expect(screen.getByText('Disable root login')).toBeInTheDocument()
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
