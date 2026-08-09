import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DashboardPage } from './DashboardPage'

const host = {
  id: 'host-1', hostname: 'web-01', fqdn: 'web-01.example.test', operating_system: 'Debian', os_family: 'debian', os_version: '13', kernel: '6.12', architecture: 'x86_64', ip_addresses: ['10.0.0.10'], tags: { environment: 'production' }, compliance_score: 71, security_score: 63, last_scan_at: '2026-08-06T12:00:00Z', finding_counts: { critical: 2, high: 3, medium: 4, low: 1, info: 0 },
}

const finding = {
  id: 'finding-1', host_id: host.id, hostname: host.hostname, report_id: 'report-1', control_id: 'LSA-SSH-1', module: 'cis', category: 'ssh', title: 'Disable Root Login', severity: 'critical', status: 'fail', lifecycle: 'new', expected: 'PermitRootLogin no', actual: 'PermitRootLogin yes', remediation_summary: 'Disable direct root SSH access.', remediation_commands: [], verification_commands: [], reboot_required: false, service_restart: true,
}

const apiMock = vi.hoisted(() => ({ dashboard: vi.fn(), hostPage: vi.fn(), findingPage: vi.fn() }))

vi.mock('../api/client', () => ({ api: apiMock }))
vi.mock('../components/security/DashboardChart', () => ({ default: () => <div data-testid="dashboard-chart" /> }))

describe('DashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiMock.dashboard.mockResolvedValue({
      total_hosts: 4,
      healthy_hosts: 1,
      at_risk_hosts: 3,
      critical_hosts: 1,
      stale_hosts: 1,
      overall_security_score: 72.4,
      compliance_score: 81.6,
      finding_counts: { critical: 2, high: 3, medium: 4, low: 1, info: 0 },
      os_distribution: { Debian: 4 },
      highest_risk_hosts: [host],
    })
    apiMock.hostPage.mockResolvedValue({ rows: [host], total: 1, page: 0, pageSize: 6 })
    apiMock.findingPage.mockImplementation(({ severity }) => Promise.resolve({ rows: severity === 'critical' ? [finding] : [], total: severity === 'critical' ? 1 : 0, page: 0, pageSize: 7 }))
  })

  it('turns urgent posture into direct investigation paths', async () => {
    render(<MemoryRouter><DashboardPage /></MemoryRouter>)

    expect(await screen.findByText('Highest Risk Hosts')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Security Overview' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Critical Findings: 2' })).toHaveAttribute('href', '/findings?severity=critical')
    expect(screen.getByRole('link', { name: 'Affected Assets: 3' })).toHaveAttribute('href', '/hosts?risk=critical')
    expect(screen.getByRole('link', { name: 'Stale Reports: 1' })).toHaveAttribute('href', '/hosts?risk=stale')
    expect(screen.getByRole('link', { name: 'Compliance Score: 81.6%' })).toHaveAttribute('href', '/hosts')
    expect(screen.getByRole('link', { name: 'Disable Root Login' })).toHaveAttribute('href', '/findings?category=ssh&finding=finding-1')
    expect(screen.getAllByRole('link', { name: /web-01/i })[0]).toHaveAttribute('href', '/hosts/host-1?return_to=%2F')
    expect(screen.getByRole('region', { name: 'Dashboard Data Context' })).toHaveTextContent('Latest Accepted Posture')
    expect(apiMock.hostPage).toHaveBeenCalledWith({ page: 0, pageSize: 6, sort: 'last_seen', direction: 'desc' })
    expect(apiMock.findingPage).toHaveBeenCalledTimes(2)
    expect(apiMock.findingPage).toHaveBeenCalledWith({ severity: 'critical', page: 0, pageSize: 7, sort: 'lifecycle', direction: 'asc' })
    expect(await screen.findByTestId('dashboard-chart')).toBeInTheDocument()
  })
})
