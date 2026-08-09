import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthContext } from '../auth/context'
import { ApplicationsPage } from './ApplicationsPage'

const { applicationEstatePage } = vi.hoisted(() => ({ applicationEstatePage: vi.fn() }))

applicationEstatePage.mockResolvedValue({
  data: {
    metrics: { unique_applications: 2, package_count: 1, service_count: 1, installation_count: 3, reporting_hosts: 2, version_drift_count: 1 },
    applications: [
      { kind: 'package', name: 'openssl', source: 'dpkg', publisher: 'Debian', description: 'TLS toolkit', host_count: 2, version_count: 2, running_host_count: 0, enabled_host_count: 0, vulnerability_count: 1, known_exploited_count: 1, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
      { kind: 'service', name: 'ssh.service', source: 'systemd', publisher: null, description: 'OpenSSH daemon', host_count: 1, version_count: 0, running_host_count: 1, enabled_host_count: 1, vulnerability_count: 0, known_exploited_count: 0, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
    ],
  },
  total: 2,
  page: 0,
  pageSize: 10,
})

vi.mock('../api/client', () => ({
  api: {
    applicationEstatePage,
    applicationCorrelation: vi.fn().mockResolvedValue([
      { application_id: 'app-1', host_id: 'host-1', hostname: 'web-01', fqdn: 'web-01.example.test', os_family: 'debian', os_version: '13', environment: 'production', security_score: 84, compliance_score: 91, version: '3.0.14-1', architecture: 'amd64', status: 'installed', enabled: null, running: null, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
      { application_id: 'app-2', host_id: 'host-2', hostname: 'db-02', fqdn: 'db-02.example.test', os_family: 'debian', os_version: '13', environment: 'production', security_score: 72, compliance_score: 86, version: '3.0.15-1', architecture: 'amd64', status: 'installed', enabled: null, running: null, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
    ]),
    vulnerabilitySummary: vi.fn().mockResolvedValue({ vulnerability_count: 1, exposure_count: 1, affected_hosts: 1, affected_applications: 1, known_exploited: 1, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 }, intelligence_state: 'fresh', last_sync: { id: 'sync-1', status: 'succeeded', trigger: 'scheduled', packages_queried: 2, vulnerabilities_found: 1, matches_found: 1, error: null, started_at: '2026-08-01T00:00:00Z', completed_at: '2026-08-01T00:01:00Z', created_at: '2026-08-01T00:00:00Z' } }),
    applicationVulnerabilities: vi.fn().mockResolvedValue([
      { id: 'DSA-9999-1', cve_id: 'CVE-2026-1234', aliases: ['CVE-2026-1234'], summary: 'OpenSSL memory safety issue', severity: 'high', cvss_score: 8.1, known_exploited: true, fixed_versions: ['3.0.15-1'], affected_hosts: 1, affected_host_ids: ['host-1'], affected_versions: ['3.0.14-1'], kev_due_date: '2026-08-15T00:00:00Z', kev_required_action: 'Apply vendor updates.', ransomware_use: 'Known', published_at: '2026-07-01T00:00:00Z', modified_at: '2026-08-01T00:00:00Z', references: [{ url: 'https://example.test/advisory' }] },
    ]),
  },
}))

describe('ApplicationsPage', () => {
  const auth = { user: { id: 'user-1', email: 'admin@example.test', name: 'Admin', role: 'admin' as const }, login: vi.fn(), radiusLogin: vi.fn(), acceptSession: vi.fn(), logout: vi.fn() }

  it('summarizes software and correlates versions with affected hosts', async () => {
    render(<AuthContext.Provider value={auth}><MemoryRouter initialEntries={['/applications?risk=kev&page=2']}><ApplicationsPage /></MemoryRouter></AuthContext.Provider>)

    expect(await screen.findByRole('heading', { name: 'Applications' })).toBeInTheDocument()
    expect(screen.getByText('Unique Applications')).toBeInTheDocument()
    expect(screen.getByText('Active Exposures')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Application Inventory' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /openssl/ })).toBeInTheDocument()
    expect(screen.getByText('2 Observed Versions')).toBeInTheDocument()

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /openssl/ })) })

    expect(await screen.findByRole('complementary', { name: 'openssl investigation' })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'openssl' })).toBeInTheDocument()
    expect(screen.getByText('3.0.14-1')).toBeInTheDocument()
    expect(screen.getByText('3.0.15-1')).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument()
    expect(screen.getAllByText('Known Exploited', { selector: '.kev-badge' })).toHaveLength(2)
    expect(screen.getByRole('link', { name: /web-01/ })).toHaveAttribute('href', expect.stringContaining('/hosts/host-1?return_to='))
    expect(decodeURIComponent(screen.getByRole('link', { name: /web-01/ }).getAttribute('href') ?? '')).toContain('/applications?risk=kev&page=2&application=package%3Adpkg%3Aopenssl')
    expect(screen.getByRole('link', { name: /db-02/ })).toHaveAttribute('href', expect.stringContaining('/hosts/host-2?return_to='))

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /CVE-2026-1234/ })) })
    expect(screen.getByRole('link', { name: /web-01/ })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /db-02/ })).not.toBeInTheDocument()

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Close application investigation' })) })
    await waitFor(() => expect(screen.queryByRole('complementary', { name: 'openssl investigation' })).not.toBeInTheDocument())

    applicationEstatePage.mockResolvedValueOnce({
      data: {
        metrics: { unique_applications: 2, package_count: 1, service_count: 1, installation_count: 3, reporting_hosts: 2, version_drift_count: 1 },
        applications: [{ kind: 'package', name: 'openssl', source: 'dpkg', publisher: 'Debian', description: 'TLS toolkit', host_count: 2, version_count: 2, running_host_count: 0, enabled_host_count: 0, vulnerability_count: 1, known_exploited_count: 1, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' }],
      },
      total: 1,
      page: 0,
      pageSize: 10,
    })
    await act(async () => { fireEvent.change(screen.getByRole('combobox', { name: 'Filter Application Risk' }), { target: { value: 'kev' } }) })
    await waitFor(() => expect(screen.queryByRole('button', { name: /ssh\.service/ })).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: /openssl/ })).toBeInTheDocument()
  })

  it('restores search and investigation context from a console deep link', async () => {
    applicationEstatePage.mockClear()
    render(<AuthContext.Provider value={auth}><MemoryRouter initialEntries={['/applications?search=openssl&application=package%3Adpkg%3Aopenssl']}><ApplicationsPage /></MemoryRouter></AuthContext.Provider>)

    expect(await screen.findByRole('complementary', { name: 'openssl investigation' })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Search table' })).toHaveValue('openssl')
    await waitFor(() => expect(applicationEstatePage).toHaveBeenCalledWith(expect.objectContaining({ search: 'openssl', kind: '', page: 0, pageSize: 10 })))
  })
})
