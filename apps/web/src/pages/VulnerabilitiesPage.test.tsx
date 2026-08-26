import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthContext } from '../auth/context'
import { VulnerabilitiesPage } from './VulnerabilitiesPage'

const { vulnerabilityPage } = vi.hoisted(() => ({ vulnerabilityPage: vi.fn() }))

const vulnerability = {
  id: 'DSA-9999-1', cve_id: 'CVE-2026-1234', aliases: ['DSA-9999-1', 'CVE-2026-1234'], summary: 'OpenSSL memory safety issue', severity: 'high', cvss_score: 8.1, known_exploited: true, fixed_versions: ['3.0.15-1'], affected_hosts: 1, affected_host_ids: ['host-1'], affected_versions: ['3.0.14-1'], kev_due_date: '2026-08-15T00:00:00Z', kev_required_action: 'Apply vendor updates.', ransomware_use: 'Known', published_at: '2026-07-01T00:00:00Z', modified_at: '2026-08-01T00:00:00Z', references: [{ url: 'https://example.test/advisory' }], exposure_count: 1, affected_applications: 1, application_names: ['openssl'],
}

vulnerabilityPage.mockResolvedValue({ rows: [vulnerability], total: 1, page: 0, pageSize: 15 })

vi.mock('../api/client', () => ({ api: {
  vulnerabilitySummary: vi.fn().mockResolvedValue({ vulnerability_count: 1, exposure_count: 1, affected_hosts: 1, affected_applications: 1, known_exploited: 1, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 }, intelligence_state: 'fresh', last_sync: { id: 'sync-1', status: 'succeeded', trigger: 'offline', packages_queried: 1, vulnerabilities_found: 1, matches_found: 1, error: null, started_at: '2026-08-01T00:00:00Z', completed_at: '2026-08-01T00:01:00Z', created_at: '2026-08-01T00:00:00Z' } }),
  vulnerabilityPage,
  vulnerabilityExposures: vi.fn().mockResolvedValue([{ id: 'exposure-1', host_id: 'host-1', hostname: 'web-01', os_family: 'debian', os_version: '13', environment: 'production', application_id: 'app-1', application_name: 'openssl', application_source: 'dpkg', installed_version: '3.0.14-1', fixed_versions: ['3.0.15-1'], detected_at: '2026-08-01T00:00:00Z', last_seen_at: '2026-08-02T00:00:00Z' }]),
  queueVulnerabilitySync: vi.fn(),
  importVulnerabilitySnapshot: vi.fn(),
} }))

describe('VulnerabilitiesPage', () => {
  const auth = { user: { id: 'user-1', email: 'admin@example.test', name: 'Admin', role: 'admin' as const }, login: vi.fn(), radiusLogin: vi.fn(), acceptSession: vi.fn(), logout: vi.fn() }

  it('prioritizes severity, exploitation, impact, fixes, and affected hosts', async () => {
    render(<AuthContext.Provider value={auth}><MemoryRouter initialEntries={['/vulnerabilities']}><VulnerabilitiesPage /></MemoryRouter></AuthContext.Provider>)

    expect(await screen.findByRole('heading', { name: 'Vulnerabilities' })).toBeInTheDocument()
    expect(screen.getByText('Active CVEs')).toBeInTheDocument()
    expect(screen.getByText('Critical And High')).toBeInTheDocument()
    expect(screen.getAllByText('Known Exploited', { selector: '.kev-badge' })).toHaveLength(2)
    const table = screen.getByRole('table', { name: 'Vulnerability Queue' })
    expect(within(table).getByText('CVSS 8.1')).toBeInTheDocument()
    expect(within(table).getByText('Fix Reported')).toBeInTheDocument()

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Investigate CVE-2026-1234' })) })
    const panel = await screen.findByRole('complementary', { name: 'CVE-2026-1234 vulnerability investigation' })
    expect(within(panel).getByText('Apply vendor updates.')).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: /web-01/ })).toHaveAttribute('href', expect.stringContaining('/hosts/host-1?return_to='))
    expect(within(panel).getByRole('link', { name: /openssl/ })).toHaveAttribute('href', '/applications?search=openssl')
    expect(within(panel).getByRole('link', { name: /Open Source Advisory/ })).toHaveAttribute('href', 'https://example.test/advisory')
  })

  it('keeps severity and exploitation filters in server-backed URL state', async () => {
    vulnerabilityPage.mockClear()
    render(<AuthContext.Provider value={auth}><MemoryRouter initialEntries={['/vulnerabilities']}><VulnerabilitiesPage /></MemoryRouter></AuthContext.Provider>)
    await screen.findByRole('table', { name: 'Vulnerability Queue' })

    fireEvent.change(screen.getByRole('combobox', { name: 'Filter Vulnerability Severity' }), { target: { value: 'high' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter Exploitation Status' }), { target: { value: 'kev' } })
    await waitFor(() => expect(vulnerabilityPage).toHaveBeenLastCalledWith(expect.objectContaining({ severity: 'high', knownExploited: true, page: 0, pageSize: 15 })))
  })
})
