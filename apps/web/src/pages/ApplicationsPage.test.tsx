import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { ApplicationsPage } from './ApplicationsPage'

vi.mock('../api/client', () => ({
  api: {
    applicationEstate: vi.fn().mockResolvedValue({
      metrics: { unique_applications: 2, package_count: 1, service_count: 1, installation_count: 3, reporting_hosts: 2, version_drift_count: 1 },
      applications: [
        { kind: 'package', name: 'openssl', source: 'dpkg', publisher: 'Debian', description: 'TLS toolkit', host_count: 2, version_count: 2, running_host_count: 0, enabled_host_count: 0, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
        { kind: 'service', name: 'ssh.service', source: 'systemd', publisher: null, description: 'OpenSSH daemon', host_count: 1, version_count: 0, running_host_count: 1, enabled_host_count: 1, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
      ],
    }),
    applicationCorrelation: vi.fn().mockResolvedValue([
      { application_id: 'app-1', host_id: 'host-1', hostname: 'web-01', fqdn: 'web-01.example.test', os_family: 'debian', os_version: '13', environment: 'production', security_score: 84, compliance_score: 91, version: '3.0.14-1', architecture: 'amd64', status: 'installed', enabled: null, running: null, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
      { application_id: 'app-2', host_id: 'host-2', hostname: 'db-02', fqdn: 'db-02.example.test', os_family: 'debian', os_version: '13', environment: 'production', security_score: 72, compliance_score: 86, version: '3.0.15-1', architecture: 'amd64', status: 'installed', enabled: null, running: null, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z' },
    ]),
  },
}))

describe('ApplicationsPage', () => {
  it('summarizes software and correlates versions with affected hosts', async () => {
    render(<MemoryRouter><ApplicationsPage /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Applications' })).toBeInTheDocument()
    expect(screen.getByText('3', { selector: '.metric-value' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /openssl/ })).toBeInTheDocument()
    expect(screen.getByText('2 observed versions')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /openssl/ }))

    expect(await screen.findByRole('heading', { name: 'openssl' })).toBeInTheDocument()
    expect(screen.getByText('3.0.14-1')).toBeInTheDocument()
    expect(screen.getByText('3.0.15-1')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /web-01/ })).toHaveAttribute('href', '/hosts/host-1')
    expect(screen.getByRole('link', { name: /db-02/ })).toHaveAttribute('href', '/hosts/host-2')
  })
})
