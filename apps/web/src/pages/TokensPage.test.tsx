import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { TokensPage } from './TokensPage'

vi.mock('../api/client', () => ({
  api: {
    hosts: vi.fn(),
    revokeToken: vi.fn(),
    tokens: vi.fn(),
  },
}))

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Admin', role: 'admin' } }),
}))

const token = {
  id: 'token-1',
  name: 'Debian production scanner',
  host_id: 'host-1',
  token_prefix: 'lsa_ingest_example',
  expires_at: '2099-01-01T00:00:00Z',
  last_used_at: '2026-08-02T08:30:00Z',
  revoked_at: null,
  created_at: '2026-08-01T08:30:00Z',
}

describe('TokensPage', () => {
  beforeEach(() => {
    vi.mocked(api.tokens).mockResolvedValue([token])
    vi.mocked(api.hosts).mockResolvedValue([{
      id: 'host-1',
      hostname: 'edge-prod-07',
      fqdn: 'edge-prod-07.example.test',
      operating_system: 'Debian GNU/Linux',
      os_family: 'debian',
      os_version: '13',
      kernel: '6.12.0',
      architecture: 'x86_64',
      ip_addresses: ['10.44.7.18'],
      tags: { environment: 'production' },
      compliance_score: 91.3,
      security_score: 87.6,
      last_scan_at: '2026-08-02T08:30:00Z',
      finding_counts: { critical: 0, high: 1, medium: 2, low: 1, info: 0 },
    }])
    vi.mocked(api.revokeToken).mockResolvedValue()
  })

  it('shows token scope and confirms revocation', async () => {
    render(<TokensPage />)
    expect(await screen.findByText('Debian production scanner')).toBeInTheDocument()
    expect(screen.getByText('edge-prod-07')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Revoke Debian production scanner' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(api.revokeToken).toHaveBeenCalledWith('token-1'))
  })
})
