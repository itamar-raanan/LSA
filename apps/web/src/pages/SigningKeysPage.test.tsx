import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { SigningKeysPage } from './SigningKeysPage'

vi.mock('../api/client', () => ({
  api: {
    hosts: vi.fn(),
    revokeSigningKey: vi.fn(),
    signingKeys: vi.fn(),
  },
}))

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Admin', role: 'admin' } }),
}))

describe('SigningKeysPage', () => {
  beforeEach(() => {
    vi.mocked(api.signingKeys).mockResolvedValue([{
      id: 'key-1',
      name: 'Debian production signer',
      host_id: 'host-1',
      public_key: 'example',
      fingerprint: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      expires_at: '2099-01-01T00:00:00Z',
      revoked_at: null,
      created_at: '2026-08-02T08:30:00Z',
    }])
    vi.mocked(api.hosts).mockResolvedValue([{
      id: 'host-1', hostname: 'edge-prod-07', fqdn: null, operating_system: 'Debian GNU/Linux',
      os_family: 'debian', os_version: '13', kernel: '6.12.0', architecture: 'x86_64',
      ip_addresses: [], tags: {}, compliance_score: 91, security_score: 88,
      last_scan_at: '2026-08-02T08:30:00Z',
      finding_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    }])
    vi.mocked(api.revokeSigningKey).mockResolvedValue()
  })

  it('shows trust scope and confirms revocation', async () => {
    render(<SigningKeysPage />)
    expect(await screen.findByText('Debian production signer')).toBeInTheDocument()
    expect(screen.getByText('edge-prod-07')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Revoke Debian production signer' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(api.revokeSigningKey).toHaveBeenCalledWith('key-1'))
  })
})
