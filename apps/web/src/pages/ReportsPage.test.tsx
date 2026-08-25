import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { ReportsPage } from './ReportsPage'

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Admin', role: 'admin' } }),
}))

vi.mock('../api/client', () => ({ api: {
  uploadBundle: vi.fn(),
  offlineScannerPackage: vi.fn().mockResolvedValue({ version: '0.6.1', filename: 'lsa-offline-scanner-0.6.1.zip', size_bytes: 102400, sha256: 'a'.repeat(64), audit_only: true }),
  downloadOfflineScannerPackage: vi.fn(),
} }))

describe('Evidence Intake', () => {
  it('guides the complete offline workflow and links to trust setup', async () => {
    render(<MemoryRouter><ReportsPage /></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'Evidence Intake' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Download Offline Scanner' })).toBeInTheDocument()
    expect(await screen.findByText('Scanner 0.6.1 · 100 KB')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Create Ingestion Token/ })).toHaveAttribute('href', '/settings/credentials?view=tokens&action=create')
    expect(screen.getByRole('link', { name: /Open Signing Keys/ })).toHaveAttribute('href', '/settings/credentials?view=signing-keys')
    expect(screen.getByText(/generate_signing_key.py/)).toBeInTheDocument()
    expect(screen.getByText(/run-offline.sh --ask-become-pass/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Choose or drop lsa-report/ })).toBeInTheDocument()
    expect(screen.getByText(/No credentials or private keys are included/)).toBeInTheDocument()
  })
})
