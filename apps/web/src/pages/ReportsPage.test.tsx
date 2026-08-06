import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { ReportsPage } from './ReportsPage'

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@lsa.local', name: 'Security Admin', role: 'admin' } }),
}))

vi.mock('../api/client', () => ({ api: { uploadBundle: vi.fn() } }))

describe('Evidence Intake', () => {
  it('explains the credential prerequisite and links to token creation', () => {
    render(<MemoryRouter><ReportsPage /></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'Evidence Intake' })).toBeInTheDocument()
    expect(screen.getByText('An Ingestion Token Is Required')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Create Ingestion Token/ })).toHaveAttribute('href', '/settings/credentials?view=tokens&action=create')
    expect(screen.getByRole('button', { name: /Choose or drop a report bundle/ })).toBeInTheDocument()
  })
})
