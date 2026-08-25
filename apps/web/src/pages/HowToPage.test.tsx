import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext'
import { HowToPage } from './HowToPage'

describe('HowToPage', () => {
  beforeEach(() => localStorage.clear())

  it('explains both collection workflows and the audit-only boundary', () => {
    localStorage.setItem('lsa_session', 'test-session')
    localStorage.setItem('lsa_user', JSON.stringify({ id: 'user-1', email: 'admin@example.test', name: 'SecOps Admin', role: 'admin' }))
    render(<MemoryRouter><AuthProvider><HowToPage /></AuthProvider></MemoryRouter>)

    expect(screen.getByRole('heading', { name: 'How To Use LSA' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Offline Ansible Report' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Managed Linux Agent' })).toBeInTheDocument()
    expect(screen.getByText(/outbound TCP 8444/i)).toBeInTheDocument()
    expect(screen.getByText(/LSA is audit-only today/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Open Evidence Intake/i })).toHaveAttribute('href', '/evidence')
    expect(screen.getByRole('link', { name: /Open Agents & Groups/i })).toHaveAttribute('href', '/agents')
  })

  it('hands administrator-only setup steps to an administrator for analysts', () => {
    localStorage.setItem('lsa_session', 'test-session')
    localStorage.setItem('lsa_user', JSON.stringify({ id: 'user-2', email: 'analyst@example.test', name: 'SOC Analyst', role: 'analyst' }))
    render(<MemoryRouter><AuthProvider><HowToPage /></AuthProvider></MemoryRouter>)

    expect(screen.getByText(/Ask an administrator to enroll the host and issue a host-scoped ingestion token/i)).toBeInTheDocument()
    expect(screen.getByText('Ask An Administrator To Enroll Or Move Agents')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Open Agents & Groups/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open Administration' })).not.toBeInTheDocument()
  })
})
