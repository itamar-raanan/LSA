import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, vi } from 'vitest'
import App from './App'
import { AuthProvider } from './auth/AuthContext'

describe('App', () => {
  beforeEach(() => localStorage.clear())
  afterEach(() => vi.unstubAllGlobals())

  it('shows the authentication screen for signed-out users', async () => {
    render(<MemoryRouter initialEntries={['/']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'Access the console' })).toBeInTheDocument()
    expect(await screen.findByText(/No organization identity provider is enabled/)).toBeInTheDocument()
  })

  it('clears a rejected stored session and returns to login', async () => {
    localStorage.setItem('lsa_session', 'stale-session')
    localStorage.setItem('lsa_user', JSON.stringify({ id: 'user-1', email: 'admin@lsa.local', name: 'Admin', role: 'admin' }))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ detail: 'Invalid session' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )))

    render(<MemoryRouter initialEntries={['/']}><AuthProvider><App /></AuthProvider></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: 'Access the console' })).toBeInTheDocument()
    expect(screen.getByText('Your session ended. Sign in again to continue.')).toBeInTheDocument()
    expect(localStorage.getItem('lsa_session')).toBeNull()
    expect(localStorage.getItem('lsa_user')).toBeNull()
  })
})
