import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { AuthProvider } from './auth/AuthContext'

describe('App', () => {
  beforeEach(() => localStorage.clear())

  it('shows the authentication screen for signed-out users', async () => {
    render(<MemoryRouter initialEntries={['/']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'Access the console' })).toBeInTheDocument()
    expect(await screen.findByText(/No organization identity provider is enabled/)).toBeInTheDocument()
  })
})
