import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CommandPalette } from './CommandPalette'

const apiMock = vi.hoisted(() => ({ hostPage: vi.fn(), applicationEstatePage: vi.fn(), findingPage: vi.fn() }))

vi.mock('../api/client', () => ({ api: apiMock }))
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ user: { id: 'user-1', role: 'analyst' } }) }))

function LocationState() {
  return <output data-testid="location">{useLocation().pathname}{useLocation().search}</output>
}

describe('CommandPalette', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiMock.hostPage.mockResolvedValue({ rows: [{ id: 'host-1', hostname: 'web-01', operating_system: 'Debian', os_version: '13', ip_addresses: ['10.0.0.10'] }], total: 1, page: 0, pageSize: 4 })
    apiMock.applicationEstatePage.mockResolvedValue({ data: { metrics: {}, applications: [] }, total: 0, page: 0, pageSize: 4 })
    apiMock.findingPage.mockResolvedValue({ rows: [], total: 0, page: 0, pageSize: 5 })
  })

  it('supports arrow-key navigation and Enter without advertising admin destinations', () => {
    render(<MemoryRouter><CommandPalette open onOpenChange={vi.fn()} /><LocationState /></MemoryRouter>)
    const search = screen.getByRole('combobox', { name: 'Global Search' })
    expect(screen.queryByRole('option', { name: /Administration/ })).not.toBeInTheDocument()
    fireEvent.keyDown(search, { key: 'ArrowDown' })
    fireEvent.keyDown(search, { key: 'Enter' })
    expect(screen.getByTestId('location')).toHaveTextContent('/hosts')
  })

  it('searches console entities and opens a host with its investigation context', async () => {
    render(<MemoryRouter><CommandPalette open onOpenChange={vi.fn()} /><LocationState /></MemoryRouter>)
    const search = screen.getByRole('combobox', { name: 'Global Search' })
    fireEvent.change(search, { target: { value: 'web-01' } })
    expect(await screen.findByRole('option', { name: /web-01/ })).toBeInTheDocument()
    fireEvent.keyDown(search, { key: 'Enter' })
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/hosts?host=host-1'))
    expect(apiMock.hostPage).toHaveBeenCalledWith({ search: 'web-01', page: 0, pageSize: 4, sort: 'asset', direction: 'asc' })
    expect(apiMock.findingPage).toHaveBeenCalledWith({ search: 'web-01', page: 0, pageSize: 5, sort: 'severity', direction: 'asc' })
  })
})
