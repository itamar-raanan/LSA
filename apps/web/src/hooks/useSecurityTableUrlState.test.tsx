import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { useSecurityTableUrlState } from './useSecurityTableUrlState'

function Harness() {
  const state = useSecurityTableUrlState({ clearOnSearch: ['host'] })
  const location = useLocation()
  return <div>
    <output data-testid="state">{state.query}|{state.sort?.id}|{state.sort?.direction}|{state.page}</output>
    <output data-testid="location">{location.search}</output>
    <button onClick={() => state.setQuery('database')}>Search</button>
    <button onClick={() => state.setSort({ id: 'risk', direction: 'desc' })}>Sort</button>
    <button onClick={() => state.setPage(2)}>Page</button>
  </div>
}

describe('useSecurityTableUrlState', () => {
  it('restores table state and updates it without discarding unrelated context', () => {
    render(<MemoryRouter initialEntries={['/hosts?search=web&sort=name&direction=desc&page=2&host=host-1&risk=critical']}><Harness /></MemoryRouter>)

    expect(screen.getByTestId('state')).toHaveTextContent('web|name|desc|1')
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(screen.getByTestId('location')).toHaveTextContent('?search=database&sort=name&direction=desc&risk=critical')
    fireEvent.click(screen.getByRole('button', { name: 'Sort' }))
    expect(screen.getByTestId('location')).toHaveTextContent('sort=risk')
    fireEvent.click(screen.getByRole('button', { name: 'Page' }))
    expect(screen.getByTestId('location')).toHaveTextContent('page=3')
  })
})
