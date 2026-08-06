import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { NotFoundPage } from './NotFoundPage'

describe('NotFoundPage', () => {
  it('explains the missing route and offers useful recovery paths', () => {
    render(<MemoryRouter initialEntries={['/retired-console-page']}><NotFoundPage /></MemoryRouter>)
    expect(screen.getByRole('heading', { name: 'This Page Does Not Exist' })).toBeInTheDocument()
    expect(screen.getByText('/retired-console-page')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Security Overview/ })).toHaveAttribute('href', '/')
    expect(screen.getByRole('link', { name: /Browse Assets/ })).toHaveAttribute('href', '/hosts')
  })
})
