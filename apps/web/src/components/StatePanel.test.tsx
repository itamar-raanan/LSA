import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { EmptyState, ErrorState, LoadingState } from './StatePanel'

describe('shared console states', () => {
  it.each(['dashboard', 'table', 'detail', 'settings'] as const)('renders a %s loading structure', (variant) => {
    const { container } = render(<LoadingState variant={variant} />)
    expect(screen.getByRole('status', { name: 'Loading data' })).toBeInTheDocument()
    expect(container.querySelector(`.loading-state-${variant}`)).toBeInTheDocument()
  })

  it('keeps recovery and first-run actions operational', () => {
    const retry = vi.fn()
    const action = vi.fn()
    const errorView = render(<ErrorState message="API unavailable" retry={retry} />)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalledOnce()
    errorView.unmount()

    render(<EmptyState title="No Assets" detail="Enroll the first endpoint." action={<button onClick={action}>Enroll Asset</button>} />)
    fireEvent.click(screen.getByRole('button', { name: 'Enroll Asset' }))
    expect(action).toHaveBeenCalledOnce()
  })
})
