import { fireEvent, render, screen, within } from '@testing-library/react'
import { useState } from 'react'
import { SecurityTable, type SecurityColumn } from './SecurityTable'

interface TestRow {
  id: string
  name: string
  state: string
}

const rows: TestRow[] = [
  { id: 'beta', name: 'Beta Host', state: 'Offline' },
  { id: 'alpha', name: 'Alpha Host', state: 'Online' },
  { id: 'gamma', name: 'Gamma Host', state: 'Online' },
]

const columns: SecurityColumn<TestRow>[] = [
  { id: 'name', header: 'Name', hideable: false, sortValue: (row) => row.name, exportValue: (row) => row.name, cell: (row) => row.name },
  { id: 'state', header: 'State', sortValue: (row) => row.state, exportValue: (row) => row.state, cell: (row) => row.state },
]

function TableHarness() {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  return <SecurityTable rows={rows} columns={columns} searchText={(row) => `${row.name} ${row.state}`} rowLabel={(row) => row.name} pageSize={2} selectedRowIds={selected} onSelectionChange={setSelected} ariaLabel="Test Assets" />
}

describe('SecurityTable', () => {
  it('supports sorting, selection, search, and pagination with accessible controls', () => {
    render(<TableHarness />)

    const table = screen.getByRole('table', { name: 'Test Assets' })
    const nameHeading = within(table).getByRole('columnheader', { name: 'Name' })
    expect(nameHeading).toHaveAttribute('aria-sort', 'none')
    expect(within(table).getAllByRole('row')[1]).toHaveTextContent('Beta Host')
    fireEvent.click(screen.getByRole('button', { name: 'Sort by Name' }))
    expect(nameHeading).toHaveAttribute('aria-sort', 'ascending')
    expect(within(table).getAllByRole('row')[1]).toHaveTextContent('Alpha Host')
    fireEvent.click(screen.getByRole('button', { name: 'Sort by Name' }))
    expect(nameHeading).toHaveAttribute('aria-sort', 'descending')
    fireEvent.click(screen.getByRole('button', { name: 'Sort by Name' }))

    const alphaSelection = screen.getByRole('checkbox', { name: 'Select Alpha Host' })
    fireEvent.click(alphaSelection)
    expect(alphaSelection).toBeChecked()
    expect(alphaSelection.closest('tr')).toHaveClass('selected-row')

    fireEvent.change(screen.getByRole('textbox', { name: 'Search table' }), { target: { value: 'gamma' } })
    expect(within(table).getByText('Gamma Host')).toBeInTheDocument()
    expect(within(table).queryByText('Alpha Host')).not.toBeInTheDocument()

    fireEvent.change(screen.getByRole('textbox', { name: 'Search table' }), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(within(table).getByText('Gamma Host')).toBeInTheDocument()
    expect(screen.getByText('Showing 3–3 Of 3')).toBeInTheDocument()
  })
})
