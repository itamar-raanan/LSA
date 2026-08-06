import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { CaretDown, CaretLeft, CaretRight, CaretUpDown, DownloadSimple, FunnelSimple, MagnifyingGlass, SlidersHorizontal } from '@phosphor-icons/react'
import { Fragment, type ReactNode, useMemo, useState } from 'react'
import { Button } from '../ui/Button'

export interface SecurityColumn<T> {
  id: string
  header: string
  cell: (row: T) => ReactNode
  sortValue?: (row: T) => string | number | null
  exportValue?: (row: T) => string | number | null
  hideable?: boolean
  className?: string
}

interface SecurityTableProps<T> {
  rows: T[]
  columns: SecurityColumn<T>[]
  searchText: (row: T) => string
  rowLabel?: (row: T) => string
  searchPlaceholder?: string
  pageSize?: number
  filename?: string
  emptyTitle?: string
  emptyDetail?: string
  renderExpanded?: (row: T) => ReactNode
  ariaLabel?: string
  query?: string
  onQueryChange?: (query: string) => void
  toolbarActions?: ReactNode
  selectedRowIds?: Set<string>
  onSelectionChange?: (selected: Set<string>) => void
  isRowSelectable?: (row: T) => boolean
  embedded?: boolean
}

export function SecurityTable<T extends { id: string }>({
  rows,
  columns,
  searchText,
  rowLabel = searchText,
  searchPlaceholder = 'Search records',
  pageSize = 8,
  filename = 'lsa-export.csv',
  emptyTitle = 'No records found',
  emptyDetail = 'Adjust the search or filters and try again.',
  renderExpanded,
  ariaLabel = 'Security records',
  query: controlledQuery,
  onQueryChange,
  toolbarActions,
  selectedRowIds,
  onSelectionChange,
  isRowSelectable = () => true,
  embedded = false,
}: SecurityTableProps<T>) {
  const [internalQuery, setInternalQuery] = useState('')
  const [sort, setSort] = useState<{ id: string; direction: 'asc' | 'desc' } | null>(null)
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const query = controlledQuery ?? internalQuery
  const selectable = selectedRowIds !== undefined && onSelectionChange !== undefined
  const visibleColumns = columns.filter((column) => !hidden.has(column.id))
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const result = needle ? rows.filter((row) => searchText(row).toLowerCase().includes(needle)) : [...rows]
    if (sort) {
      const column = columns.find((item) => item.id === sort.id)
      if (column?.sortValue) result.sort((a, b) => String(column.sortValue?.(a) ?? '').localeCompare(String(column.sortValue?.(b) ?? ''), undefined, { numeric: true }) * (sort.direction === 'asc' ? 1 : -1))
    }
    return result
  }, [columns, query, rows, searchText, sort])
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(page, pageCount - 1)
  const displayed = filtered.slice(safePage * pageSize, (safePage + 1) * pageSize)
  const displayedSelectable = displayed.filter(isRowSelectable)
  const pageSelected = displayedSelectable.length > 0 && displayedSelectable.every((row) => selectedRowIds?.has(row.id))

  function updateQuery(value: string) {
    setInternalQuery(value)
    onQueryChange?.(value)
    setPage(0)
  }

  function togglePageSelection() {
    if (!selectedRowIds || !onSelectionChange) return
    const next = new Set(selectedRowIds)
    displayedSelectable.forEach((row) => pageSelected ? next.delete(row.id) : next.add(row.id))
    onSelectionChange(next)
  }

  function toggleRow(row: T) {
    if (!selectedRowIds || !onSelectionChange || !isRowSelectable(row)) return
    const next = new Set(selectedRowIds)
    if (next.has(row.id)) next.delete(row.id)
    else next.add(row.id)
    onSelectionChange(next)
  }

  function toggleSort(column: SecurityColumn<T>) {
    if (!column.sortValue) return
    setSort((current) => current?.id === column.id ? { id: column.id, direction: current.direction === 'asc' ? 'desc' : 'asc' } : { id: column.id, direction: 'asc' })
  }

  function exportCsv() {
    const csv = [visibleColumns.map((column) => column.header), ...filtered.map((row) => visibleColumns.map((column) => column.exportValue?.(row) ?? column.sortValue?.(row) ?? ''))]
      .map((line) => line.map((value) => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return <div className={`security-table-shell ${embedded ? 'security-table-shell-embedded' : ''}`}>
    <div className="security-table-toolbar">
      <label className="soc-search"><MagnifyingGlass size={15} /><span className="sr-only">Search table</span><input value={query} onChange={(event) => updateQuery(event.target.value)} placeholder={searchPlaceholder} /></label>
      <div className="flex flex-wrap items-center justify-end gap-2">
        {toolbarActions}
        <span className="hidden items-center gap-1.5 text-[10px] text-slate-500 sm:flex"><FunnelSimple size={13} />{filtered.length} Records</span>
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild><Button size="sm"><SlidersHorizontal size={14} />Columns<CaretDown size={12} /></Button></DropdownMenu.Trigger>
          <DropdownMenu.Portal><DropdownMenu.Content align="end" className="soc-menu-content">
            <DropdownMenu.Label className="soc-menu-label">Visible Columns</DropdownMenu.Label>
            {columns.filter((column) => column.hideable !== false).map((column) => <DropdownMenu.CheckboxItem key={column.id} checked={!hidden.has(column.id)} onCheckedChange={() => setHidden((current) => { const next = new Set(current); if (next.has(column.id)) next.delete(column.id); else next.add(column.id); return next })} className="soc-menu-item"><span className="soc-menu-check">{!hidden.has(column.id) ? '✓' : ''}</span>{column.header}</DropdownMenu.CheckboxItem>)}
          </DropdownMenu.Content></DropdownMenu.Portal>
        </DropdownMenu.Root>
        <Button size="sm" onClick={exportCsv}><DownloadSimple size={14} />Export</Button>
      </div>
    </div>
    <div className="overflow-x-auto"><table className="security-table" aria-label={ariaLabel}>
      <thead><tr>{selectable && <th className="w-9"><input type="checkbox" aria-label="Select visible rows" checked={pageSelected} disabled={!displayedSelectable.length} onChange={togglePageSelection} /></th>}{renderExpanded && <th className="w-9" />}{visibleColumns.map((column) => <th key={column.id} className={column.className} aria-label={column.header}>{column.sortValue ? <button aria-label={`Sort by ${column.header}`} onClick={() => toggleSort(column)}>{column.header}<CaretUpDown size={12} /></button> : <span className="security-table-heading">{column.header}</span>}</th>)}</tr></thead>
      <tbody>{displayed.map((row) => <Fragment key={row.id}><tr className={selectedRowIds?.has(row.id) ? 'selected-row' : undefined}>{selectable && <td><input type="checkbox" aria-label={`Select ${rowLabel(row)}`} checked={selectedRowIds?.has(row.id) ?? false} disabled={!isRowSelectable(row)} onChange={() => toggleRow(row)} /></td>}{renderExpanded && <td><button className="table-expand" aria-label={`${expanded === row.id ? 'Collapse' : 'Expand'} row`} onClick={() => setExpanded(expanded === row.id ? null : row.id)}><CaretRight size={14} className={expanded === row.id ? 'rotate-90' : ''} /></button></td>}{visibleColumns.map((column) => <td key={column.id} className={column.className}>{column.cell(row)}</td>)}</tr>{renderExpanded && expanded === row.id && <tr className="expanded-row"><td colSpan={visibleColumns.length + Number(selectable) + 1}>{renderExpanded(row)}</td></tr>}</Fragment>)}</tbody>
    </table>{!displayed.length && <div className="grid min-h-44 place-items-center text-center"><div><FunnelSimple size={21} className="mx-auto text-slate-600" /><p className="mt-3 text-xs text-slate-400">{emptyTitle}</p><p className="mt-1 text-[11px] text-slate-600">{emptyDetail}</p></div></div>}</div>
    <div className="security-table-footer"><span>Showing {filtered.length ? safePage * pageSize + 1 : 0}–{Math.min((safePage + 1) * pageSize, filtered.length)} Of {filtered.length}</span><div className="flex items-center gap-1"><Button variant="ghost" size="icon" aria-label="Previous page" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}><CaretLeft size={15} /></Button><span className="px-2 font-mono text-[10px] text-slate-500">{safePage + 1} / {pageCount}</span><Button variant="ghost" size="icon" aria-label="Next page" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}><CaretRight size={15} /></Button></div></div>
  </div>
}
