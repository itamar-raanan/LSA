import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { CaretDown, CaretLeft, CaretRight, CaretUpDown, DownloadSimple, FunnelSimple, MagnifyingGlass, SlidersHorizontal } from '@phosphor-icons/react'
import { Fragment, type ReactNode, useEffect, useMemo, useState } from 'react'
import { Button } from '../ui/Button'

export interface SecurityColumn<T> {
  id: string
  header: string
  cell: (row: T) => ReactNode
  sortValue?: (row: T) => string | number | null
  exportValue?: (row: T) => string | number | null
  hideable?: boolean
  className?: string
  priority?: 'primary' | 'secondary' | 'detail'
}

export interface SecurityTableSort {
  id: string
  direction: 'asc' | 'desc'
}

export interface SecurityTableServerPagination {
  page: number
  pageSize: number
  totalRows: number
  onPageChange: (page: number) => void
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
  sort?: SecurityTableSort | null
  onSortChange?: (sort: SecurityTableSort | null) => void
  page?: number
  onPageChange?: (page: number) => void
  serverPagination?: SecurityTableServerPagination
  bulkActions?: ReactNode
  selectionSummary?: boolean
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
  sort: controlledSort,
  onSortChange,
  page: controlledPage,
  onPageChange,
  serverPagination,
  bulkActions,
  selectionSummary = true,
}: SecurityTableProps<T>) {
  const [internalQuery, setInternalQuery] = useState('')
  const [internalSort, setInternalSort] = useState<SecurityTableSort | null>(null)
  const [internalPage, setInternalPage] = useState(0)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const query = controlledQuery ?? internalQuery
  const sort = controlledSort === undefined ? internalSort : controlledSort
  const page = serverPagination?.page ?? controlledPage ?? internalPage
  const effectivePageSize = serverPagination?.pageSize ?? pageSize
  const selectable = selectedRowIds !== undefined && onSelectionChange !== undefined
  const visibleColumns = columns.filter((column) => !hidden.has(column.id))
  const responsiveColumns = visibleColumns.filter((column) => column.priority && column.priority !== 'primary')
  const filtered = useMemo(() => {
    if (serverPagination) return [...rows]
    const needle = query.trim().toLowerCase()
    const result = needle ? rows.filter((row) => searchText(row).toLowerCase().includes(needle)) : [...rows]
    if (sort) {
      const column = columns.find((item) => item.id === sort.id)
      if (column?.sortValue) result.sort((a, b) => String(column.sortValue?.(a) ?? '').localeCompare(String(column.sortValue?.(b) ?? ''), undefined, { numeric: true }) * (sort.direction === 'asc' ? 1 : -1))
    }
    return result
  }, [columns, query, rows, searchText, serverPagination, sort])
  const totalRows = serverPagination?.totalRows ?? filtered.length
  const pageCount = Math.max(1, Math.ceil(totalRows / effectivePageSize))
  const safePage = Math.min(page, pageCount - 1)
  const displayed = serverPagination ? filtered : filtered.slice(safePage * effectivePageSize, (safePage + 1) * effectivePageSize)
  const displayedSelectable = displayed.filter(isRowSelectable)
  const pageSelected = displayedSelectable.length > 0 && displayedSelectable.every((row) => selectedRowIds?.has(row.id))

  useEffect(() => {
    if (serverPagination && page !== safePage) serverPagination.onPageChange(safePage)
  }, [page, safePage, serverPagination])

  function updateQuery(value: string) {
    setInternalQuery(value)
    onQueryChange?.(value)
    changePage(0)
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
    const next: SecurityTableSort = sort?.id === column.id ? { id: column.id, direction: sort.direction === 'asc' ? 'desc' : 'asc' } : { id: column.id, direction: 'asc' }
    setInternalSort(next)
    onSortChange?.(next)
    changePage(0)
  }

  function changePage(next: number) {
    const bounded = Math.max(0, Math.min(pageCount - 1, next))
    setInternalPage(bounded)
    onPageChange?.(bounded)
    serverPagination?.onPageChange(bounded)
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
        {selectionSummary && selectable && selectedRowIds && selectedRowIds.size > 0 && <div className="security-table-selection" role="status"><strong>{selectedRowIds.size}</strong> Selected<button type="button" onClick={() => onSelectionChange?.(new Set())}>Clear</button>{bulkActions}</div>}
        {toolbarActions}
        <span className="security-table-count">{totalRows} Records</span>
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild><Button size="sm"><SlidersHorizontal size={14} />Options<CaretDown size={12} /></Button></DropdownMenu.Trigger>
          <DropdownMenu.Portal><DropdownMenu.Content align="end" className="soc-menu-content">
            <DropdownMenu.Label className="soc-menu-label">Visible Columns</DropdownMenu.Label>
            {columns.filter((column) => column.hideable !== false).map((column) => <DropdownMenu.CheckboxItem key={column.id} checked={!hidden.has(column.id)} onCheckedChange={() => setHidden((current) => { const next = new Set(current); if (next.has(column.id)) next.delete(column.id); else next.add(column.id); return next })} className="soc-menu-item"><span className="soc-menu-check">{!hidden.has(column.id) ? '✓' : ''}</span>{column.header}</DropdownMenu.CheckboxItem>)}
            <DropdownMenu.Separator className="soc-menu-separator" />
            <DropdownMenu.Item className="soc-menu-item" onSelect={exportCsv}><span className="soc-menu-check"><DownloadSimple size={13} /></span>{serverPagination ? 'Export Current Page' : 'Export All Rows'}</DropdownMenu.Item>
          </DropdownMenu.Content></DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </div>
    <div className="security-table-scroll"><table className="security-table" aria-label={ariaLabel}>
      <thead><tr>{selectable && <th className="w-9"><input type="checkbox" aria-label="Select visible rows" checked={pageSelected} disabled={!displayedSelectable.length} onChange={togglePageSelection} /></th>}{(renderExpanded || responsiveColumns.length > 0) && <th className={renderExpanded ? 'w-9' : 'w-9 security-responsive-expand'} aria-label="Row Details" />}{visibleColumns.map((column) => <th key={column.id} className={`${column.className ?? ''} security-column-${column.priority ?? 'secondary'}`} aria-label={column.header} aria-sort={column.sortValue ? sort?.id === column.id ? sort.direction === 'asc' ? 'ascending' : 'descending' : 'none' : undefined}>{column.sortValue ? <button aria-label={`Sort by ${column.header}`} onClick={() => toggleSort(column)}>{column.header}<CaretUpDown size={12} /></button> : <span className="security-table-heading">{column.header}</span>}</th>)}</tr></thead>
      <tbody>{displayed.map((row, rowIndex) => <Fragment key={row.id}><tr className={selectedRowIds?.has(row.id) ? 'selected-row' : undefined}>{selectable && <td><input type="checkbox" aria-label={`Select ${rowLabel(row)}`} checked={selectedRowIds?.has(row.id) ?? false} disabled={!isRowSelectable(row)} onChange={() => toggleRow(row)} /></td>}{(renderExpanded || responsiveColumns.length > 0) && <td className={renderExpanded ? '' : 'security-responsive-expand'}><button className="table-expand" aria-expanded={expanded === row.id} aria-label={`${expanded === row.id ? 'Collapse' : 'Expand'} Additional Details For Row ${safePage * effectivePageSize + rowIndex + 1}`} onClick={() => setExpanded(expanded === row.id ? null : row.id)}><CaretRight size={14} className={expanded === row.id ? 'rotate-90' : ''} /></button></td>}{visibleColumns.map((column) => <td key={column.id} className={`${column.className ?? ''} security-column-${column.priority ?? 'secondary'}`}>{column.cell(row)}</td>)}</tr>{expanded === row.id && (renderExpanded || responsiveColumns.length > 0) && <tr className="expanded-row"><td colSpan={visibleColumns.length + Number(selectable) + 1}>{renderExpanded?.(row)}{responsiveColumns.length > 0 && <dl className="security-responsive-details">{responsiveColumns.map((column) => <div key={column.id} className={`security-responsive-detail-${column.priority}`}><dt>{column.header}</dt><dd>{column.cell(row)}</dd></div>)}</dl>}</td></tr>}</Fragment>)}</tbody>
    </table>{!displayed.length && <div className="grid min-h-44 place-items-center text-center"><div><FunnelSimple size={21} className="mx-auto text-slate-600" /><p className="mt-3 text-xs text-slate-400">{emptyTitle}</p><p className="mt-1 text-[11px] text-slate-600">{emptyDetail}</p></div></div>}</div>
    <div className="security-table-footer"><span>Showing {totalRows ? safePage * effectivePageSize + 1 : 0}–{Math.min(safePage * effectivePageSize + displayed.length, totalRows)} Of {totalRows}</span><div className="flex items-center gap-1"><Button variant="ghost" size="icon" aria-label="Previous page" disabled={safePage === 0} onClick={() => changePage(safePage - 1)}><CaretLeft size={15} /></Button><span className="px-2 font-mono text-[10px] text-slate-500">{safePage + 1} / {pageCount}</span><Button variant="ghost" size="icon" aria-label="Next page" disabled={safePage >= pageCount - 1} onClick={() => changePage(safePage + 1)}><CaretRight size={15} /></Button></div></div>
  </div>
}
