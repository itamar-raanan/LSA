import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { ChevronDown, ChevronLeft, ChevronRight, ChevronsUpDown, Download, ListFilter, Search, Settings2 } from 'lucide-react'
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

export function SecurityTable<T extends { id: string }>({
  rows, columns, searchPlaceholder = 'Search records', searchText, pageSize = 8, filename = 'lsa-export.csv',
  emptyTitle = 'No records found', renderExpanded,
}: {
  rows: T[]; columns: SecurityColumn<T>[]; searchPlaceholder?: string; searchText: (row: T) => string;
  pageSize?: number; filename?: string; emptyTitle?: string; renderExpanded?: (row: T) => ReactNode;
}) {
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<{ id: string; direction: 'asc' | 'desc' } | null>(null)
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [hidden, setHidden] = useState<Set<string>>(new Set())
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

  function toggleSort(column: SecurityColumn<T>) {
    if (!column.sortValue) return
    setSort((current) => current?.id === column.id ? { id: column.id, direction: current.direction === 'asc' ? 'desc' : 'asc' } : { id: column.id, direction: 'asc' })
  }

  function exportCsv() {
    const csv = [visibleColumns.map((column) => column.header), ...filtered.map((row) => visibleColumns.map((column) => column.exportValue?.(row) ?? column.sortValue?.(row) ?? ''))]
      .map((line) => line.map((value) => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url)
  }

  return <div className="security-table-shell">
    <div className="security-table-toolbar">
      <label className="soc-search"><Search size={15} /><span className="sr-only">Search table</span><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0) }} placeholder={searchPlaceholder} /></label>
      <div className="flex items-center gap-2">
        <span className="hidden items-center gap-1.5 text-[10px] text-slate-500 sm:flex"><ListFilter size={13} />{filtered.length} records</span>
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild><Button size="sm"><Settings2 size={14} />Columns<ChevronDown size={12} /></Button></DropdownMenu.Trigger>
          <DropdownMenu.Portal><DropdownMenu.Content align="end" className="soc-menu-content">
            <DropdownMenu.Label className="soc-menu-label">Visible columns</DropdownMenu.Label>
            {columns.filter((column) => column.hideable !== false).map((column) => <DropdownMenu.CheckboxItem key={column.id} checked={!hidden.has(column.id)} onCheckedChange={() => setHidden((current) => { const next = new Set(current); if (next.has(column.id)) next.delete(column.id); else next.add(column.id); return next })} className="soc-menu-item"><span className="soc-menu-check">{!hidden.has(column.id) ? '✓' : ''}</span>{column.header}</DropdownMenu.CheckboxItem>)}
          </DropdownMenu.Content></DropdownMenu.Portal>
        </DropdownMenu.Root>
        <Button size="sm" onClick={exportCsv}><Download size={14} />Export</Button>
      </div>
    </div>
    <div className="overflow-x-auto"><table className="security-table"><thead><tr>{renderExpanded && <th className="w-9" />}{visibleColumns.map((column) => <th key={column.id} className={column.className}><button disabled={!column.sortValue} onClick={() => toggleSort(column)}>{column.header}{column.sortValue && <ChevronsUpDown size={12} />}</button></th>)}</tr></thead>
      <tbody>{displayed.map((row) => <Fragment key={row.id}><tr>{renderExpanded && <td><button className="table-expand" aria-label={`${expanded === row.id ? 'Collapse' : 'Expand'} row`} onClick={() => setExpanded(expanded === row.id ? null : row.id)}><ChevronRight size={14} className={expanded === row.id ? 'rotate-90' : ''} /></button></td>}{visibleColumns.map((column) => <td key={column.id} className={column.className}>{column.cell(row)}</td>)}</tr>{renderExpanded && expanded === row.id && <tr className="expanded-row"><td colSpan={visibleColumns.length + 1}>{renderExpanded(row)}</td></tr>}</Fragment>)}</tbody>
    </table>{!displayed.length && <div className="grid min-h-44 place-items-center text-center"><div><ListFilter size={21} className="mx-auto text-slate-600" /><p className="mt-3 text-xs text-slate-400">{emptyTitle}</p><p className="mt-1 text-[11px] text-slate-600">Adjust the search or filters and try again.</p></div></div>}</div>
    <div className="security-table-footer"><span>Showing {filtered.length ? safePage * pageSize + 1 : 0}–{Math.min((safePage + 1) * pageSize, filtered.length)} of {filtered.length}</span><div className="flex items-center gap-1"><Button variant="ghost" size="icon" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}><ChevronLeft size={15} /></Button><span className="px-2 font-mono text-[10px] text-slate-500">{safePage + 1} / {pageCount}</span><Button variant="ghost" size="icon" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}><ChevronRight size={15} /></Button></div></div>
  </div>
}
