import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { SecurityTableSort } from '../components/security/SecurityTable'

interface SecurityTableUrlStateOptions {
  queryKey?: string
  sortKey?: string
  directionKey?: string
  pageKey?: string
  clearOnSearch?: string[]
}

export function useSecurityTableUrlState({
  queryKey = 'search',
  sortKey = 'sort',
  directionKey = 'direction',
  pageKey = 'page',
  clearOnSearch = [],
}: SecurityTableUrlStateOptions = {}) {
  const [searchParams, setSearchParams] = useSearchParams()
  const query = searchParams.get(queryKey) ?? ''
  const sort = useMemo<SecurityTableSort | null>(() => {
    const id = searchParams.get(sortKey)
    if (!id) return null
    return { id, direction: searchParams.get(directionKey) === 'desc' ? 'desc' : 'asc' }
  }, [directionKey, searchParams, sortKey])
  const page = Math.max(0, (Number.parseInt(searchParams.get(pageKey) ?? '1', 10) || 1) - 1)

  const update = useCallback((changes: Record<string, string | null>) => {
    const next = new URLSearchParams(searchParams)
    Object.entries(changes).forEach(([key, value]) => {
      if (!value) next.delete(key)
      else next.set(key, value)
    })
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  const setQuery = useCallback((value: string) => {
    const changes: Record<string, string | null> = { [queryKey]: value.trim() ? value : null, [pageKey]: null }
    clearOnSearch.forEach((key) => { changes[key] = null })
    update(changes)
  }, [clearOnSearch, pageKey, queryKey, update])

  const setSort = useCallback((value: SecurityTableSort | null) => {
    update({ [sortKey]: value?.id ?? null, [directionKey]: value?.direction === 'desc' ? 'desc' : null, [pageKey]: null })
  }, [directionKey, pageKey, sortKey, update])

  const setPage = useCallback((value: number) => {
    update({ [pageKey]: value > 0 ? String(value + 1) : null })
  }, [pageKey, update])

  return { query, sort, page, setQuery, setSort, setPage }
}
