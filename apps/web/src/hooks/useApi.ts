import { useCallback, useEffect, useState } from 'react'

export function useApi<T>(loader: () => Promise<T>, dependencies: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true)
    setError(null)
    try {
      setData(await loader())
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to load data')
    } finally {
      setLoading(false)
    }
    // Loader dependencies are intentionally controlled by the caller.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies)

  useEffect(() => {
    void load()
  }, [load])

  const reload = useCallback(() => load(true), [load])
  const refresh = useCallback(() => load(false), [load])

  return { data, error, loading, reload, refresh }
}
