const CONSOLE_ORIGIN = 'https://lsa.local'
const RETURN_ROUTES = new Map([
  ['/', 'Security Overview'],
  ['/findings', 'Security Findings'],
  ['/applications', 'Applications'],
  ['/hosts', 'Assets'],
])

type LocationContext = Pick<Location, 'pathname' | 'search' | 'hash'>

export function consoleLocation(location: LocationContext): string {
  return `${location.pathname}${location.search}${location.hash}`
}

export function withInvestigationReturn(destination: string, location: LocationContext): string {
  const target = new URL(destination, CONSOLE_ORIGIN)
  target.searchParams.set('return_to', consoleLocation(location))
  return `${target.pathname}${target.search}${target.hash}`
}

export function investigationReturn(rawTarget: string | null): { to: string; label: string } | null {
  if (!rawTarget) return null
  try {
    const target = new URL(rawTarget, CONSOLE_ORIGIN)
    const label = target.origin === CONSOLE_ORIGIN ? RETURN_ROUTES.get(target.pathname) : undefined
    if (!label) return null
    return { to: `${target.pathname}${target.search}${target.hash}`, label }
  } catch {
    return null
  }
}
