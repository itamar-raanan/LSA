import { describe, expect, it } from 'vitest'
import { formatDate, formatDateTime } from './dateTime'

describe('operator date formatting', () => {
  it('uses explicit fallbacks for missing or invalid telemetry', () => {
    expect(formatDate(null)).toBe('Not Reported')
    expect(formatDateTime(undefined)).toBe('Never')
    expect(formatDateTime('not-a-date', 'Unavailable')).toBe('Unavailable')
  })

  it('uses the same stable date shape across console workspaces', () => {
    const date = new Date(2026, 7, 9, 14, 5)
    expect(formatDate(date)).toMatch(/2026/)
    expect(formatDateTime(date)).toContain(formatDate(date))
  })
})
