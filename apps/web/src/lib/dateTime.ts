const dateFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
})

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

const compactDateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

function resolveDate(value: string | Date | null | undefined): Date | null {
  if (!value) return null
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatDate(value: string | Date | null | undefined, fallback = 'Not Reported'): string {
  const date = resolveDate(value)
  return date ? dateFormatter.format(date) : fallback
}

export function formatDateTime(value: string | Date | null | undefined, fallback = 'Never'): string {
  const date = resolveDate(value)
  return date ? dateTimeFormatter.format(date) : fallback
}

export function formatCompactDateTime(value: string | Date | null | undefined, fallback = 'Pending'): string {
  const date = resolveDate(value)
  return date ? compactDateTimeFormatter.format(date) : fallback
}
