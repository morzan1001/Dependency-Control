import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
 
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function toggle<T extends string>(list: readonly T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value]
}

export interface Named {
  id: string
  name: string
}

export function isNameTaken(items: readonly Named[] | undefined, name: string, current?: Named): boolean {
  const wanted = name.trim()
  return (
    wanted !== '' &&
    wanted !== current?.name &&
    (items ?? []).some((item) => item.id !== current?.id && item.name.trim().toLowerCase() === wanted.toLowerCase())
  )
}

// The same id listed twice, as two runs of one project, shares its name with nothing.
export function sharedNames<T extends Named>(items: readonly T[]): Map<string, T[]> {
  const byName = new Map<string, Map<string, T>>()
  for (const item of items) byName.set(item.name, (byName.get(item.name) ?? new Map<string, T>()).set(item.id, item))
  return new Map([...byName].filter(([, byId]) => byId.size > 1).map(([name, byId]) => [name, [...byId.values()]]))
}

// A chart axis drops a label that would overlap its neighbour, so long ones keep only their tail, where names sharing a prefix differ.
export function truncateLabel(label: string, max = 20): string {
  return label.length > max ? `…${label.slice(-max)}` : label
}

interface ValidationError {
  msg?: string;
  type?: string;
  loc?: (string | number)[];
}

interface ErrorWithResponse {
  response?: {
    data?: {
      detail?: string | ValidationError[] | Record<string, unknown>;
    };
  };
  message?: string;
}

export function getErrorMessage(error: unknown): string {
  if (typeof error !== 'object' || error === null) {
    return 'An unknown error occurred';
  }

  const err = error as ErrorWithResponse;
  const detail = err.response?.data?.detail;
  if (detail) {
    if (Array.isArray(detail)) {
      // A validation entry can reach us without msg; show the raw entry instead of throwing.
      return detail
        .map((validationErr: ValidationError) =>
          (validationErr.msg ?? JSON.stringify(validationErr)).replace(/^(Value error, |value is not a valid email address: )/, ''),
        )
        .join('\n');
    }
    if (typeof detail === 'string') {
      return detail;
    }
    return JSON.stringify(detail);
  }
  return err.message || 'An unknown error occurred';
}

export const DEFAULT_DATE_FORMAT: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' }

export function formatDate(
  date: string | Date | undefined | null,
  options: Intl.DateTimeFormatOptions = DEFAULT_DATE_FORMAT
): string {
  if (!date) return 'N/A'
  try {
    const d = typeof date === 'string' ? new Date(date) : date
    if (Number.isNaN(d.getTime())) return String(date)
    return d.toLocaleDateString(undefined, options)
  } catch {
    return String(date)
  }
}

export function formatDateTime(date: string | Date | undefined | null): string {
  return formatDate(date, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

export function shortCommitHash(hash: string | undefined | null): string {
  if (!hash) return ''
  return hash.substring(0, 7)
}

// null coverage means nothing was ever outdated (N/A), distinct from 0%.
export function formatCoveragePct(pct: number | null): string {
  return pct === null ? 'N/A' : `${pct}%`
}

// null means no calendar window was requested, so no rate can be stated.
export function formatUpdatesPerMonth(rate: number | null | undefined): string {
  return rate === null || rate === undefined ? 'N/A' : `${rate}`
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1)
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}
