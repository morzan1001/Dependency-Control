import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
 
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

interface ValidationError {
  msg: string;
  type?: string;
  loc?: (string | number)[];
}

interface ErrorWithResponse {
  response?: {
    data?: {
      detail?: string | ValidationError[];
    };
  };
  message?: string;
}

export function getErrorMessage(error: ErrorWithResponse | Error | unknown): string {
  if (typeof error !== 'object' || error === null) {
    return "An unknown error occurred";
  }

  const err = error as ErrorWithResponse;
  if (err.response?.data?.detail) {
    const detail = err.response.data.detail;
    if (Array.isArray(detail)) {
      return detail.map((validationErr: ValidationError) => {
        return validationErr.msg.replace('Value error, ', '');
      }).join('\n');
    }
    if (typeof detail === 'string') {
      return detail;
    }
  }
  return (error as Error).message || "An unknown error occurred";
}

const DEFAULT_DATE_FORMAT: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' }

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
