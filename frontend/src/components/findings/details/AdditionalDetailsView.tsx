import { Badge } from '@/components/ui/badge'
import type { FindingDetails } from '@/types/scan'
import { AlertTriangle, Building, Calendar, ExternalLink, FileText, User } from 'lucide-react'
import { formatDate } from '@/lib/utils'

// Fields rendered elsewhere; skip in this generic detail view.
const skipFields = new Set(['license', 'severity', 'type', 'message', 'id', 'component', 'version', 'fixed_version'])

// Fields displayed side-by-side (e.g. cycle + lts for EOL).
const rowGroupFields = new Set(['cycle', 'lts'])

function isUrl(value: unknown): value is string {
  return typeof value === 'string' && (value.startsWith('http://') || value.startsWith('https://'))
}

function isDateField(key: string): boolean {
  return key.includes('date') || key === 'eol' || key === 'end_of_life'
}

function isEmptyValue(value: unknown): boolean {
  if (value === null || value === undefined || value === '') return true
  if (Array.isArray(value) && value.length === 0) return true
  if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value as Record<string, unknown>).length === 0) return true
  return false
}

function renderArrayItem(key: string, item: unknown, index: number) {
  if (isUrl(item)) {
    return (
      <a
        key={`${key}-url-${item}`}
        href={item}
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary hover:underline break-all text-xs flex items-center gap-1"
      >
        <ExternalLink className="h-3 w-3 flex-shrink-0" />
        {item}
      </a>
    )
  }
  return (
    <Badge key={`${key}-badge-${index}-${String(item)}`} variant="outline" className="font-mono text-xs w-fit">
      {String(item)}
    </Badge>
  )
}

function renderValue(key: string, value: unknown) {
  if (key === 'license_url' && typeof value === 'string') {
    return (
      <a
        href={value}
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary hover:underline flex items-center gap-1"
      >
        <ExternalLink className="h-3 w-3" />
        View License
      </a>
    )
  }

  if (isUrl(value)) {
    return (
      <a href={value} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline break-all">
        {value}
      </a>
    )
  }

  if (isDateField(key)) {
    const formatted = formatDate(String(value))
    if (formatted !== 'N/A' && formatted !== String(value)) {
      return <span>{formatted}</span>
    }
  }

  if (typeof value === 'boolean') {
    return <Badge variant={value ? 'default' : 'secondary'}>{value ? 'Yes' : 'No'}</Badge>
  }

  if (Array.isArray(value)) {
    const hasUrls = value.some(isUrl)
    if (hasUrls) {
      return (
        <div className="flex flex-col gap-1">
          {value.map((item, i) => renderArrayItem(key, item, i))}
        </div>
      )
    }

    return (
      <div className="flex flex-wrap gap-1">
        {value.map((item, i) => (
          <Badge key={`${key}-${i}-${String(item)}`} variant="outline" className="font-mono text-xs">
            {String(item)}
          </Badge>
        ))}
      </div>
    )
  }

  if (typeof value === 'object' && value !== null) {
    return (
      <pre className="bg-muted p-2 rounded text-xs overflow-auto max-h-32">{JSON.stringify(value, null, 2)}</pre>
    )
  }

  return <span className="break-all">{String(value)}</span>
}

function getFieldIcon(key: string) {
  if (key.includes('url') || key.includes('link')) return ExternalLink
  if (key.includes('date') || key.includes('eol') || key.includes('end_of_life')) return Calendar
  if (key.includes('license')) return FileText
  if (key.includes('author') || key.includes('maintainer')) return User
  if (key.includes('publisher') || key.includes('vendor')) return Building
  if (key.includes('risk') || key.includes('warning')) return AlertTriangle
  return null
}

function formatFieldName(key: string) {
  return key
    .replaceAll('_', ' ')
    .replaceAll(/([A-Z])/g, ' $1')
    .split(' ')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ')
    .trim()
}

export function AdditionalDetailsView({ details }: Readonly<{ details: FindingDetails }>) {
  const filteredEntries = Object.entries(details as Record<string, unknown>).filter(([key, value]) => {
    if (skipFields.has(key)) return false
    return !isEmptyValue(value)
  })

  const groupedEntries = filteredEntries.filter(([key]) => rowGroupFields.has(key))
  const regularEntries = filteredEntries.filter(([key]) => !rowGroupFields.has(key))

  if (filteredEntries.length === 0) {
    return null
  }

  return (
    <div className="bg-muted/50 rounded-lg p-4 space-y-3">
      {groupedEntries.length > 0 && (
        <div className="grid grid-cols-2 gap-4">
          {groupedEntries.map(([key, value]) => {
            const Icon = getFieldIcon(key)
            return (
              <div key={key} className="flex items-start gap-3">
                {Icon && <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />}
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-muted-foreground">{formatFieldName(key)}</p>
                  <div className="text-sm">{renderValue(key, value)}</div>
                </div>
              </div>
            )
          })}
        </div>
      )}
      {regularEntries.map(([key, value]) => {
        const Icon = getFieldIcon(key)
        return (
          <div key={key} className="flex items-start gap-3">
            {Icon && <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />}
            <div className="flex-1 min-w-0">
              <p className="text-xs text-muted-foreground">{formatFieldName(key)}</p>
              <div className="text-sm">{renderValue(key, value)}</div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
