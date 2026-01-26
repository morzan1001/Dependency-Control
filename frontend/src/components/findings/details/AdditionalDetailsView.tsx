import { Badge } from '@/components/ui/badge'
import type { FindingDetails } from '@/types/scan'
import { AlertTriangle, Building, Calendar, ExternalLink, FileText, User } from 'lucide-react'
import { formatDate } from '@/lib/utils'

export function AdditionalDetailsView({ details }: { details: FindingDetails }) {
  // Skip rendering for these redundant fields that are shown elsewhere
  const skipFields = ['license', 'severity', 'type', 'message', 'id', 'component', 'version', 'fixed_version']

  // Fields that should be grouped together in a row (e.g., cycle and lts for EOL)
  const rowGroupFields = ['cycle', 'lts']

  // Filter out empty values and redundant fields
  const filteredEntries = Object.entries(details as Record<string, unknown>).filter(([key, value]) => {
    if (skipFields.includes(key)) return false
    if (value === null || value === undefined || value === '') return false
    if (Array.isArray(value) && value.length === 0) return false
    if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value as object).length === 0) return false
    return true
  })

  // Separate grouped fields from regular fields
  const groupedEntries = filteredEntries.filter(([key]) => rowGroupFields.includes(key))
  const regularEntries = filteredEntries.filter(([key]) => !rowGroupFields.includes(key))

  if (filteredEntries.length === 0) {
    return null
  }

  // Helper to render a value based on its type
  const renderValue = (key: string, value: unknown) => {
    // Handle license_url specially - render as link
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

    // Handle URLs in any field
    if (typeof value === 'string' && (value.startsWith('http://') || value.startsWith('https://'))) {
      return (
        <a href={value} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline break-all">
          {value}
        </a>
      )
    }

    // Handle dates
    if (key.includes('date') || key === 'eol' || key === 'end_of_life') {
      const formatted = formatDate(String(value))
      if (formatted !== 'N/A' && formatted !== String(value)) {
        return <span>{formatted}</span>
      }
    }

    // Handle booleans
    if (typeof value === 'boolean') {
      return <Badge variant={value ? 'default' : 'secondary'}>{value ? 'Yes' : 'No'}</Badge>
    }

    // Handle arrays
    if (Array.isArray(value)) {
      // Check if array contains URLs
      const hasUrls = value.some(
        (item) => typeof item === 'string' && (item.startsWith('http://') || item.startsWith('https://'))
      )
      if (hasUrls) {
        return (
          <div className="flex flex-col gap-1">
            {value.map((item, i) =>
              typeof item === 'string' && (item.startsWith('http://') || item.startsWith('https://')) ? (
                <a
                  key={i}
                  href={item}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline break-all text-xs flex items-center gap-1"
                >
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                  {item}
                </a>
              ) : (
                <Badge key={i} variant="outline" className="font-mono text-xs w-fit">
                  {String(item)}
                </Badge>
              )
            )}
          </div>
        )
      }

      return (
        <div className="flex flex-wrap gap-1">
          {value.map((item, i) => (
            <Badge key={i} variant="outline" className="font-mono text-xs">
              {String(item)}
            </Badge>
          ))}
        </div>
      )
    }

    // Handle nested objects
    if (typeof value === 'object' && value !== null) {
      return (
        <pre className="bg-muted p-2 rounded text-xs overflow-auto max-h-32">{JSON.stringify(value, null, 2)}</pre>
      )
    }

    // Default: render as string
    return <span className="break-all">{String(value)}</span>
  }

  // Get appropriate icon for field
  const getFieldIcon = (key: string) => {
    if (key.includes('url') || key.includes('link')) return ExternalLink
    if (key.includes('date') || key.includes('eol') || key.includes('end_of_life')) return Calendar
    if (key.includes('license')) return FileText
    if (key.includes('author') || key.includes('maintainer')) return User
    if (key.includes('publisher') || key.includes('vendor')) return Building
    if (key.includes('risk') || key.includes('warning')) return AlertTriangle
    return null
  }

  // Format field name for display
  const formatFieldName = (key: string) => {
    return key
      .replace(/_/g, ' ')
      .replace(/([A-Z])/g, ' $1')
      .split(' ')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ')
      .trim()
  }

  return (
    <div className="bg-muted/50 rounded-lg p-4 space-y-3">
      {/* Grouped fields (cycle + lts) displayed side by side */}
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
      {/* Regular fields */}
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
