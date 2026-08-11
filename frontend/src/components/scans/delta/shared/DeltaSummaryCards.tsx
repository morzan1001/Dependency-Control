import { Card, CardContent } from '@/components/ui/card'
import { SeverityBadge } from '@/components/findings/SeverityBadge'

interface DeltaSummaryCardsProps {
  readonly added: number
  readonly removed: number
  readonly unchanged: number
  readonly changed?: number
  readonly bySeverity?: Record<string, number>
}

export function DeltaSummaryCards({ added, removed, unchanged, changed, bySeverity }: DeltaSummaryCardsProps) {
  const tiles = [
    { label: 'Added', value: `+${added}`, className: 'text-green-600' },
    { label: 'Removed', value: `−${removed}`, className: 'text-red-600' },
    ...(changed !== undefined ? [{ label: 'Changed', value: `↻${changed}`, className: 'text-blue-600' }] : []),
    { label: 'Unchanged', value: `${unchanged}`, className: 'text-muted-foreground' },
  ]
  const severities = Object.entries(bySeverity ?? {}).filter(([, count]) => count > 0)

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map((tile) => (
          <Card key={tile.label}>
            <CardContent className="py-3">
              <div className={`text-xl font-bold ${tile.className}`}>{tile.value}</div>
              <p className="text-xs text-muted-foreground">{tile.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      {severities.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted-foreground">By severity:</span>
          {severities.map(([severity, count]) => (
            <span key={severity} className="flex items-center gap-1">
              {/* delta API returns lowercase severities; SeverityBadge expects app-wide uppercase casing */}
              <SeverityBadge severity={severity.toUpperCase()} /> {count}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
