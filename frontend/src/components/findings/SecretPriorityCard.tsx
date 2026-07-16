import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { SecretPrioritizedCounts } from '@/types/scan'

interface SecretPriorityCardProps {
  readonly counts: SecretPrioritizedCounts
}

export function SecretPriorityCard({ counts }: SecretPriorityCardProps) {
  if (counts.total === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Secret Priority</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-4 gap-4 text-center">
          <div>
            <p className="text-2xl font-bold">{counts.total}</p>
            <p className="text-xs text-muted-foreground">Total</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-severity-critical">{counts.actionable_count}</p>
            <p className="text-xs text-muted-foreground">Actionable</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-muted-foreground">{counts.deprioritized_count}</p>
            <p className="text-xs text-muted-foreground">Deprioritized</p>
          </div>
          <div>
            <p className="text-2xl font-bold">{counts.historical_only_count}</p>
            <p className="text-xs text-muted-foreground">Only in history</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
