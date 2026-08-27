import { AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { getErrorMessage } from '@/lib/utils'

interface AnalyticsErrorCardProps {
  title: string
  error: unknown
  onRetry: () => void
}

export function AnalyticsErrorCard({ title, error, onRetry }: Readonly<AnalyticsErrorCardProps>) {
  return (
    <Card>
      <CardContent className="py-8">
        <div role="alert" className="flex flex-col items-center gap-2 text-center text-muted-foreground">
          <AlertTriangle className="h-12 w-12" />
          <p>{title}</p>
          <p className="text-sm">{getErrorMessage(error)}</p>
          <Button variant="outline" size="sm" onClick={onRetry}>
            Retry
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
