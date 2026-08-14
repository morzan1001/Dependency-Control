import { Badge } from '@/components/ui/badge'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS } from '@/lib/scan-status'

export function ScanStatusBadge({ status }: { status: string }) {
  if (status === SCAN_STATUS_COMPLETED_WITH_ERRORS) {
    return (
      <Badge
        variant="secondary"
        className="flex w-fit items-center gap-1 text-amber-600 border-amber-500/20 bg-amber-500/10"
      >
        <AlertTriangle className="h-3 w-3" />
        completed with errors
      </Badge>
    )
  }
  return (
    <Badge
      variant={status === SCAN_STATUS_COMPLETED ? 'default' : 'secondary'}
      className="flex w-fit items-center gap-1"
    >
      {['pending', 'processing'].includes(status) && <Loader2 className="h-3 w-3 animate-spin" />}
      {status}
    </Badge>
  )
}
