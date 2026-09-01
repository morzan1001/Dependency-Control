import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS } from '@/lib/scan-status'

export function ScanStatusBadge({ status, failedAnalyzers }: { status: string; failedAnalyzers?: string[] }) {
  if (status === SCAN_STATUS_COMPLETED_WITH_ERRORS) {
    const failed = failedAnalyzers?.filter(Boolean) ?? []
    const detail = failed.length > 0
      ? `Failed analyzer${failed.length > 1 ? 's' : ''}: ${failed.join(', ')}`
      : 'One or more analyzers returned partial results.'
    const badge = (
      <Badge
        variant="secondary"
        aria-label={`completed with errors — ${detail}`}
        className="flex w-fit items-center gap-1 text-amber-600 border-amber-500/20 bg-amber-500/10 cursor-help"
      >
        <AlertTriangle className="h-3 w-3" />
        completed with errors
      </Badge>
    )
    return (
      <TooltipProvider delayDuration={200}>
        <Tooltip>
          <TooltipTrigger asChild>{badge}</TooltipTrigger>
          <TooltipContent className="max-w-xs">
            <p className="font-medium">{detail}</p>
            <p className="mt-1 text-muted-foreground">
              Other analyzers completed; the results shown are otherwise complete. This is usually a
              transient error at an upstream source (e.g. OSV.dev).
            </p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
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
