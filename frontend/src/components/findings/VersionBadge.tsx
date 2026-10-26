import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export function VersionBadge({ version, className }: Readonly<{ version: string; className?: string }>) {
  return (
    <Badge variant="outline" className={cn('max-w-[160px]', className)} title={version}>
      <span className="min-w-0 truncate">{version}</span>
    </Badge>
  )
}
