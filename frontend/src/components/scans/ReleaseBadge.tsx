import { Rocket } from 'lucide-react'
import { Badge } from '@/components/ui/badge'

interface ReleaseBadgeProps {
  environment?: string | null
  version?: string | null
  className?: string
}

export function ReleaseBadge({ environment, version, className = '' }: ReleaseBadgeProps) {
  const label = environment || 'release'
  const named = version ? `Release ${version}` : 'Release'
  const ariaLabel = environment ? `${named} in ${environment}` : named

  return (
    <Badge
      variant="outline"
      aria-label={ariaLabel}
      // The --success token carries its own light and dark value, so one class set covers both.
      className={`flex w-fit items-center gap-1.5 border-success/30 bg-success/10 text-success hover:bg-success/20 ${className}`}
    >
      <Rocket className="h-3 w-3" />
      <span>{label}</span>
      {version && <span className="font-mono text-[0.7rem] opacity-80">{version}</span>}
    </Badge>
  )
}
