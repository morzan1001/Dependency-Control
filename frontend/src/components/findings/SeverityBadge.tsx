import { Badge } from '@/components/ui/badge'
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  CircleAlert,
  type LucideIcon,
} from 'lucide-react'
import { getSeverityBgColor } from '@/lib/finding-utils'
import { cn } from '@/lib/utils'

interface SeverityBadgeProps {
  severity: string
  showIcon?: boolean
}

const SEVERITY_ICONS: Record<string, LucideIcon> = {
  CRITICAL: AlertOctagon,
  HIGH: AlertTriangle,
  MEDIUM: AlertCircle,
  LOW: Info,
  INFO: Info,
}

export function SeverityBadge({ severity, showIcon = true }: Readonly<SeverityBadgeProps>) {
  const Icon = SEVERITY_ICONS[severity?.toUpperCase()] ?? CircleAlert

  return (
    <Badge className={cn(getSeverityBgColor(severity), 'flex w-fit items-center gap-1')}>
      {showIcon && <Icon className="h-3 w-3" />}
      {severity}
    </Badge>
  )
}
