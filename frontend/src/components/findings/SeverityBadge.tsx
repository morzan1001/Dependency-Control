/**
 * Reusable SeverityBadge component
 * Displays severity with consistent styling and icons across the application
 */

import { Badge } from '@/components/ui/badge'
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  CircleAlert,
  type LucideIcon,
} from 'lucide-react'
import { getSeverityBgColor, getSeverityColor } from '@/lib/finding-utils'

interface SeverityBadgeProps {
  severity: string
  showIcon?: boolean
  className?: string
}

interface SeverityConfig {
  color: string
  icon: LucideIcon
}

function getSeverityConfig(severity: string): SeverityConfig {
  const configs: Record<string, SeverityConfig> = {
    CRITICAL: { color: 'bg-severity-critical', icon: AlertOctagon },
    HIGH: { color: 'bg-severity-high', icon: AlertTriangle },
    MEDIUM: { color: 'bg-severity-medium text-severity-medium-foreground', icon: AlertCircle },
    LOW: { color: 'bg-severity-low', icon: Info },
    INFO: { color: 'bg-severity-info', icon: Info },
    UNKNOWN: { color: 'bg-muted', icon: CircleAlert },
  }
  return configs[severity?.toUpperCase()] || { color: 'bg-muted', icon: CircleAlert }
}

export function SeverityBadge({ severity, showIcon = true, className = '' }: SeverityBadgeProps) {
  const config = getSeverityConfig(severity)
  const Icon = config.icon

  return (
    <Badge className={`${config.color} hover:${config.color} text-white flex items-center gap-1 ${className}`}>
      {showIcon && <Icon className="h-3 w-3" />}
      {severity}
    </Badge>
  )
}

/**
 * Compact version for tables and lists
 */
export function SeverityBadgeCompact({ severity, className = '' }: { severity: string; className?: string }) {
  const bgColor = getSeverityBgColor(severity)

  return (
    <Badge className={`${bgColor} text-white text-xs px-1.5 py-0 ${className}`}>
      {severity}
    </Badge>
  )
}

/**
 * Inline text-only severity indicator
 */
export function SeverityText({ severity, className = '' }: { severity: string; className?: string }) {
  return <span className={`font-medium ${getSeverityColor(severity)} ${className}`}>{severity}</span>
}
