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
import { getSeverityBgColor } from '@/lib/finding-utils'

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
    CRITICAL: { color: 'bg-red-500', icon: AlertOctagon },
    HIGH: { color: 'bg-orange-500', icon: AlertTriangle },
    MEDIUM: { color: 'bg-yellow-500 text-black', icon: AlertCircle },
    LOW: { color: 'bg-blue-500', icon: Info },
    INFO: { color: 'bg-gray-500', icon: Info },
    UNKNOWN: { color: 'bg-gray-400', icon: CircleAlert },
  }
  return configs[severity?.toUpperCase()] || { color: 'bg-gray-400', icon: CircleAlert }
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
  const colorClass = {
    CRITICAL: 'text-red-600 dark:text-red-400',
    HIGH: 'text-orange-600 dark:text-orange-400',
    MEDIUM: 'text-yellow-600 dark:text-yellow-400',
    LOW: 'text-blue-600 dark:text-blue-400',
    INFO: 'text-gray-600 dark:text-gray-400',
  }[severity?.toUpperCase()] || 'text-gray-500'

  return <span className={`font-medium ${colorClass} ${className}`}>{severity}</span>
}
