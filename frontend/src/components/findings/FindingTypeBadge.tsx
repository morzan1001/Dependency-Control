/**
 * FindingTypeBadge component
 * Displays finding type with consistent color coding
 */

import { Badge } from '@/components/ui/badge'
import { 
  ShieldAlert, 
  FileCode, 
  Key, 
  ServerCrash,
  FileText,
  Clock,
  Stamp
} from 'lucide-react'

interface FindingTypeBadgeProps {
  type: string
  className?: string
}

export function FindingTypeBadge({ type, className = '' }: FindingTypeBadgeProps) {
  const getBadgeStyle = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'vulnerability':
        return {
          variant: 'outline' as const,
          className: 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100',
          icon: ShieldAlert,
          label: 'Vulnerability'
        }
      case 'secret':
        return {
          variant: 'outline' as const,
          className: 'border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100',
          icon: Key,
          label: 'Secret'
        }
      case 'sast':
        return {
          variant: 'outline' as const,
          className: 'border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100',
          icon: FileCode,
          label: 'SAST'
        }
      case 'iac':
        return {
          variant: 'outline' as const,
          className: 'border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100',
          icon: FileCode,
          label: 'IaC'
        }
      case 'system_warning':
        return {
          variant: 'destructive' as const,
          className: 'bg-destructive/90 hover:bg-destructive',
          icon: ServerCrash,
          label: 'System Error'
        }
      case 'outdated':
        return {
          variant: 'outline' as const,
          className: 'border-yellow-200 bg-yellow-50 text-yellow-700 hover:bg-yellow-100',
          icon: Clock,
          label: 'Outdated'
        }
      case 'license':
        return {
          variant: 'outline' as const,
          className: 'border-purple-200 bg-purple-50 text-purple-700 hover:bg-purple-100',
          icon: Stamp,
          label: 'License'
        }
      case 'quality':
        return {
          variant: 'outline' as const,
          className: 'border-green-200 bg-green-50 text-green-700 hover:bg-green-100',
          icon: FileText,
          label: 'Quality'
        }
      case 'eol':
        return {
          variant: 'outline' as const,
          className: 'border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100',
          icon: Clock,
          label: 'EOL'
        }
      default:
        return {
          variant: 'outline' as const,
          className: '',
          icon: null,
          label: type
        }
    }
  }

  const style = getBadgeStyle(type)
  const Icon = style.icon

  return (
    <Badge 
      variant={style.variant}
      className={`${style.className} flex items-center gap-1.5 ${className}`}
    >
      {Icon && <Icon className="h-3 w-3" />}
      <span className="capitalize">{style.label}</span>
    </Badge>
  )
}

/**
 * Displays multiple finding types as a row of badges
 */
interface FindingTypeBadgesProps {
  primaryType: string
  additionalTypes?: Array<{ type: string; severity?: string }>
  className?: string
}

export function FindingTypeBadges({ primaryType, additionalTypes, className = '' }: FindingTypeBadgesProps) {
  return (
    <div className={`flex flex-wrap gap-1 ${className}`}>
      <Badge variant="outline">{primaryType}</Badge>
      {additionalTypes?.map((addType, idx) => (
        <FindingTypeBadge key={idx} type={addType.type} />
      ))}
    </div>
  )
}
