import { Badge } from '@/components/ui/badge'
import { CRYPTO_FINDING_TYPES, FINDING_TYPE_LABELS } from '@/lib/constants'
import { 
  ShieldAlert, 
  FileCode, 
  Key, 
  KeyRound,
  Bug,
  ServerCrash,
  FileText,
  Clock,
  Stamp
} from 'lucide-react'

export function FindingTypeBadge({ type }: Readonly<{ type: string }>) {
  const getBadgeStyle = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'vulnerability':
        return {
          variant: 'outline' as const,
          className: 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-800 dark:bg-red-950/50 dark:text-red-400 dark:hover:bg-red-900/50',
          icon: ShieldAlert
        }
      case 'secret':
        return {
          variant: 'outline' as const,
          className: 'border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100 dark:border-orange-800 dark:bg-orange-950/50 dark:text-orange-400 dark:hover:bg-orange-900/50',
          icon: Key
        }
      case 'sast':
        return {
          variant: 'outline' as const,
          className: 'border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100 dark:border-blue-800 dark:bg-blue-950/50 dark:text-blue-400 dark:hover:bg-blue-900/50',
          icon: FileCode
        }
      case 'iac':
        return {
          variant: 'outline' as const,
          className: 'border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100 dark:border-indigo-800 dark:bg-indigo-950/50 dark:text-indigo-400 dark:hover:bg-indigo-900/50',
          icon: FileCode
        }
      case 'system_warning':
        return {
          variant: 'destructive' as const,
          className: 'bg-destructive/90 hover:bg-destructive',
          icon: ServerCrash
        }
      case 'outdated':
        return {
          variant: 'outline' as const,
          className: 'border-yellow-200 bg-yellow-50 text-yellow-700 hover:bg-yellow-100 dark:border-yellow-800 dark:bg-yellow-950/50 dark:text-yellow-400 dark:hover:bg-yellow-900/50',
          icon: Clock
        }
      case 'license':
        return {
          variant: 'outline' as const,
          className: 'border-purple-200 bg-purple-50 text-purple-700 hover:bg-purple-100 dark:border-purple-800 dark:bg-purple-950/50 dark:text-purple-400 dark:hover:bg-purple-900/50',
          icon: Stamp
        }
      case 'quality':
        return {
          variant: 'outline' as const,
          className: 'border-green-200 bg-green-50 text-green-700 hover:bg-green-100 dark:border-green-800 dark:bg-green-950/50 dark:text-green-400 dark:hover:bg-green-900/50',
          icon: FileText
        }
      case 'eol':
        return {
          variant: 'outline' as const,
          className: 'border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100 dark:border-orange-800 dark:bg-orange-950/50 dark:text-orange-400 dark:hover:bg-orange-900/50',
          icon: Clock
        }
      case 'malware':
        return {
          variant: 'outline' as const,
          className: 'border-pink-200 bg-pink-50 text-pink-700 hover:bg-pink-100 dark:border-pink-800 dark:bg-pink-950/50 dark:text-pink-400 dark:hover:bg-pink-900/50',
          icon: Bug
        }
      default:
        if (CRYPTO_FINDING_TYPES.some((crypto) => crypto.value === type?.toLowerCase())) {
          return {
            variant: 'outline' as const,
            className: 'border-teal-200 bg-teal-50 text-teal-700 hover:bg-teal-100 dark:border-teal-800 dark:bg-teal-950/50 dark:text-teal-400 dark:hover:bg-teal-900/50',
            icon: KeyRound
          }
        }
        return {
          variant: 'outline' as const,
          className: '',
          icon: null
        }
    }
  }

  const style = getBadgeStyle(type)
  const Icon = style.icon
  const key = type?.toLowerCase()
  const known = FINDING_TYPE_LABELS[key] ?? CRYPTO_FINDING_TYPES.find((crypto) => crypto.value === key)?.label
  const label = known ?? type

  return (
    <Badge
      variant={style.variant}
      className={`${style.className} inline-flex max-w-full items-center gap-1.5`}
      title={label}
    >
      {Icon && <Icon className="h-3 w-3 shrink-0" />}
      <span className={known ? 'truncate' : 'truncate capitalize'}>{label}</span>
    </Badge>
  )
}
