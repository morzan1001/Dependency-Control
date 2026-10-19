import { Badge } from '@/components/ui/badge'
import { CRYPTO_FINDING_TYPES, FINDING_TYPE_LABELS } from '@/lib/constants'
import { getFindingTypeBadgeClass } from '@/lib/finding-utils'
import {
  ShieldAlert,
  FileCode,
  Key,
  KeyRound,
  Bug,
  ServerCrash,
  FileText,
  Clock,
  Stamp,
  type LucideIcon,
} from 'lucide-react'

const TYPE_ICONS: Record<string, LucideIcon> = {
  vulnerability: ShieldAlert,
  secret: Key,
  sast: FileCode,
  iac: FileCode,
  system_warning: ServerCrash,
  outdated: Clock,
  license: Stamp,
  quality: FileText,
  eol: Clock,
  malware: Bug,
}

export function FindingTypeBadge({ type }: Readonly<{ type: string }>) {
  const key = type?.toLowerCase()
  const crypto = CRYPTO_FINDING_TYPES.find((entry) => entry.value === key)
  const Icon = TYPE_ICONS[key] ?? (crypto ? KeyRound : null)
  const known = FINDING_TYPE_LABELS[key] ?? crypto?.label
  const label = known ?? type

  return (
    <Badge
      variant={key === 'system_warning' ? 'destructive' : 'outline'}
      className={`${getFindingTypeBadgeClass(type)} inline-flex max-w-full items-center gap-1.5`}
      title={label}
    >
      {Icon && <Icon className="h-3 w-3 shrink-0" />}
      <span className={known ? 'truncate' : 'truncate capitalize'}>{label}</span>
    </Badge>
  )
}
