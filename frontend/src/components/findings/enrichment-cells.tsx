// Shared EPSS/KEV/exploit-maturity cells for the impact-analysis and hotspots
// tables; per-site output differences are preserved via explicit props.
import { Badge } from '@/components/ui/badge'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { AlertTriangle, Calendar, Lock, Shield } from 'lucide-react'
import { formatEpssScore } from '@/lib/finding-utils'

/** Text colour class for an EPSS probability (0-1 scale). */
function getEpssColorClass(score: number): string {
  if (score >= 0.1) return 'text-severity-critical'
  if (score >= 0.01) return 'text-severity-high'
  return 'text-muted-foreground'
}

interface EpssCellProps {
  score?: number | null
  percentile?: number | null
  /** 'hotspot' adds the "Top X%" sub-line and a different tooltip label; 'impact' omits them. */
  variant: 'impact' | 'hotspot'
}

export function EpssCell({ score, percentile, variant }: Readonly<EpssCellProps>) {
  if (score === undefined || score === null) {
    return <span className="text-muted-foreground text-xs">-</span>
  }
  const formatted = formatEpssScore(score)
  const tooltipLabel =
    variant === 'hotspot'
      ? `EPSS: ${formatted} probability of exploitation`
      : 'Probability of exploitation in next 30 days'
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="flex flex-col items-center">
          <span className={`font-medium ${getEpssColorClass(score)}`}>
            {formatted}
          </span>
          {variant === 'hotspot' && percentile !== undefined && percentile !== null && (
            <span className="text-xs text-muted-foreground">
              Top {(100 - percentile).toFixed(0)}%
            </span>
          )}
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <p>{tooltipLabel}</p>
        {percentile !== undefined && percentile !== null && (
          <p className="text-xs">Percentile: {percentile.toFixed(1)}%</p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}

interface KevCellProps {
  hasKev?: boolean
  kevCount?: number | null
  ransomwareUse?: boolean | null
  dueDate?: string | null
  /** When true the ransomware badge carries a "Ransomware" text label; when false it is icon-only. */
  ransomwareLabel?: boolean
}

export function KevCell({
  hasKev,
  kevCount,
  ransomwareUse,
  dueDate,
  ransomwareLabel = false,
}: Readonly<KevCellProps>) {
  if (!hasKev) {
    return <span className="text-muted-foreground text-xs">-</span>
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="flex flex-col items-center gap-1">
          <Badge variant="destructive" className="text-xs gap-1">
            <Shield className="h-3 w-3" />
            KEV{kevCount && kevCount > 1 ? ` (${kevCount})` : ''}
          </Badge>
          {ransomwareUse && (
            <Badge className="text-xs bg-purple-600 gap-1">
              <Lock className="h-3 w-3" />
              {ransomwareLabel ? 'Ransomware' : null}
            </Badge>
          )}
        </div>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <p className="font-medium">CISA Known Exploited Vulnerability</p>
        <p className="text-xs">Actively exploited in the wild</p>
        {ransomwareUse && (
          <p className="text-xs text-purple-400 mt-1 flex items-center gap-1"><AlertTriangle className="h-3 w-3" />Used in ransomware campaigns</p>
        )}
        {dueDate && (
          <p className="text-xs mt-1 flex items-center gap-1"><Calendar className="h-3 w-3" />Remediation due: {dueDate}</p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}

/** Returns null for unknown/absent maturity so callers can drop it directly inside a tooltip body. */
export function ExploitMaturityBadge({ maturity }: Readonly<{ maturity?: string }>) {
  if (!maturity || maturity === 'unknown') return null
  const colors: Record<string, string> = {
    active: 'bg-red-600 text-white',
    weaponized: 'bg-red-700 text-white',
    high: 'bg-severity-high text-severity-high-foreground',
    medium: 'bg-severity-medium text-severity-medium-foreground',
    low: 'bg-severity-low text-severity-low-foreground',
  }
  return (
    <Badge className={`text-xs ${colors[maturity] || 'bg-gray-500'}`}>
      {maturity}
    </Badge>
  )
}
