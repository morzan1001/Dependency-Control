import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Notice } from '@/components/analytics/ThreatIntelNote'
import { useAnalyticsScope } from '@/hooks/queries/use-analytics'
import { formatDate } from '@/lib/utils'

const HEAD_MODE = '__head__'
const HEAD_MODE_LABEL = 'Latest scan'
const SCOPE_LABEL = 'Analytics scope'
const headOnlyNote = (tab: string) => `The ${tab} tab always reports the latest scan, so the release view is off here.`
const asOfNote = (date: string) => `Vulnerabilities published since then are not in these numbers; the oldest analysis behind them ran ${date}.`

interface AnalyticsScopeProps {
  releaseEnvironment?: string
  // Label of the tab on screen when no endpoint behind it can answer for a release.
  headOnlyTab?: string
}

export function AnalyticsScopeSelect({
  releaseEnvironment,
  onChange,
  headOnlyTab,
}: Readonly<AnalyticsScopeProps & { onChange: (releaseEnvironment: string | undefined) => void }>) {
  const { data: scope } = useAnalyticsScope(releaseEnvironment)
  const environments = scope?.release_environments ?? []

  // Nothing was ever marked as released, so a switch would offer only the mode already in use.
  if (environments.length === 0) return null

  return (
    <Select
      value={releaseEnvironment ?? HEAD_MODE}
      onValueChange={(value) => onChange(value === HEAD_MODE ? undefined : value)}
      disabled={headOnlyTab !== undefined}
    >
      <SelectTrigger className="w-full shrink-0 sm:w-[180px]" aria-label={SCOPE_LABEL}><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value={HEAD_MODE}>{HEAD_MODE_LABEL}</SelectItem>
        {environments.map((environment) => (
          <SelectItem key={environment} value={environment}>{`${environment} release`}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

export function AnalyticsScopeNotes({ releaseEnvironment, headOnlyTab }: Readonly<AnalyticsScopeProps>) {
  const { data: scope } = useAnalyticsScope(releaseEnvironment)
  if (scope === undefined) return null

  const showHeadOnly = headOnlyTab !== undefined && scope.release_environments.length > 0
  // The bare-list tabs show no counters, so without coverage a partly resolved fleet reads as a small healthy one.
  const showCoverage = scope.projects_without_release > 0
  // Findings are as old as their analysis: a release is never rebuilt, and even head can be months old.
  const asOf = scope.oldest_analysis_at
  if (!showHeadOnly && !showCoverage && !asOf) return null

  return (
    <div className="space-y-2">
      {showCoverage && (
        <Notice tone="info">
          {`Counted ${scope.resolved_projects} of ${scope.resolved_projects + scope.projects_without_release} projects; ${scope.projects_without_release} contributed no scan to this scope.`}
        </Notice>
      )}
      {showHeadOnly && <p className="text-xs text-muted-foreground">{headOnlyNote(headOnlyTab)}</p>}
      {asOf && <p className="text-xs text-muted-foreground">{asOfNote(formatDate(asOf))}</p>}
    </div>
  )
}
