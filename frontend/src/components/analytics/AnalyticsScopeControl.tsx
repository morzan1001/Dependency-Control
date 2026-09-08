import { Info } from 'lucide-react'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { useAnalyticsScope } from '@/hooks/queries/use-analytics'
import { formatDate } from '@/lib/utils'

const HEAD_MODE = '__head__'
const HEAD_MODE_LABEL = 'Latest scan'
const SCOPE_LABEL = 'Analytics scope'
const headOnlyNote = (tab: string) => `The ${tab} tab always reports the latest scan, so the release view is off here.`
const asOfNote = (date: string) => `Vulnerabilities published since then are not in these numbers; the oldest analysis behind them ran ${date}.`

interface AnalyticsScopeControlProps {
  releaseEnvironment?: string
  onChange: (releaseEnvironment: string | undefined) => void
  // Label of the tab on screen when no endpoint behind it can answer for a release.
  headOnlyTab?: string
}

export function AnalyticsScopeControl({ releaseEnvironment, onChange, headOnlyTab }: Readonly<AnalyticsScopeControlProps>) {
  const { data: scope } = useAnalyticsScope(releaseEnvironment)
  const environments = scope?.release_environments ?? []

  return (
    <div className="space-y-3">
      {/* Nothing was ever marked as released, so a switch would offer only the mode already in use. */}
      {environments.length > 0 && (
        <div className="space-y-1">
          <Select
            value={releaseEnvironment ?? HEAD_MODE}
            onValueChange={(value) => onChange(value === HEAD_MODE ? undefined : value)}
            disabled={headOnlyTab !== undefined}
          >
            <SelectTrigger className="w-[240px]" aria-label={SCOPE_LABEL}><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value={HEAD_MODE}>{HEAD_MODE_LABEL}</SelectItem>
              {environments.map((environment) => (
                <SelectItem key={environment} value={environment}>{`${environment} release`}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {headOnlyTab !== undefined && (
            <p className="text-xs text-muted-foreground">{headOnlyNote(headOnlyTab)}</p>
          )}
        </div>
      )}
      {/* Coverage carries the whole page: the bare-list tabs beside it return no counters, so a
          partly resolved fleet would otherwise read as a small healthy one. */}
      {scope !== undefined && scope.projects_without_release > 0 && (
        <div className="flex items-start gap-2 rounded-md border border-info/30 bg-info/10 px-3 py-2 text-sm">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-info" />
          <p>
            {`Counted ${scope.resolved_projects} of ${scope.resolved_projects + scope.projects_without_release} projects; ${scope.projects_without_release} contributed no scan to this scope.`}
          </p>
        </div>
      )}
      {/* A release is a build nobody rebuilt, so its findings are the landscape of its analysis
          date. Head is the freshest analysis there is and can still be months old. */}
      {scope?.oldest_analysis_at && (
        <p className="text-xs text-muted-foreground">{asOfNote(formatDate(scope.oldest_analysis_at))}</p>
      )}
    </div>
  )
}
