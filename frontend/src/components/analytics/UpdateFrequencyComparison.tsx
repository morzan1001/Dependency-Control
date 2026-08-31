import { useMemo, useState, type ReactNode } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import {
  Trophy,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Clock,
  GitBranch,
  Hourglass,
  Info,
  RefreshCw,
  Users,
} from 'lucide-react'
import {
  Tooltip as HintTooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { useUpdateFrequencyComparison } from '@/hooks/queries/use-analytics'
import { useTeams } from '@/hooks/queries/use-teams'
import { formatDate, formatCoveragePct, formatUpdatesPerMonth } from '@/lib/utils'
import type {
  ProjectUpdateSummary,
  UpdateDataStatus,
  UpdateFrequencyComparison as Comparison,
} from '@/types/analytics'
import { AnalyticsErrorCard } from './AnalyticsErrorCard'
import { WindowSelect } from './WindowSelect'
import { TREND_CONFIG } from './trend-config'

type Metric = 'coverage' | 'updates'

const CHART_TOP_N = 25
const CHART_ANIMATION_MAX_BARS = 15
const TABLE_PAGE_SIZE = 25
// Ranking projects needs one shared window; the backend defaults to the same span.
const DEFAULT_WINDOW_DAYS = 90

const NO_VALUE = '—'

// A column header whose figure has non-obvious window semantics carries an info
// affordance; the copy is the only place a reader learns what the number counts.
function HintHeader({
  children,
  hint,
  align = 'left',
}: Readonly<{ children: ReactNode; hint: string; align?: 'left' | 'right' }>) {
  return (
    <TableHead className={align === 'right' ? 'text-right' : undefined}>
      <HintTooltip>
        <TooltipTrigger className={`inline-flex items-center gap-1 ${align === 'right' ? 'flex-row-reverse' : ''}`}>
          {children}
          <Info className="h-3 w-3 text-muted-foreground" aria-label={hint} />
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">{hint}</TooltipContent>
      </HintTooltip>
    </TableHead>
  )
}

// A partial row carries numbers, so it is not one of these: it renders its metrics
// with a caveat instead of a placeholder.
const STATUS_CONFIG: Record<
  Exclude<UpdateDataStatus, 'ready' | 'partial'>,
  { label: string; hint: string; icon: typeof Clock; className: string }
> = {
  pending: {
    label: 'Not computed yet',
    hint: 'No update metrics recorded for this project yet.',
    icon: Clock,
    className: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  },
  insufficient_data: {
    label: 'Too few scans',
    hint: 'Fewer than 2 comparable scans in this window.',
    icon: Hourglass,
    className: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  },
  error: {
    label: 'Measurement failed',
    hint: 'Recording the update metrics for this project failed.',
    icon: AlertTriangle,
    className: 'bg-red-500/10 text-red-600 border-red-500/20',
  },
}

interface RequestedFilters {
  teamId?: string
  windowDays?: number
}

// Only a fully covered project may be ranked, charted or averaged against the rest.
function isMeasured(project: ProjectUpdateSummary): boolean {
  return project.data_status === 'ready'
}

function metricValue(project: ProjectUpdateSummary, metric: Metric): number {
  // An unmeasured value ranks below every measured one.
  if (metric === 'updates') return project.updates_per_month ?? -1
  return project.update_coverage_pct ?? -1
}

function StatusBadge({ status }: Readonly<{ status: Exclude<UpdateDataStatus, 'ready' | 'partial'> }>) {
  const config = STATUS_CONFIG[status]
  const StatusIcon = config.icon

  return (
    <Badge variant="outline" className={`gap-1 whitespace-nowrap font-normal ${config.className}`} title={config.hint}>
      <StatusIcon className="h-3 w-3" />
      {config.label}
    </Badge>
  )
}

function partialHint(scanCount: number | null): string {
  const scans = scanCount === null ? 'only part of' : `only ${scanCount} scans of`
  return (
    `Measured on ${scans} this window. The numbers are exact for those scans, but they ` +
    'cover a shorter stretch than a fully measured project, so this row carries no rank ' +
    'and stays out of the team averages.'
  )
}

function PartialBadge({ scanCount }: Readonly<{ scanCount: number | null }>) {
  return (
    <Badge
      variant="outline"
      className="gap-1 whitespace-nowrap font-normal bg-blue-500/10 text-blue-600 border-blue-500/20"
      title={partialHint(scanCount)}
    >
      <Info className="h-3 w-3" />
      Partial window
    </Badge>
  )
}

function unmeasuredNote(data: Comparison): string | null {
  const parts = [
    data.partial_projects > 0 && `${data.partial_projects} on a partial window`,
    data.pending_projects > 0 && `${data.pending_projects} not computed yet`,
    data.skipped_insufficient_data > 0 && `${data.skipped_insufficient_data} with too few scans`,
    data.skipped_error > 0 && `${data.skipped_error} failed`,
  ].filter((part): part is string => typeof part === 'string')

  return parts.length > 0 ? parts.join(' · ') : null
}

function PendingBanner({ count }: Readonly<{ count: number }>) {
  return (
    <Card className="border-dashed">
      <CardContent className="flex items-start gap-3 py-4">
        <Clock className="h-5 w-5 shrink-0 text-muted-foreground" />
        <div className="space-y-1 text-sm">
          <p className="font-medium">{count} project{count === 1 ? '' : 's'} not computed yet</p>
          <p className="text-muted-foreground">
            Update metrics are recorded while a scan is ingested, so a project stays blank until two of
            its scans have run through. It is listed without numbers and left out of the team averages.
            Reload the comparison once those scans have finished.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

function PartialBanner({ count }: Readonly<{ count: number }>) {
  return (
    <Card className="border-dashed">
      <CardContent className="flex items-start gap-3 py-4">
        <Info className="h-5 w-5 shrink-0 text-muted-foreground" />
        <div className="space-y-1 text-sm">
          <p className="font-medium">
            {count} project{count === 1 ? '' : 's'} measured on part of the window
          </p>
          <p className="text-muted-foreground">
            Their numbers are exact for the scans they cover, but those scans span a shorter
            stretch than the window holds — usually because the update metrics of the older
            scans have not been recorded yet. Each is listed with its numbers and left out of
            the ranking and the team averages, so a project measured over three weeks is not
            compared with one measured over three months.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

function ComparisonSummaryCards({ data, measuredCount }: Readonly<{ data: Comparison; measuredCount: number }>) {
  const unmeasured = unmeasuredNote(data)

  return (
    <div className="grid gap-4 md:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Avg Updates/Month</CardTitle>
          <Users className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatUpdatesPerMonth(data.team_avg_updates_per_month)}</div>
          <p className="text-xs text-muted-foreground">
            across {measuredCount} measured project{measuredCount === 1 ? '' : 's'}
          </p>
          {unmeasured && <p className="text-xs text-muted-foreground">{unmeasured}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Avg Coverage</CardTitle>
          <Users className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatCoveragePct(data.team_avg_coverage_pct)}</div>
          <p className="text-xs text-muted-foreground">
            {data.team_avg_coverage_pct === null ? 'no measurable coverage' : 'of outdated deps resolved'}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Best Project</CardTitle>
          <Trophy className="h-4 w-4 text-green-500" />
        </CardHeader>
        <CardContent>
          <div className="text-lg font-bold truncate" title={data.best_project ?? undefined}>
            {data.best_project || NO_VALUE}
          </div>
          <p className="text-xs text-muted-foreground">highest measured coverage</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Needs Attention</CardTitle>
          <AlertTriangle className="h-4 w-4 text-amber-500" />
        </CardHeader>
        <CardContent>
          <div className="text-lg font-bold truncate" title={data.worst_project ?? undefined}>
            {data.worst_project || NO_VALUE}
          </div>
          <p className="text-xs text-muted-foreground">lowest measured coverage</p>
        </CardContent>
      </Card>
    </div>
  )
}

function ComparisonChart({ projects }: Readonly<{ projects: ProjectUpdateSummary[] }>) {
  const [metric, setMetric] = useState<Metric>('coverage')

  const chartData = useMemo(
    () =>
      [...projects]
        .sort((a, b) => metricValue(b, metric) - metricValue(a, metric))
        .slice(0, CHART_TOP_N)
        .map((p) => ({
          name: p.project_name.length > 20 ? p.project_name.substring(0, 20) + '...' : p.project_name,
          fullName: p.project_name,
          // An unmeasured value leaves a gap rather than a zero bar.
          value: (metric === 'coverage' ? p.update_coverage_pct : p.updates_per_month) ?? undefined,
        })),
    [projects, metric]
  )

  const metricLabel = metric === 'coverage' ? 'Update coverage percentage' : 'Updates per month'

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Project Comparison</CardTitle>
          <CardDescription>
            {projects.length > CHART_TOP_N
              ? `${metricLabel} — top ${CHART_TOP_N} of ${projects.length} measured projects`
              : `${metricLabel} by measured project`}
          </CardDescription>
        </div>
        <Select value={metric} onValueChange={(v) => setMetric(v as Metric)}>
          <SelectTrigger className="w-[180px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="coverage">Coverage %</SelectItem>
            <SelectItem value="updates">Updates/Month</SelectItem>
          </SelectContent>
        </Select>
      </CardHeader>
      <CardContent>
        <div className="w-full min-w-0" style={{ height: Math.max(250, chartData.length * 40) }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis type="number" className="text-xs" />
              <YAxis dataKey="name" type="category" width={150} className="text-xs" />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--background))',
                  borderColor: 'hsl(var(--border))',
                }}
                itemStyle={{ color: 'hsl(var(--foreground))' }}
                formatter={(value) =>
                  metric === 'coverage' ? `${value}%` : value
                }
                labelFormatter={(_, payload) => payload?.[0]?.payload?.fullName || ''}
              />
              <Bar
                dataKey="value"
                fill="hsl(var(--primary))"
                radius={[0, 4, 4, 0]}
                isAnimationActive={chartData.length <= CHART_ANIMATION_MAX_BARS}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}

function getCoverageBadgeClass(pct: number | null): string {
  if (pct === null) return 'bg-gray-500/10 text-gray-500 border-gray-500/20'
  if (pct >= 70) return 'bg-green-500/10 text-green-600 border-green-500/20'
  if (pct >= 40) return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20'
  return 'bg-red-500/10 text-red-600 border-red-500/20'
}

function MeasuredCells({ project }: Readonly<{ project: ProjectUpdateSummary }>) {
  const trend = TREND_CONFIG[project.trend_direction ?? 'unknown'] ?? TREND_CONFIG.unknown
  const TrendIcon = trend.icon

  return (
    <>
      <TableCell className="text-right font-mono">{formatUpdatesPerMonth(project.updates_per_month)}</TableCell>
      <TableCell className="text-right">
        <Badge variant="outline" className={getCoverageBadgeClass(project.update_coverage_pct)}>
          {formatCoveragePct(project.update_coverage_pct)}
        </Badge>
      </TableCell>
      <TableCell className="text-right font-mono">
        {project.patch_ratio === null ? NO_VALUE : `${(project.patch_ratio * 100).toFixed(0)}%`}
      </TableCell>
      <TableCell className="text-center">
        <TrendIcon className={`h-4 w-4 inline ${trend.color}`} />
        <span className="sr-only">{trend.label}</span>
      </TableCell>
      <TableCell className="text-right">{project.total_outdated ?? NO_VALUE}</TableCell>
      <TableCell className="text-xs text-muted-foreground">{formatDate(project.last_scan_date)}</TableCell>
    </>
  )
}

function ProjectRankingTable({ projects }: Readonly<{ projects: ProjectUpdateSummary[] }>) {
  const [requestedPage, setPage] = useState(1)

  const totalPages = Math.max(1, Math.ceil(projects.length / TABLE_PAGE_SIZE))
  // A shorter project list can strand the page index past the last page.
  const page = Math.min(requestedPage, totalPages)
  const offset = (page - 1) * TABLE_PAGE_SIZE
  const visible = projects.slice(offset, offset + TABLE_PAGE_SIZE)
  // Ranked rows lead the list, so a row's position is its rank up to that count.
  const rankedCount = projects.filter(isMeasured).length

  return (
    <Card>
      <CardHeader>
        <CardTitle>Project Ranking</CardTitle>
        <CardDescription>
          {rankedCount === projects.length
            ? `${rankedCount} projects ranked by update coverage and frequency`
            : `${rankedCount} of ${projects.length} projects ranked by update coverage and frequency; the rest are listed unranked`}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <TooltipProvider delayDuration={200}>
          <Table>
            <TableHeader className="sticky top-0 bg-background z-10 shadow-sm">
              <TableRow>
                <TableHead>#</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Branch</TableHead>
                <TableHead>Team</TableHead>
                <HintHeader align="right" hint="Version changes per month, measured over the selected window (updates ÷ window in months). Not extrapolated from scan spacing.">
                  Updates/Mo
                </HintHeader>
                <HintHeader align="right" hint="Of the packages that were outdated at some point in the window, the share later brought up to date.">
                  Coverage
                </HintHeader>
                <HintHeader align="right" hint="Share of the counted updates that were patch-level (x.y.Z).">
                  Patch %
                </HintHeader>
                <TableHead className="text-center">Trend</TableHead>
                <HintHeader align="right" hint="Distinct packages outdated at any point in the window, not the number outdated right now.">
                  Outdated
                </HintHeader>
                <TableHead>Last Scan</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((project, idx) => (
                <TableRow key={project.project_id}>
                  <TableCell className="text-muted-foreground">
                    {isMeasured(project) ? offset + idx + 1 : NO_VALUE}
                  </TableCell>
                  <TableCell className="font-medium">
                    <span className="inline-flex flex-wrap items-center gap-2">
                      {project.project_name}
                      {project.data_status === 'partial' && <PartialBadge scanCount={project.scan_count} />}
                    </span>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {project.branch ? (
                      <span className="inline-flex items-center gap-1 font-mono text-xs">
                        <GitBranch className="h-3 w-3" />
                        {project.branch}
                      </span>
                    ) : (
                      NO_VALUE
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{project.team_name || NO_VALUE}</TableCell>
                  {project.data_status === 'ready' || project.data_status === 'partial' ? (
                    <MeasuredCells project={project} />
                  ) : (
                    // One spanning cell keeps unmeasured rows from parking a value under a metric header.
                    <TableCell colSpan={6}>
                      <StatusBadge status={project.data_status} />
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </TooltipProvider>
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-end gap-2 py-4 text-sm text-muted-foreground">
            Page {page} of {totalPages}
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              <ChevronLeft className="h-4 w-4" /> Previous
            </Button>
            <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function UpdateFrequencyComparison() {
  const [selectedTeamId, setSelectedTeamId] = useState<string | undefined>(undefined)
  const [windowDays, setWindowDays] = useState<number | undefined>(DEFAULT_WINDOW_DAYS)
  const [requested, setRequested] = useState<RequestedFilters | null>(null)

  const { data: teamsData } = useTeams()
  const { data, isFetching, error, refetch } = useUpdateFrequencyComparison(
    requested?.teamId,
    { windowDays: requested?.windowDays },
    requested !== null
  )

  // A disabled query still hands back whatever sits in the cache for its key.
  const comparison = requested === null ? undefined : data
  const loadError = requested === null ? null : error

  const measuredProjects = useMemo(() => (comparison?.projects ?? []).filter(isMeasured), [comparison])

  const filtersDirty =
    requested === null || requested.teamId !== selectedTeamId || requested.windowDays !== windowDays

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Update Frequency Comparison</CardTitle>
          <CardDescription>
            Compare how well projects keep their dependencies up to date
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex flex-wrap items-center gap-4">
            <Select
              value={selectedTeamId || 'all'}
              onValueChange={(v) => setSelectedTeamId(v === 'all' ? undefined : v)}
            >
              <SelectTrigger className="w-[250px]">
                <SelectValue placeholder="All teams" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Teams</SelectItem>
                {teamsData?.map((team) => (
                  <SelectItem key={team.id} value={team.id}>
                    {team.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <WindowSelect value={windowDays} onChange={setWindowDays} allowScans={false} />
            <Button
              variant="outline"
              disabled={isFetching}
              onClick={() =>
                filtersDirty ? setRequested({ teamId: selectedTeamId, windowDays }) : refetch()
              }
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
              {filtersDirty ? 'Load comparison' : 'Reload comparison'}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            {filtersDirty && requested !== null
              ? 'Filters changed — load the comparison to apply them.'
              : 'Ranks every project in scope over one shared window; an uncached run can take a while.'}
          </p>
        </CardContent>
      </Card>

      {isFetching && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-4">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={`cmp-skeleton-${i}`} className="h-28 w-full" />
            ))}
          </div>
          <Skeleton className="h-64 w-full" />
        </div>
      )}

      {loadError && !isFetching && (
        <AnalyticsErrorCard
          title="Failed to load comparison data"
          error={loadError}
          onRetry={() => refetch()}
        />
      )}

      {requested === null && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4 text-muted-foreground">
              <Users className="h-12 w-12" />
              <p>Pick a team and time window, then load the comparison</p>
            </div>
          </CardContent>
        </Card>
      )}

      {comparison?.projects.length === 0 && !isFetching && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4 text-muted-foreground">
              <Users className="h-12 w-12" />
              <p>No projects in this scope</p>
              <p className="text-sm">Projects without enough scans are listed too, so this means the filter matched none</p>
            </div>
          </CardContent>
        </Card>
      )}

      {comparison && comparison.projects.length > 0 && !isFetching && (
        <>
          <ComparisonSummaryCards data={comparison} measuredCount={measuredProjects.length} />
          {comparison.partial_projects > 0 && <PartialBanner count={comparison.partial_projects} />}
          {comparison.pending_projects > 0 && <PendingBanner count={comparison.pending_projects} />}
          {measuredProjects.length > 0 && <ComparisonChart projects={measuredProjects} />}
          <ProjectRankingTable projects={comparison.projects} />
        </>
      )}
    </div>
  )
}
