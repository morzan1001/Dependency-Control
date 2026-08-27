import { useMemo, useState } from 'react'
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
  RefreshCw,
  Users,
} from 'lucide-react'
import { useUpdateFrequencyComparison } from '@/hooks/queries/use-analytics'
import { useTeams } from '@/hooks/queries/use-teams'
import { formatDate, formatCoveragePct, formatUpdatesPerMonth } from '@/lib/utils'
import type { ProjectUpdateSummary, UpdateFrequencyComparison as Comparison } from '@/types/analytics'
import { AnalyticsErrorCard } from './AnalyticsErrorCard'
import { WindowSelect } from './WindowSelect'
import { TREND_CONFIG } from './trend-config'

type Metric = 'coverage' | 'updates'

const CHART_TOP_N = 25
const CHART_ANIMATION_MAX_BARS = 15
const TABLE_PAGE_SIZE = 25
// Ranking projects needs one shared window; the backend defaults to the same span.
const DEFAULT_WINDOW_DAYS = 90

interface RequestedFilters {
  teamId?: string
  windowDays?: number
}

function metricValue(project: ProjectUpdateSummary, metric: Metric): number {
  // An unmeasured value ranks below every measured one.
  if (metric === 'updates') return project.updates_per_month ?? -1
  return project.update_coverage_pct ?? -1
}

function ComparisonSummaryCards({ data }: Readonly<{ data: Comparison }>) {
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
            across {data.projects.length} projects
            {data.skipped_projects > 0 && ` · ${data.skipped_projects} skipped (need 2+ scans)`}
          </p>
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
            {data.best_project || '—'}
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
            {data.worst_project || '—'}
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
              ? `${metricLabel} — top ${CHART_TOP_N} of ${projects.length} projects`
              : `${metricLabel} by project`}
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

function ProjectRankingTable({ projects }: Readonly<{ projects: ProjectUpdateSummary[] }>) {
  const [requestedPage, setPage] = useState(1)

  const totalPages = Math.max(1, Math.ceil(projects.length / TABLE_PAGE_SIZE))
  // A shorter project list can strand the page index past the last page.
  const page = Math.min(requestedPage, totalPages)
  const offset = (page - 1) * TABLE_PAGE_SIZE
  const visible = projects.slice(offset, offset + TABLE_PAGE_SIZE)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Project Ranking</CardTitle>
        <CardDescription>
          {projects.length} projects ranked by update coverage and frequency
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-background z-10 shadow-sm">
              <TableRow>
                <TableHead>#</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Team</TableHead>
                <TableHead className="text-right">Updates/Mo</TableHead>
                <TableHead className="text-right">Coverage</TableHead>
                <TableHead className="text-right">Patch %</TableHead>
                <TableHead className="text-center">Trend</TableHead>
                <TableHead className="text-right">Outdated</TableHead>
                <TableHead>Last Scan</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((project, idx) => {
                const trend = TREND_CONFIG[project.trend_direction] ?? TREND_CONFIG.stable
                const TrendIcon = trend.icon

                return (
                  <TableRow key={project.project_id}>
                    <TableCell className="text-muted-foreground">{offset + idx + 1}</TableCell>
                    <TableCell className="font-medium">{project.project_name}</TableCell>
                    <TableCell className="text-muted-foreground">{project.team_name || '—'}</TableCell>
                    <TableCell className="text-right font-mono">{formatUpdatesPerMonth(project.updates_per_month)}</TableCell>
                    <TableCell className="text-right">
                      <Badge
                        variant="outline"
                        className={getCoverageBadgeClass(project.update_coverage_pct)}
                      >
                        {formatCoveragePct(project.update_coverage_pct)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {(project.patch_ratio * 100).toFixed(0)}%
                    </TableCell>
                    <TableCell className="text-center">
                      <TrendIcon className={`h-4 w-4 inline ${trend.color}`} />
                    </TableCell>
                    <TableCell className="text-right">{project.total_outdated}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatDate(project.last_scan_date)}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
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
              : 'Replays the scan history of every project in scope and can take several minutes.'}
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
              <p>No projects with enough scan history found</p>
              <p className="text-sm">Projects need at least 2 completed scans for comparison</p>
            </div>
          </CardContent>
        </Card>
      )}

      {comparison && comparison.projects.length > 0 && !isFetching && (
        <>
          <ComparisonSummaryCards data={comparison} />
          <ComparisonChart projects={comparison.projects} />
          <ProjectRankingTable projects={comparison.projects} />
        </>
      )}
    </div>
  )
}
