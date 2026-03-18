import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
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
  TrendingUp,
  TrendingDown,
  Minus,
  Trophy,
  AlertTriangle,
  Users,
} from 'lucide-react'
import { useUpdateFrequencyComparison } from '@/hooks/queries/use-analytics'
import { useTeams } from '@/hooks/queries/use-teams'
import { formatDate } from '@/lib/utils'
import type { ProjectUpdateSummary } from '@/types/analytics'

const trendIcons = {
  improving: { icon: TrendingUp, color: 'text-green-500' },
  stable: { icon: Minus, color: 'text-gray-500' },
  deteriorating: { icon: TrendingDown, color: 'text-red-500' },
}

interface ComparisonSummaryData {
  readonly team_avg_updates_per_month: number
  readonly team_avg_coverage_pct: number
  readonly best_project?: string
  readonly worst_project?: string
  readonly projects: ProjectUpdateSummary[]
}

function ComparisonSummaryCards({ data }: Readonly<{ data: ComparisonSummaryData }>) {
  return (
    <div className="grid gap-4 md:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Avg Updates/Month</CardTitle>
          <Users className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.team_avg_updates_per_month}</div>
          <p className="text-xs text-muted-foreground">
            across {data.projects.length} projects
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Avg Coverage</CardTitle>
          <Users className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.team_avg_coverage_pct}%</div>
          <p className="text-xs text-muted-foreground">
            of outdated deps resolved
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Best Project</CardTitle>
          <Trophy className="h-4 w-4 text-green-500" />
        </CardHeader>
        <CardContent>
          <div className="text-lg font-bold truncate" title={data.best_project}>
            {data.best_project || '—'}
          </div>
          <p className="text-xs text-muted-foreground">highest update coverage</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Needs Attention</CardTitle>
          <AlertTriangle className="h-4 w-4 text-amber-500" />
        </CardHeader>
        <CardContent>
          <div className="text-lg font-bold truncate" title={data.worst_project}>
            {data.worst_project || '—'}
          </div>
          <p className="text-xs text-muted-foreground">lowest update coverage</p>
        </CardContent>
      </Card>
    </div>
  )
}

function ComparisonChart({ projects }: Readonly<{ projects: ProjectUpdateSummary[] }>) {
  const [metric, setMetric] = useState<'coverage' | 'updates'>('coverage')

  const chartData = projects.map((p) => ({
    name: p.project_name.length > 20 ? p.project_name.substring(0, 20) + '...' : p.project_name,
    fullName: p.project_name,
    value: metric === 'coverage' ? p.update_coverage_pct : p.updates_per_month,
  }))

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Project Comparison</CardTitle>
          <CardDescription>
            {metric === 'coverage' ? 'Update coverage percentage' : 'Updates per month'} by project
          </CardDescription>
        </div>
        <Select value={metric} onValueChange={(v) => setMetric(v as 'coverage' | 'updates')}>
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
        <div className="w-full min-w-0" style={{ height: Math.max(250, projects.length * 40) }}>
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
                formatter={(value: number) =>
                  metric === 'coverage' ? `${value}%` : value
                }
                labelFormatter={(_, payload) => payload?.[0]?.payload?.fullName || ''}
              />
              <Bar
                dataKey="value"
                fill="hsl(var(--primary))"
                radius={[0, 4, 4, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}

function getCoverageBadgeClass(pct: number): string {
  if (pct >= 70) return 'bg-green-500/10 text-green-600 border-green-500/20'
  if (pct >= 40) return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20'
  return 'bg-red-500/10 text-red-600 border-red-500/20'
}

function ProjectRankingTable({ projects }: Readonly<{ projects: ProjectUpdateSummary[] }>) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Project Ranking</CardTitle>
        <CardDescription>
          All projects ranked by update coverage and frequency
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
              {projects.map((project, idx) => {
                const trend = trendIcons[project.trend_direction] || trendIcons.stable
                const TrendIcon = trend.icon

                return (
                  <TableRow key={project.project_id}>
                    <TableCell className="text-muted-foreground">{idx + 1}</TableCell>
                    <TableCell className="font-medium">{project.project_name}</TableCell>
                    <TableCell className="text-muted-foreground">{project.team_name || '—'}</TableCell>
                    <TableCell className="text-right font-mono">{project.updates_per_month}</TableCell>
                    <TableCell className="text-right">
                      <Badge
                        variant="outline"
                        className={getCoverageBadgeClass(project.update_coverage_pct)}
                      >
                        {project.update_coverage_pct}%
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
      </CardContent>
    </Card>
  )
}

interface UpdateFrequencyComparisonProps {
  onSelectProject?: (projectId: string) => void
}

export function UpdateFrequencyComparison({ onSelectProject }: Readonly<UpdateFrequencyComparisonProps>) {
  const [selectedTeamId, setSelectedTeamId] = useState<string | undefined>(undefined)

  const { data: teamsData } = useTeams()
  const { data, isLoading, error } = useUpdateFrequencyComparison(selectedTeamId)

  return (
    <div className="space-y-6">
      {/* Header with team filter */}
      <Card>
        <CardHeader>
          <CardTitle>Update Frequency Comparison</CardTitle>
          <CardDescription>
            Compare how well projects keep their dependencies up to date
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
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
          </div>
        </CardContent>
      </Card>

      {/* Loading */}
      {isLoading && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-4">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={`cmp-skeleton-${i}`} className="h-28 w-full" />
            ))}
          </div>
          <Skeleton className="h-64 w-full" />
        </div>
      )}

      {/* Error */}
      {error && (
        <Card>
          <CardContent className="py-8">
            <div className="flex flex-col items-center gap-2 text-muted-foreground">
              <AlertTriangle className="h-12 w-12" />
              <p>Failed to load comparison data</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {data?.projects.length === 0 && (
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

      {/* Results */}
      {data?.projects.length > 0 && (
        <>
          <ComparisonSummaryCards data={data} />
          <ComparisonChart projects={data.projects} />
          <ProjectRankingTable projects={data.projects} />
        </>
      )}
    </div>
  )
}
