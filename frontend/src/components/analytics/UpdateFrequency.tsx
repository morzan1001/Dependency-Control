import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ProjectCombobox } from '@/components/ui/project-combobox'
import { WindowSelect } from './WindowSelect'
import { TREND_CONFIG } from './trend-config'
import {
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  Line,
  ComposedChart,
} from 'recharts'
import {
  RefreshCw,
  Clock,
  Package,
  ArrowRight,
  GitBranch,
} from 'lucide-react'
import { AnalyticsErrorCard } from './AnalyticsErrorCard'
import { useUpdateFrequency } from '@/hooks/queries/use-analytics'
import { formatDate, formatCoveragePct, formatUpdatesPerMonth } from '@/lib/utils'
import type { UpdateFrequencyMetrics, DependencyUpdateEvent } from '@/types/analytics'

interface UpdateFrequencyProps {
  projectId?: string
}

const updateTypeColors: Record<string, string> = {
  patch: '#22c55e',
  minor: '#eab308',
  major: '#ef4444',
  unknown: '#94a3b8',
  downgrade: '#a855f7',
}

const updateTypeBadgeVariants: Record<string, string> = {
  patch: 'bg-green-500/10 text-green-600 border-green-500/20',
  minor: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  major: 'bg-red-500/10 text-red-600 border-red-500/20',
  unknown: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  downgrade: 'bg-purple-500/10 text-purple-600 border-purple-500/20',
}

function formatDays(days: number): string {
  if (days < 1) return `${(days * 24).toFixed(1)}h`
  return `${days.toFixed(days < 10 ? 1 : 0)}d`
}

function SummaryCards({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  const trend = TREND_CONFIG[data.trend_direction] ?? TREND_CONFIG.unknown
  const TrendIcon = trend.icon
  const coverageKnown = data.update_coverage_pct !== null

  return (
    <div className="grid gap-4 md:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Updates / Month</CardTitle>
          <RefreshCw className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatUpdatesPerMonth(data.updates_per_month)}</div>
          <p className="text-xs text-muted-foreground">
            {data.total_updates} updates over {formatDays(data.time_range_days)}
            {data.updates_per_month === null && ' · pick a time window for a rate'}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Scan Cadence</CardTitle>
          <Clock className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatDays(data.avg_days_between_scans)}</div>
          <p className="text-xs text-muted-foreground">
            avg. between {data.scan_count} scans
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Update Coverage</CardTitle>
          <Package className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatCoveragePct(data.update_coverage_pct)}</div>
          <p className="text-xs text-muted-foreground">
            {coverageKnown
              ? `${data.outdated_resolved} of ${data.total_outdated_detected} outdated resolved`
              : 'no outdated backlog measured in this window'}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Trend</CardTitle>
          <TrendIcon className={`h-4 w-4 ${trend.color}`} />
        </CardHeader>
        <CardContent>
          <div className={`text-2xl font-bold ${trend.color}`}>{trend.label}</div>
          <p className="text-xs text-muted-foreground truncate" title={data.trend_detail}>
            {data.trend_detail}
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

function TimelineChart({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  const chartData = data.scan_timeline.map((entry) => ({
    ...entry,
    date: formatDate(entry.date, { month: 'short', day: 'numeric' }),
  }))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Update Timeline</CardTitle>
        <CardDescription>
          Dependency updates per scan interval, colored by update type
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[300px] w-full min-w-0">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis dataKey="date" className="text-xs" />
              <YAxis yAxisId="left" className="text-xs" />
              <YAxis yAxisId="right" orientation="right" className="text-xs" />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--background))',
                  borderColor: 'hsl(var(--border))',
                }}
                itemStyle={{ color: 'hsl(var(--foreground))' }}
              />
              <Legend />
              <Bar yAxisId="left" dataKey="patch" stackId="updates" fill={updateTypeColors.patch} name="Patch" />
              <Bar yAxisId="left" dataKey="minor" stackId="updates" fill={updateTypeColors.minor} name="Minor" />
              <Bar yAxisId="left" dataKey="major" stackId="updates" fill={updateTypeColors.major} name="Major" />
              <Bar yAxisId="left" dataKey="unknown" stackId="updates" fill={updateTypeColors.unknown} name="Unknown" />
              <Bar yAxisId="left" dataKey="downgrades" stackId="updates" fill={updateTypeColors.downgrade} name="Downgrade" />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="outdated_count"
                stroke="#94a3b8"
                strokeWidth={2}
                strokeDasharray="5 5"
                // Scans without an outdated analysis are null, and recharts draws no
                // segment next to a null: without dots an isolated measurement vanishes.
                dot={{ r: 2 }}
                name="Outdated"
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}

function GranularityChart({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  const pieData = [
    { name: 'Patch', value: data.patch_updates, color: updateTypeColors.patch },
    { name: 'Minor', value: data.minor_updates, color: updateTypeColors.minor },
    { name: 'Major', value: data.major_updates, color: updateTypeColors.major },
    { name: 'Unknown', value: data.unknown_updates, color: updateTypeColors.unknown },
  ].filter((d) => d.value > 0)

  if (pieData.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Update Granularity</CardTitle>
        <CardDescription>Share of forward updates by tier (patch, minor, major, unknown)</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[250px] w-full min-w-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                dataKey="value"
                label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
              >
                {pieData.map((entry) => (
                  <Cell key={`cell-${entry.name}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--background))',
                  borderColor: 'hsl(var(--border))',
                }}
                itemStyle={{ color: 'hsl(var(--foreground))' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}

function SlowPackagesTable({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  if (data.slowest_packages.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Slowest to Update</CardTitle>
        <CardDescription>
          Packages that remain outdated across the most scans
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-background z-10 shadow-sm">
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Current</TableHead>
                <TableHead>Latest</TableHead>
                <TableHead className="text-right">Scans Outdated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.slowest_packages.map((pkg) => (
                <TableRow key={pkg.name}>
                  <TableCell className="font-medium">{pkg.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">{pkg.type}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{pkg.current_version || '—'}</TableCell>
                  <TableCell className="font-mono text-xs">{pkg.latest_version || '—'}</TableCell>
                  <TableCell className="text-right">
                    <Badge variant="secondary">{pkg.scans_outdated}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}

function RecentUpdatesTable({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  if (data.recent_updates.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Updates</CardTitle>
        <CardDescription>
          Latest dependency version changes detected across scans
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-background z-10 shadow-sm">
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Version Change</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Date</TableHead>
                <TableHead>Was Outdated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.recent_updates.map((event: DependencyUpdateEvent, idx: number) => (
                <TableRow key={`${event.package_name}-${idx}`}>
                  <TableCell className="font-medium">{event.package_name}</TableCell>
                  <TableCell>
                    <span className="font-mono text-xs flex items-center gap-1">
                      {event.old_version}
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      {event.new_version}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-xs ${updateTypeBadgeVariants[event.update_type] || ''}`}
                    >
                      {event.update_type}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDate(event.scan_date)}
                  </TableCell>
                  <TableCell>
                    {event.was_outdated && (
                      <Badge variant="outline" className="text-xs bg-amber-500/10 text-amber-600 border-amber-500/20">
                        outdated
                      </Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}

function UpstreamCadenceCard({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  const metrics = [
    { label: 'Releases / 12 mo', value: data.upstream_releases_last_12m_median, suffix: '', digits: 1 },
    { label: 'Days between releases', value: data.upstream_days_between_releases_median, suffix: 'd', digits: 0 },
    { label: 'Days since latest release', value: data.upstream_days_since_latest_release_median, suffix: 'd', digits: 0 },
    { label: 'Adoption latency', value: data.adoption_latency_days_median, suffix: 'd', digits: 0 },
  ]

  if (metrics.every((m) => m.value === null)) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Upstream Release Cadence</CardTitle>
        <CardDescription>
          How often your dependencies publish upstream (median across packages, via deps.dev), independent of your scan
          frequency
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          {metrics.map((m) => (
            <div key={m.label}>
              <div className="text-2xl font-bold">
                {m.value === null ? '—' : `${m.value.toFixed(m.digits)}${m.suffix}`}
              </div>
              <p className="text-xs text-muted-foreground">{m.label}</p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function UpdateFrequency({ projectId: initialProjectId }: Readonly<UpdateFrequencyProps>) {
  const [selectedProjectId, setSelectedProjectId] = useState<string>(initialProjectId || '')
  const [windowDays, setWindowDays] = useState<number | undefined>(90)

  const { data, isFetching, error, refetch } = useUpdateFrequency(selectedProjectId, { windowDays })

  return (
    <div className="space-y-6">
      {!initialProjectId && (
        <Card>
          <CardHeader>
            <CardTitle>Update Frequency</CardTitle>
            <CardDescription>
              Analyze how regularly and incrementally your project updates its dependencies
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap items-center gap-4">
              <ProjectCombobox
                value={selectedProjectId}
                onValueChange={setSelectedProjectId}
                className="w-[350px]"
              />
              <WindowSelect value={windowDays} onChange={setWindowDays} />
            </div>
          </CardContent>
        </Card>
      )}

      {initialProjectId && selectedProjectId && (
        <div className="flex justify-end">
          <WindowSelect value={windowDays} onChange={setWindowDays} />
        </div>
      )}

      {isFetching && selectedProjectId && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-4">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={`skeleton-${i}`} className="h-28 w-full" />
            ))}
          </div>
          <Skeleton className="h-80 w-full" />
        </div>
      )}

      {error && !isFetching && (
        <AnalyticsErrorCard
          title="Failed to load update frequency data"
          error={error}
          onRetry={() => refetch()}
        />
      )}

      {!selectedProjectId && !initialProjectId && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4 text-muted-foreground">
              <RefreshCw className="h-12 w-12" />
              <p>Select a project to analyze its update frequency</p>
            </div>
          </CardContent>
        </Card>
      )}

      {data && data.scan_count < 2 && !isFetching && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4 text-muted-foreground">
              <Clock className="h-12 w-12" />
              <p>At least 2 completed scans are required for update frequency analysis</p>
              <p className="text-sm">Currently {data.scan_count} scan(s) available</p>
            </div>
          </CardContent>
        </Card>
      )}

      {data && data.scan_count >= 2 && !isFetching && (
        <>
          {data.branch && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <GitBranch className="h-4 w-4" />
              <span>
                Branch <span className="font-medium text-foreground">{data.branch}</span>
                {data.dominant_ecosystem && ` · ${data.dominant_ecosystem}`}
              </span>
            </div>
          )}

          <SummaryCards data={data} />

          <TimelineChart data={data} />

          <div className="grid gap-6 md:grid-cols-2">
            <GranularityChart data={data} />
            <SlowPackagesTable data={data} />
          </div>

          <UpstreamCadenceCard data={data} />

          <RecentUpdatesTable data={data} />
        </>
      )}
    </div>
  )
}
