import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ProjectCombobox } from '@/components/ui/project-combobox'
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
  TrendingUp,
  TrendingDown,
  Minus,
  Clock,
  Package,
  ArrowRight,
  AlertTriangle,
} from 'lucide-react'
import { useUpdateFrequency } from '@/hooks/queries/use-analytics'
import { formatDate } from '@/lib/utils'
import type { UpdateFrequencyMetrics, DependencyUpdateEvent } from '@/types/analytics'

interface UpdateFrequencyProps {
  projectId?: string
}

const updateTypeColors: Record<string, string> = {
  patch: '#22c55e',
  minor: '#eab308',
  major: '#ef4444',
  unknown: '#94a3b8',
}

const updateTypeBadgeVariants: Record<string, string> = {
  patch: 'bg-green-500/10 text-green-600 border-green-500/20',
  minor: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  major: 'bg-red-500/10 text-red-600 border-red-500/20',
  unknown: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
}

const trendConfig = {
  improving: { icon: TrendingUp, color: 'text-green-500', label: 'Improving' },
  stable: { icon: Minus, color: 'text-gray-500', label: 'Stable' },
  deteriorating: { icon: TrendingDown, color: 'text-red-500', label: 'Deteriorating' },
}

function SummaryCards({ data }: Readonly<{ data: UpdateFrequencyMetrics }>) {
  const trend = trendConfig[data.trend_direction] || trendConfig.stable
  const TrendIcon = trend.icon

  return (
    <div className="grid gap-4 md:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Updates / Month</CardTitle>
          <RefreshCw className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.updates_per_month}</div>
          <p className="text-xs text-muted-foreground">
            {data.total_updates} total across {data.scan_count} scans
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Scan Cadence</CardTitle>
          <Clock className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.avg_days_between_scans}d</div>
          <p className="text-xs text-muted-foreground">
            avg. days between scans
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Update Coverage</CardTitle>
          <Package className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.update_coverage_pct}%</div>
          <p className="text-xs text-muted-foreground">
            {data.outdated_resolved} of {data.total_outdated_detected} outdated resolved
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
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="outdated_count"
                stroke="#94a3b8"
                strokeWidth={2}
                strokeDasharray="5 5"
                dot={false}
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
        <CardDescription>Distribution of update types (patch, minor, major)</CardDescription>
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

export function UpdateFrequency({ projectId: initialProjectId }: Readonly<UpdateFrequencyProps>) {
  const [selectedProjectId, setSelectedProjectId] = useState<string>(initialProjectId || '')

  const { data, isLoading, error } = useUpdateFrequency(selectedProjectId)

  return (
    <div className="space-y-6">
      {/* Project Selector */}
      {!initialProjectId && (
        <Card>
          <CardHeader>
            <CardTitle>Update Frequency</CardTitle>
            <CardDescription>
              Analyze how regularly and incrementally your project updates its dependencies
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <ProjectCombobox
                value={selectedProjectId}
                onValueChange={setSelectedProjectId}
                className="w-[350px]"
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {isLoading && selectedProjectId && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-4">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={`skeleton-${i}`} className="h-28 w-full" />
            ))}
          </div>
          <Skeleton className="h-80 w-full" />
        </div>
      )}

      {/* Error State */}
      {error && (
        <Card>
          <CardContent className="py-8">
            <div className="flex flex-col items-center gap-2 text-muted-foreground">
              <AlertTriangle className="h-12 w-12" />
              <p>Failed to load update frequency data</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty State - no project selected */}
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

      {/* Not enough scans */}
      {data && data.scan_count < 2 && (
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

      {/* Results */}
      {data && data.scan_count >= 2 && (
        <>
          <SummaryCards data={data} />

          <TimelineChart data={data} />

          <div className="grid gap-6 md:grid-cols-2">
            <GranularityChart data={data} />
            <SlowPackagesTable data={data} />
          </div>

          <RecentUpdatesTable data={data} />
        </>
      )}
    </div>
  )
}
