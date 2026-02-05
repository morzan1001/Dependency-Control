import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Activity, ShieldAlert, ShieldCheck, FolderGit2, ArrowUp, ArrowDown } from 'lucide-react'
import { useDashboardStats } from '@/hooks/queries/use-analytics'
import { useRecentScans } from '@/hooks/queries/use-scans'
import { useProjects} from '@/hooks/queries/use-projects'
import { useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useScrollContainer, createScrollObserver } from '@/hooks/use-scroll-container'
import { formatDate } from '@/lib/utils'

export default function Dashboard() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState('created_at')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const limit = 50 // Optimized for virtual scrolling
  const { data: recentScans, isLoading: isLoadingScans } = useRecentScans()
  const { data: dashboardStats, isLoading: isLoadingStats } = useDashboardStats()

  const { data: projectsData, isLoading: isLoadingProjects } = useProjects(
    '', // search
    page,
    limit,
    sortBy,
    sortOrder
  )

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortOrder('desc')
    }
  }

  const renderSortIcon = (column: string) => {
    if (sortBy !== column) return null;
    return sortOrder === 'asc' ? <ArrowUp className="ml-2 h-4 w-4 inline" /> : <ArrowDown className="ml-2 h-4 w-4 inline" />;
  };

  const scanList = recentScans || []
  const projectList = projectsData?.items || []
  const totalPages = projectsData?.pages || 0

  // Virtual Scroll Setup
  const { parentRef, scrollContainer, tableOffset } = useScrollContainer()
  
  // eslint-disable-next-line
  const rowVirtualizer = useVirtualizer({
    count: projectList.length,
    getScrollElement: () => scrollContainer,
    estimateSize: () => 73, // Approximate row height
    overscan: 5,
    observeElementOffset: createScrollObserver(scrollContainer, tableOffset),
  })

  const stats = [
    {
      title: "Total Projects",
      value: dashboardStats?.total_projects.toString() || "0",
      icon: FolderGit2,
      description: "Active projects"
    },
    {
      title: "Critical Vulnerabilities",
      value: dashboardStats?.total_critical.toString() || "0",
      icon: ShieldAlert,
      description: "Across all projects",
      className: "text-destructive"
    },
    {
      title: "High Vulnerabilities",
      value: dashboardStats?.total_high.toString() || "0",
      icon: Activity,
      description: "Across all projects",
      className: "text-severity-high"
    },
    {
      title: "Avg Risk Score",
      value: dashboardStats?.avg_risk_score.toString() || "0.0",
      icon: ShieldCheck,
      description: "Average risk per project",
      tooltip: "Calculated as the average sum of CVSS scores per project. If CVSS is missing, weighted severity is used: Critical=10, High=7.5, Medium=4, Low=1."
    }
  ]

  // Chart Data
  const chartData = dashboardStats?.top_risky_projects || []

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">Overview of your security posture.</p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {isLoadingStats ? (
          Array(4).fill(0).map((_, i) => (
            <Skeleton key={i} className="h-32 rounded-xl" />
          ))
        ) : (
          stats.map((stat) => {
            const Icon = stat.icon
            return (
              <Card key={stat.title} title={stat.tooltip}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    {stat.title}
                    {stat.tooltip && (
                      <span className="sr-only">{stat.tooltip}</span>
                    )}
                  </CardTitle>
                  <Icon className={`h-4 w-4 text-muted-foreground ${stat.className || ''}`} />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stat.value}</div>
                  <p className="text-xs text-muted-foreground">
                    {stat.description}
                  </p>
                </CardContent>
              </Card>
            )
          })
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Chart Section */}
        <Card className="col-span-4">
            <CardHeader>
            <CardTitle>Top 5 Riskiest Projects</CardTitle>
            </CardHeader>
            <CardContent className="pl-2">
            {isLoadingStats ? (
                <Skeleton className="h-[300px] w-full rounded-xl" />
            ) : (
                <div className="h-[300px] w-full min-w-0">
                    <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} />
                        <XAxis 
                        dataKey="name" 
                        stroke="#888888" 
                        fontSize={12} 
                        tickLine={false} 
                        axisLine={false} 
                        />
                        <YAxis
                        stroke="#888888"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(value) => `${value}`}
                        />
                        <Tooltip 
                            cursor={{ fill: 'transparent' }}
                            contentStyle={{
                              borderRadius: '8px',
                              border: '1px solid hsl(var(--border))',
                              backgroundColor: 'hsl(var(--popover))',
                              color: 'hsl(var(--popover-foreground))',
                              boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
                            }}
                            labelStyle={{ color: 'hsl(var(--popover-foreground))' }}
                            itemStyle={{ color: 'hsl(var(--popover-foreground))' }}
                        />
                        <Bar dataKey="risk" fill="currentColor" radius={[4, 4, 0, 0]} className="fill-primary" barSize={40} />
                    </BarChart>
                    </ResponsiveContainer>
                </div>
            )}
            </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="col-span-3">
            <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="space-y-6 max-h-[300px] overflow-y-auto pr-2">
                    {isLoadingScans ? (
                        Array.from({ length: 5 }).map((_, i) => (
                            <div key={i} className="flex items-center">
                                <div className="space-y-1 w-full">
                                    <Skeleton className="h-4 w-[200px]" />
                                    <Skeleton className="h-3 w-[150px]" />
                                </div>
                                <Skeleton className="ml-auto h-4 w-[80px]" />
                            </div>
                        ))
                    ) : (
                        <>
                            {scanList.map((scan) => (
                                <div key={scan.id} className="flex items-center">
                                    <div className="space-y-1">
                                        <p className="text-sm font-medium leading-none">{scan.project_name}</p>
                                        <p className="text-sm text-muted-foreground">
                                            {scan.pipeline_iid ? `Pipeline #${scan.pipeline_iid}` : 'Scan'} on {scan.branch} - {scan.status}
                                        </p>
                                    </div>
                                    <div className="ml-auto font-medium text-sm text-muted-foreground">
                                        {formatDate(scan.created_at)}
                                    </div>
                                </div>
                            ))}
                            {scanList.length === 0 && (
                                <div className="text-sm text-muted-foreground">No recent activity.</div>
                            )}
                        </>
                    )}
                </div>
            </CardContent>
        </Card>
      </div>

      {/* Projects Table */}
      <Card>
        <CardHeader>
          <CardTitle>Projects</CardTitle>
        </CardHeader>
        <CardContent>
            <div 
                ref={parentRef}
                className="relative w-full"
            >
                <table className="w-full caption-bottom text-sm table-fixed">
                    <thead className="[&_tr]:border-b sticky top-0 bg-background z-10 shadow-sm">
                        <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                            <th className="w-auto h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0 cursor-pointer hover:text-foreground" onClick={() => handleSort('name')}>
                                Name {renderSortIcon('name')}
                            </th>
                            <th className="w-[150px] h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Team</th>
                            <th className="w-[150px] h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0 cursor-pointer hover:text-foreground" onClick={() => handleSort('last_scan_at')}>
                                Last Scan {renderSortIcon('last_scan_at')}
                            </th>
                            <th className="w-[100px] h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0 cursor-pointer hover:text-foreground" onClick={() => handleSort('critical')}>
                                Critical {renderSortIcon('critical')}
                            </th>
                            <th className="w-[100px] h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0 cursor-pointer hover:text-foreground" onClick={() => handleSort('high')}>
                                High {renderSortIcon('high')}
                            </th>
                            <th className="w-[120px] h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Status</th>
                        </tr>
                    </thead>
                    <tbody className="[&_tr:last-child]:border-0">
                        {isLoadingProjects ? (
                            Array.from({ length: 5 }).map((_, i) => (
                                <tr key={i} className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                                    <td className="p-4 align-middle"><Skeleton className="h-4 w-[150px]" /></td>
                                    <td className="p-4 align-middle"><Skeleton className="h-4 w-[100px]" /></td>
                                    <td className="p-4 align-middle"><Skeleton className="h-4 w-[100px]" /></td>
                                    <td className="p-4 align-middle"><Skeleton className="h-4 w-[40px]" /></td>
                                    <td className="p-4 align-middle"><Skeleton className="h-4 w-[40px]" /></td>
                                    <td className="p-4 align-middle"><Skeleton className="h-6 w-[80px] rounded-full" /></td>
                                </tr>
                            ))
                        ) : (
                            <>
                                {rowVirtualizer.getVirtualItems().length > 0 && (
                                    <tr style={{ height: `${rowVirtualizer.getVirtualItems()[0].start}px` }}>
                                        <td colSpan={6} />
                                    </tr>
                                )}
                                {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                                    const project = projectList[virtualRow.index]
                                    return (
                                        <tr 
                                            key={project.id} 
                                            data-index={virtualRow.index}
                                            ref={rowVirtualizer.measureElement}
                                            className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer"
                                            onClick={() => navigate(`/projects/${project.id}`)}
                                        >
                                            <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0 font-medium">{project.name}</td>
                                            <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0">{project.team_id || '-'}</td>
                                            <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0">{project.last_scan_at ? formatDate(project.last_scan_at) : 'Never'}</td>
                                            <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0 text-destructive font-bold">{project.stats?.critical || 0}</td>
                                            <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0 text-severity-high font-bold">{project.stats?.high || 0}</td>
                                            <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0">
                                                <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 ${
                                                    (project.stats?.critical || 0) > 0 ? 'bg-destructive text-destructive-foreground hover:bg-destructive/80' :
                                                    (project.stats?.high || 0) > 0 ? 'bg-severity-high text-severity-high-foreground hover:bg-severity-high/80' :
                                                    'bg-success text-success-foreground hover:bg-success/80'
                                                }`}>
                                                    {(project.stats?.critical || 0) > 0 ? 'Critical' : (project.stats?.high || 0) > 0 ? 'High Risk' : 'Secure'}
                                                </span>
                                            </td>
                                        </tr>
                                    )
                                })}
                                {rowVirtualizer.getVirtualItems().length > 0 && (
                                    <tr style={{ height: `${rowVirtualizer.getTotalSize() - rowVirtualizer.getVirtualItems()[rowVirtualizer.getVirtualItems().length - 1].end}px` }}>
                                        <td colSpan={6} />
                                    </tr>
                                )}
                            </>
                        )}
                    </tbody>
                </table>
            </div>
            <div className="flex items-center justify-end space-x-2 py-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
              >
                Previous
              </Button>
              <div className="text-sm text-muted-foreground">
                Page {page} of {totalPages || 1}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || totalPages === 0}
              >
                Next
              </Button>
            </div>
        </CardContent>
      </Card>
    </div>
  )
}
