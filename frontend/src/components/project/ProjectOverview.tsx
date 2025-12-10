import { useQuery } from '@tanstack/react-query'
import { getProjectScans } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Activity, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'

interface ProjectOverviewProps {
  projectId: string
}

export function ProjectOverview({ projectId }: ProjectOverviewProps) {
  const { data: scans, isLoading } = useQuery({
    queryKey: ['project-scans-overview', projectId],
    queryFn: () => getProjectScans(projectId, 0, 50), // Fetch last 50 for charts
  })

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
    )
  }

  const scanList = scans || []
  
  // Filter scans for the default branch (usually main or master) or just take all for now
  // Ideally we should filter by the project's default branch if available
  const chartData = [...scanList]
      .sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
      .map((scan: any) => ({
          date: new Date(scan.created_at).toLocaleDateString(),
          critical: scan.stats?.critical || 0,
          high: scan.stats?.high || 0,
          medium: scan.stats?.medium || 0,
          low: scan.stats?.low || 0
      }))

  const latestScan = scanList.length > 0 ? scanList[0] : null
  const stats = {
      critical: latestScan?.stats?.critical || 0,
      high: latestScan?.stats?.high || 0,
      medium: latestScan?.stats?.medium || 0,
      low: latestScan?.stats?.low || 0
  }

  const severityData = [
      { name: 'Critical', value: stats.critical, color: '#ef4444' },
      { name: 'High', value: stats.high, color: '#f97316' },
      { name: 'Medium', value: stats.medium, color: '#eab308' },
      { name: 'Low', value: stats.low, color: '#3b82f6' },
  ].filter(d => d.value > 0)

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scanList.length}</div>
            <p className="text-xs text-muted-foreground">
              {latestScan ? `Last scan ${new Date(latestScan.created_at).toLocaleDateString()}` : "No scans yet"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{stats.critical}</div>
            <p className="text-xs text-muted-foreground">
              In latest scan
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{stats.high}</div>
            <p className="text-xs text-muted-foreground">
              In latest scan
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Score</CardTitle>
            <ShieldCheck className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">
              {Math.max(0, 100 - (stats.critical * 10 + stats.high * 5 + stats.medium * 2)).toFixed(0)}
            </div>
            <p className="text-xs text-muted-foreground">
              Estimated health
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Vulnerability Trends</CardTitle>
          </CardHeader>
          <CardContent className="pl-2">
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" className="text-xs" />
                  <YAxis className="text-xs" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                    itemStyle={{ color: 'hsl(var(--foreground))' }}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} />
                  <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} />
                  <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                    itemStyle={{ color: 'hsl(var(--foreground))' }}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
