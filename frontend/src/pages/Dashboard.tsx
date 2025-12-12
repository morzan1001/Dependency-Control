import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Activity, ShieldAlert, ShieldCheck, FolderGit2 } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { getProjects, getRecentScans } from '@/lib/api'
import { useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'

export default function Dashboard() {
  const navigate = useNavigate()
  const { data: projects, isLoading: isLoadingProjects, error: errorProjects } = useQuery({
    queryKey: ['projects'],
    queryFn: getProjects,
  })

  const { data: recentScans, isLoading: isLoadingScans } = useQuery({
    queryKey: ['recent-scans'],
    queryFn: getRecentScans,
  })

  if (isLoadingProjects || isLoadingScans) {
    return (
      <div className="space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-10 w-48" />
          <Skeleton className="h-4 w-64" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Skeleton className="h-32 rounded-xl" />
          <Skeleton className="h-32 rounded-xl" />
          <Skeleton className="h-32 rounded-xl" />
          <Skeleton className="h-32 rounded-xl" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
          <Skeleton className="col-span-4 h-[400px] rounded-xl" />
          <Skeleton className="col-span-3 h-[400px] rounded-xl" />
        </div>
      </div>
    )
  }

  if (errorProjects) {
    return <div className="text-destructive">Error loading dashboard: {errorProjects.message}</div>
  }

  const projectList = projects || []
  const scanList = recentScans || []

  // Stats Calculation
  let totalCritical = 0
  let totalHigh = 0
  let totalRiskScore = 0

  projectList.forEach(p => {
    if (p.stats) {
      totalCritical += p.stats.critical || 0
      totalHigh += p.stats.high || 0
      
      if (p.stats.risk_score !== undefined) {
        totalRiskScore += p.stats.risk_score
      } else {
        // Fallback calculation matching backend logic for consistency
        // Critical=10, High=7.5, Medium=4, Low=1
        totalRiskScore += (p.stats.critical || 0) * 10 + (p.stats.high || 0) * 7.5 + (p.stats.medium || 0) * 4 + (p.stats.low || 0) * 1
      }
    }
  })

  const avgRiskScore = projectList.length > 0 ? (totalRiskScore / projectList.length).toFixed(1) : "0.0"

  const stats = [
    {
      title: "Total Projects",
      value: projectList.length.toString(),
      icon: FolderGit2,
      description: "Active projects"
    },
    {
      title: "Critical Vulnerabilities",
      value: totalCritical.toString(),
      icon: ShieldAlert,
      description: "Across all projects",
      className: "text-destructive"
    },
    {
      title: "High Vulnerabilities",
      value: totalHigh.toString(),
      icon: Activity,
      description: "Across all projects",
      className: "text-orange-500"
    },
    {
      title: "Avg Risk Score",
      value: avgRiskScore,
      icon: ShieldCheck,
      description: "Average risk per project",
      tooltip: "Calculated as the average sum of CVSS scores per project. If CVSS is missing, weighted severity is used: Critical=10, High=7.5, Medium=4, Low=1."
    }
  ]

  // Chart Data
  const chartData = [...projectList]
    .sort((a, b) => {
      const getScore = (p: typeof projectList[0]) => {
        if (p.stats?.risk_score !== undefined) return p.stats.risk_score
        return (p.stats?.critical || 0) * 10 + (p.stats?.high || 0) * 7.5 + (p.stats?.medium || 0) * 4
      }
      return getScore(b) - getScore(a)
    })
    .slice(0, 5)
    .map(p => ({
      name: p.name,
      risk: p.stats?.risk_score !== undefined 
        ? p.stats.risk_score 
        : (p.stats?.critical || 0) * 10 + (p.stats?.high || 0) * 7.5 + (p.stats?.medium || 0) * 4
    }))

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">Overview of your security posture.</p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => {
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
        })}
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Chart Section */}
        <Card className="col-span-4">
            <CardHeader>
            <CardTitle>Top 5 Riskiest Projects</CardTitle>
            </CardHeader>
            <CardContent className="pl-2">
            <div className="h-[300px] w-full">
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
                        cursor={{fill: 'transparent'}}
                        contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                    />
                    <Bar dataKey="risk" fill="currentColor" radius={[4, 4, 0, 0]} className="fill-primary" barSize={40} />
                </BarChart>
                </ResponsiveContainer>
            </div>
            </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="col-span-3">
            <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="space-y-6 max-h-[300px] overflow-y-auto pr-2">
                    {scanList.map((scan) => (
                        <div key={scan._id} className="flex items-center">
                            <div className="space-y-1">
                                <p className="text-sm font-medium leading-none">{scan.project_name}</p>
                                <p className="text-sm text-muted-foreground">
                                    Scan on {scan.branch} - {scan.status}
                                </p>
                            </div>
                            <div className="ml-auto font-medium text-sm text-muted-foreground">
                                {new Date(scan.created_at).toLocaleDateString()}
                            </div>
                        </div>
                    ))}
                    {scanList.length === 0 && (
                        <div className="text-sm text-muted-foreground">No recent activity.</div>
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
            <div className="relative w-full overflow-auto">
                <table className="w-full caption-bottom text-sm">
                    <thead className="[&_tr]:border-b">
                        <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                            <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Name</th>
                            <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Team</th>
                            <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Last Scan</th>
                            <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Critical</th>
                            <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">High</th>
                            <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0">Status</th>
                        </tr>
                    </thead>
                    <tbody className="[&_tr:last-child]:border-0">
                        {projectList.map((project) => (
                            <tr 
                                key={project._id} 
                                className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer"
                                onClick={() => navigate(`/projects/${project._id}`)}
                            >
                                <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0 font-medium">{project.name}</td>
                                <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0">{project.team_id || '-'}</td>
                                <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0">{project.last_scan_at ? new Date(project.last_scan_at).toLocaleDateString() : 'Never'}</td>
                                <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0 text-destructive font-bold">{project.stats?.critical || 0}</td>
                                <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0 text-orange-500 font-bold">{project.stats?.high || 0}</td>
                                <td className="p-4 align-middle [&:has([role=checkbox])]:pr-0">
                                    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 ${
                                        (project.stats?.critical || 0) > 0 ? 'bg-destructive text-destructive-foreground hover:bg-destructive/80' :
                                        (project.stats?.high || 0) > 0 ? 'bg-orange-500 text-white hover:bg-orange-500/80' :
                                        'bg-green-500 text-white hover:bg-green-500/80'
                                    }`}>
                                        {(project.stats?.critical || 0) > 0 ? 'Critical' : (project.stats?.high || 0) > 0 ? 'High Risk' : 'Secure'}
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </CardContent>
      </Card>
    </div>
  )
}
