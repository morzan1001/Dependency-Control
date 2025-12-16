import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getProjectScans, getProject, getWaivers, Finding, Waiver, Scan } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Activity, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'

interface ProjectOverviewProps {
  projectId: string
  selectedBranches: string[]
}

export function ProjectOverview({ projectId, selectedBranches }: ProjectOverviewProps) {
  const { data: project } = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => getProject(projectId),
  })

  const { data: scans, isLoading } = useQuery({
    queryKey: ['project-scans-overview', projectId],
    queryFn: () => getProjectScans(projectId, 0, 100), // Fetch last 100 for charts
  })

  const { data: waivers } = useQuery({
    queryKey: ['waivers', projectId],
    queryFn: () => getWaivers(projectId),
  })

  const scanList = scans || []
  
  // Filter scans based on selection
  const filteredScans = scanList.filter(s => selectedBranches.includes(s.branch))

  // Calculate Project Stats (Deduplicated across latest scan of each branch)
  const projectStats = useMemo(() => {
      if (!filteredScans.length) return null;

      // Helper to check if finding is active (not waived, analyzer enabled)
      const isFindingActive = (finding: Finding) => {
          // Check waivers
          let isWaived = finding.waived;
          if (!isWaived && waivers) {
              isWaived = waivers.some((waiver: Waiver) => {
                  if (waiver.expiration_date && new Date(waiver.expiration_date) < new Date()) return false;
                  let match = true;
                  if (waiver.finding_id && waiver.finding_id !== finding.id) match = false;
                  if (match && waiver.package_name && waiver.package_name !== finding.component) match = false;
                  if (match && waiver.package_version && waiver.package_version !== finding.version) match = false;
                  if (match && waiver.finding_type && waiver.finding_type !== finding.type) match = false;
                  return match;
              });
          }
          if (isWaived) return false;

          // Check active analyzers
          const activeAnalyzers = project?.active_analyzers || [];
          const findingScanners = finding.scanners || [];
          if (findingScanners.length > 0) {
              const isActive = findingScanners.some((scanner: string) => activeAnalyzers.includes(scanner));
              if (!isActive) return false;
          }
          return true;
      };

      // 1. Group by branch
      const scansByBranch: Record<string, Scan[]> = {};
      filteredScans.forEach(scan => {
          if (scan.status !== 'completed') return;
          if (!scansByBranch[scan.branch]) scansByBranch[scan.branch] = [];
          scansByBranch[scan.branch].push(scan);
      });

      const uniqueFindings = new Map(); // Global unique findings
      const branchStatsData: { name: string; critical: number; high: number; medium: number; low: number }[] = [];

      Object.entries(scansByBranch).forEach(([branch, branchScans]) => {
          // Sort by date desc
          branchScans.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
          if (branchScans.length === 0) return;

          const latestScan = branchScans[0];
          const latestCommit = latestScan.commit_hash;
          const commitScans = branchScans.filter(s => s.commit_hash === latestCommit);

          const currentBranchStats = { name: branch, critical: 0, high: 0, medium: 0, low: 0 };
          const branchUniqueFindings = new Set<string>();

          commitScans.forEach(scan => {
              if (!scan.findings_summary) return;
              scan.findings_summary.forEach((finding: Finding) => {
                  if (!isFindingActive(finding)) return;

                  const key = `${finding.type}:${finding.id}:${finding.component}:${finding.version}`;
                  
                  // Add to global stats
                  if (!uniqueFindings.has(key)) {
                      uniqueFindings.set(key, finding);
                  }

                  // Add to branch stats (deduplicated locally)
                  if (!branchUniqueFindings.has(key)) {
                      branchUniqueFindings.add(key);
                      const severity = (finding.severity || 'UNKNOWN').toLowerCase();
                      if (currentBranchStats[severity as keyof typeof currentBranchStats] !== undefined) {
                          (currentBranchStats as any)[severity]++;
                      }
                  }
              });
          });
          branchStatsData.push(currentBranchStats);
      });

      // 3. Calculate Global Stats
      const stats: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
      uniqueFindings.forEach(finding => {
          const severity = (finding.severity || 'UNKNOWN').toLowerCase();
          if (stats[severity] !== undefined) stats[severity]++;
          else stats.unknown++;
      });

      return { stats, branchStats: branchStatsData };
  }, [filteredScans, project, waivers]);

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

  const stats = projectStats?.stats || { critical: 0, high: 0, medium: 0, low: 0 }
  const branchStats = projectStats?.branchStats || []
  
  // Trend Data Processing
  const sortedScans = [...filteredScans].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
  
  // Group by date
  const trendMap = new Map<string, any>()
  
  sortedScans.forEach(scan => {
      const date = new Date(scan.created_at).toLocaleDateString()
      const risk = (scan.stats?.critical || 0) + (scan.stats?.high || 0)
      
      if (!trendMap.has(date)) {
          trendMap.set(date, { date })
      }
      
      const entry = trendMap.get(date)
      // If multiple scans for same branch on same day, this will take the last one (due to sort order)
      entry[scan.branch] = risk
  })
  
  const trendData = Array.from(trendMap.values())
  const COLORS = ['#2563eb', '#16a34a', '#d97706', '#dc2626', '#9333ea', '#0891b2', '#ea580c', '#4f46e5'];

  const pieData = [
      { name: 'Critical', value: stats.critical || 0, color: '#ef4444' },
      { name: 'High', value: stats.high || 0, color: '#f97316' },
      { name: 'Medium', value: stats.medium || 0, color: '#eab308' },
      { name: 'Low', value: stats.low || 0, color: '#3b82f6' },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{filteredScans.length}</div>
            <p className="text-xs text-muted-foreground">
              Across selected branches
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
              Unique findings
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
              Unique findings
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Waivers</CardTitle>
            <ShieldCheck className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{waivers?.length || 0}</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
                <CardTitle>Vulnerability Trends</CardTitle>
                <CardDescription>
                    {selectedBranches.length > 0 ? `Showing trends for: ${selectedBranches.join(', ')}` : 'Select branches to view trends'}
                </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="pl-2">
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" className="text-xs" />
                  <YAxis className="text-xs" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                    itemStyle={{ color: 'hsl(var(--foreground))' }}
                  />
                  <Legend />
                  {selectedBranches.map((branch, index) => (
                      <Line 
                          key={branch}
                          type="monotone" 
                          dataKey={branch} 
                          stroke={COLORS[index % COLORS.length]} 
                          strokeWidth={2} 
                          activeDot={{ r: 8 }} 
                          connectNulls
                          name={branch}
                      />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
            <CardDescription>Based on unique findings</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
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

      {branchStats.length > 0 && (
        <div className="grid gap-4 md:grid-cols-1">
            <Card>
                <CardHeader>
                    <CardTitle>Severity Distribution by Branch</CardTitle>
                    <CardDescription>Breakdown of findings per branch</CardDescription>
                </CardHeader>
                <CardContent className="h-[400px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={branchStats} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip 
                                contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                                itemStyle={{ color: 'hsl(var(--foreground))' }}
                            />
                            <Legend />
                            <Bar dataKey="critical" stackId="a" fill="#ef4444" />
                            <Bar dataKey="high" stackId="a" fill="#f97316" />
                            <Bar dataKey="medium" stackId="a" fill="#eab308" />
                            <Bar dataKey="low" stackId="a" fill="#3b82f6" />
                        </BarChart>
                    </ResponsiveContainer>
                </CardContent>
            </Card>
        </div>
      )}
    </div>
  )
}
