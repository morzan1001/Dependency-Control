import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useProjectScans, useScanResults } from '@/hooks/queries/use-scans'
import { useProjectWaivers } from '@/hooks/queries/use-waivers'
import { Scan } from '@/types/scan'
import { isScanUsable } from '@/lib/scan-status'
import { highestRiskBranch } from '@/lib/branches'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Activity, ShieldAlert, ShieldCheck, AlertTriangle, GitBranch } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { ThreatIntelligenceDashboard } from '@/components/ThreatIntelligenceDashboard'
import { SecretPriorityCard } from '@/components/findings/SecretPriorityCard'
import { PostProcessorResultCard } from '@/components/PostProcessorResults'
import { isPostProcessorResult } from '@/lib/post-processors'
import { MAX_SCANS_FOR_CHARTS } from '@/lib/constants'
import { formatDate } from '@/lib/utils'
import { SEVERITY_CHART_COLORS } from '@/lib/finding-utils'

interface ProjectOverviewProps {
  projectId: string
  selectedBranches: string[]
}

export function ProjectOverview({ projectId, selectedBranches }: ProjectOverviewProps) {
  const navigate = useNavigate()
  const { data: scans, isLoading } = useProjectScans(projectId, { page: 1, limit: MAX_SCANS_FOR_CHARTS, excludeDeletedBranches: true })

  const { data: waivers } = useProjectWaivers(projectId)

  const scanList = scans || []

  const filteredScans = scanList.filter((s: Scan) => selectedBranches.includes(s.branch))

  const uniqueScansCount = filteredScans.filter((s: Scan) => !s.is_rescan).length

  const projectStats = useMemo(() => {
      if (!filteredScans.length) return null;

      const latestScansByBranch: Record<string, Scan> = {};

      filteredScans.forEach((scan: Scan) => {
          if (!isScanUsable(scan.status)) return;

          const currentLatest = latestScansByBranch[scan.branch];
          if (!currentLatest || new Date(scan.created_at) > new Date(currentLatest.created_at)) {
              latestScansByBranch[scan.branch] = scan;
          }
      });

      const branchStatsData = Object.values(latestScansByBranch).map(scan => ({
          name: scan.branch,
          critical: scan.stats?.critical || 0,
          high: scan.stats?.high || 0,
          medium: scan.stats?.medium || 0,
          low: scan.stats?.low || 0,
          info: scan.stats?.info || 0,
          unknown: scan.stats?.unknown || 0
      }));

      return { branchStats: branchStatsData, latestScansByBranch };
  }, [filteredScans]);

  const latestScansByBranch = useMemo(() => projectStats?.latestScansByBranch || {}, [projectStats]);
  const branchNames = Object.keys(latestScansByBranch);
  const [pickedBranch, setPickedBranch] = useState<string | null>(null);
  // Every headline number below comes from this one scan. Summing across branches would
  // count the same CVE once per branch; the per-branch breakdown covers the rest.
  const activeBranch = pickedBranch && branchNames.includes(pickedBranch)
    ? pickedBranch
    : highestRiskBranch(latestScansByBranch);
  const activeScan = activeBranch ? latestScansByBranch[activeBranch] : undefined;
  const { data: scanResults } = useScanResults(activeScan?.id || '');

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

  const stats = activeScan?.stats || {}
  const branchStats = projectStats?.branchStats || []

  const threatIntel = stats.threat_intel
  const hasThreatIntelData = threatIntel && (
    (threatIntel.kev_count ?? 0) > 0 ||
    (threatIntel.high_epss_count ?? 0) > 0 ||
    (threatIntel.medium_epss_count ?? 0) > 0 ||
    (threatIntel.weaponized_count ?? 0) > 0 ||
    (threatIntel.active_exploitation_count ?? 0) > 0
  )
  const reachability = stats.reachability
  const hasReachabilityData = reachability && (
    (reachability.analyzed_count ?? 0) > 0 ||
    (reachability.reachable_count ?? 0) > 0 ||
    (reachability.likely_reachable_count ?? 0) > 0 ||
    (reachability.unreachable_count ?? 0) > 0 ||
    (reachability.unknown_count ?? 0) > 0
  )
  const hasEnhancedStats = hasThreatIntelData || hasReachabilityData

  const sortedScans = [...filteredScans].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())

  interface TrendEntry {
    date: string;
    [branch: string]: string | number;
  }
  const trendMap = new Map<string, TrendEntry>()
  
  sortedScans.forEach(scan => {
      const date = formatDate(scan.created_at)
      const risk = (scan.stats?.critical || 0) + (scan.stats?.high || 0)
      
      if (!trendMap.has(date)) {
          trendMap.set(date, { date })
      }
      
      const entry = trendMap.get(date)!
      // Multiple scans for a branch on the same day: last one wins (sort order).
      entry[scan.branch] = risk
  })
  
  const trendData = Array.from(trendMap.values())
  const COLORS = ['#2563eb', '#16a34a', '#d97706', '#dc2626', '#9333ea', '#0891b2', '#ea580c', '#4f46e5'];

  const pieData = [
      { name: 'Critical', value: stats.critical || 0, color: SEVERITY_CHART_COLORS.CRITICAL },
      { name: 'High', value: stats.high || 0, color: SEVERITY_CHART_COLORS.HIGH },
      { name: 'Medium', value: stats.medium || 0, color: SEVERITY_CHART_COLORS.MEDIUM },
      { name: 'Low', value: stats.low || 0, color: SEVERITY_CHART_COLORS.LOW },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      {branchNames.length > 1 && activeBranch && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-muted-foreground">
            Findings exist on every branch, so the blocks below show one branch at a time.
          </p>
          <Tabs value={activeBranch} onValueChange={setPickedBranch}>
            <TabsList>
              {branchNames.map(branch => (
                <TabsTrigger key={branch} value={branch} className="gap-1.5">
                  <GitBranch className="h-3 w-3" />
                  {branch}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{uniqueScansCount}</div>
            <p className="text-xs text-muted-foreground">
              Across selected branches
            </p>
          </CardContent>
        </Card>
        <Card
          className="cursor-pointer transition-colors hover:bg-muted/50"
          onClick={() => {
            if (activeScan) navigate(`/projects/${projectId}/scans/${activeScan.id}?severity=CRITICAL`)
          }}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{stats.critical ?? 0}</div>
            <p className="text-xs text-muted-foreground">
              {activeBranch ? `Branch ${activeBranch} — click to view findings` : 'Click to view findings'}
            </p>
          </CardContent>
        </Card>
        <Card
          className="cursor-pointer transition-colors hover:bg-muted/50"
          onClick={() => {
            if (activeScan) navigate(`/projects/${projectId}/scans/${activeScan.id}?severity=HIGH`)
          }}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{stats.high ?? 0}</div>
            <p className="text-xs text-muted-foreground">
              {activeBranch ? `Branch ${activeBranch} — click to view findings` : 'Click to view findings'}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Waivers</CardTitle>
            <ShieldCheck className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{waivers?.pages?.[0]?.total || 0}</div>
          </CardContent>
        </Card>
      </div>

      {hasEnhancedStats && <ThreatIntelligenceDashboard stats={stats} />}

      {stats.secret_priority && <SecretPriorityCard counts={stats.secret_priority} />}

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
            <div className="h-[300px] w-full min-w-0">
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
            <div className="h-[300px] w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart className="cursor-pointer">
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    onClick={(data) => {
                      if (data?.name) {
                        const scan = activeBranch ? latestScansByBranch[activeBranch] : Object.values(latestScansByBranch)[0]
                        if (scan) navigate(`/projects/${projectId}/scans/${scan.id}?severity=${data.name.toUpperCase()}`)
                      }
                    }}
                  >
                    {pieData.map((entry) => (
                      <Cell key={`cell-${entry.name}`} fill={entry.color} />
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
                <CardContent>
                    <div className="h-[400px] w-full min-w-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                              data={branchStats}
                              margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                              className="cursor-pointer"
                              onClick={(state) => {
                                if (state?.activeLabel) {
                                  const branchName = state.activeLabel
                                  const scan = latestScansByBranch[branchName]
                                  if (scan) navigate(`/projects/${projectId}/scans/${scan.id}`)
                                }
                              }}
                            >
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip
                                    contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                                    itemStyle={{ color: 'hsl(var(--foreground))' }}
                                />
                                <Legend />
                                <Bar dataKey="critical" stackId="a" fill={SEVERITY_CHART_COLORS.CRITICAL} />
                                <Bar dataKey="high" stackId="a" fill={SEVERITY_CHART_COLORS.HIGH} />
                                <Bar dataKey="medium" stackId="a" fill={SEVERITY_CHART_COLORS.MEDIUM} />
                                <Bar dataKey="low" stackId="a" fill={SEVERITY_CHART_COLORS.LOW} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </CardContent>
            </Card>
        </div>
      )}

      {activeBranch && scanResults?.some(r => isPostProcessorResult(r.analyzer_name)) && (
        <div className="space-y-4">
          <h3 className="text-xl font-semibold">Enrichment & Intelligence</h3>
          <div className="space-y-6">
            {scanResults
              .filter(r => isPostProcessorResult(r.analyzer_name))
              .map((result) => (
                <PostProcessorResultCard
                  key={result.id}
                  analyzerName={result.analyzer_name}
                  result={result.result}
                />
              ))}
          </div>
        </div>
      )}
    </div>
  )
}
