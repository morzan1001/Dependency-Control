import { useMemo, useState } from 'react'
import { useProjectScans, useScanResults } from '@/hooks/queries/use-scans'
import { useProjectWaivers } from '@/hooks/queries/use-waivers'
import { Scan, ThreatIntelligenceStats, ReachabilityStats, PrioritizedCounts } from '@/types/scan'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Activity, ShieldAlert, ShieldCheck, AlertTriangle, GitBranch } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { ThreatIntelligenceDashboard } from '@/components/ThreatIntelligenceDashboard'
import { PostProcessorResultCard } from '@/components/PostProcessorResults'
import { isPostProcessorResult } from '@/lib/post-processors'
import { MAX_SCANS_FOR_CHARTS } from '@/lib/constants'
import { formatDate } from '@/lib/utils'

/** Accumulate threat intelligence stats from a scan into the accumulator */
function accumulateThreatIntel(acc: ThreatIntelligenceStats, ti: ThreatIntelligenceStats) {
  acc.kev_count += ti.kev_count || 0
  acc.kev_ransomware_count += ti.kev_ransomware_count || 0
  acc.high_epss_count += ti.high_epss_count || 0
  acc.medium_epss_count += ti.medium_epss_count || 0
  acc.weaponized_count += ti.weaponized_count || 0
  acc.active_exploitation_count += ti.active_exploitation_count || 0
  if (ti.max_epss_score != null) {
    acc.max_epss_score = Math.max(acc.max_epss_score ?? 0, ti.max_epss_score)
  }
}

/** Accumulate reachability stats from a scan into the accumulator */
function accumulateReachability(acc: ReachabilityStats, r: ReachabilityStats) {
  acc.analyzed_count += r.analyzed_count || 0
  acc.reachable_count += r.reachable_count || 0
  acc.likely_reachable_count += r.likely_reachable_count || 0
  acc.unreachable_count += r.unreachable_count || 0
  acc.unknown_count += r.unknown_count || 0
  acc.reachable_critical += r.reachable_critical || 0
  acc.reachable_high += r.reachable_high || 0
}

/** Accumulate prioritized counts from a scan into the accumulator */
function accumulatePrioritized(acc: PrioritizedCounts, p: PrioritizedCounts) {
  acc.total += p.total || 0
  acc.critical += p.critical || 0
  acc.high += p.high || 0
  acc.medium += p.medium || 0
  acc.low += p.low || 0
  acc.actionable_critical += p.actionable_critical || 0
  acc.actionable_high += p.actionable_high || 0
  acc.actionable_total += p.actionable_total || 0
  acc.deprioritized_count += p.deprioritized_count || 0
}

interface ProjectOverviewProps {
  projectId: string
  selectedBranches: string[]
}

export function ProjectOverview({ projectId, selectedBranches }: ProjectOverviewProps) {
  const { data: scans, isLoading } = useProjectScans(projectId, { page: 1, limit: MAX_SCANS_FOR_CHARTS, excludeDeletedBranches: true })

  const { data: waivers } = useProjectWaivers(projectId)

  const scanList = scans || []

  // Filter scans based on selection
  const filteredScans = scanList.filter((s: Scan) => selectedBranches.includes(s.branch))

  // Count unique pipelines (excluding rescans)
  const uniqueScansCount = filteredScans.filter((s: Scan) => !s.is_rescan).length

  // Calculate Project Stats - aggregate across ALL selected branches
  const projectStats = useMemo(() => {
      if (!filteredScans.length) return null;

      // 1. Group by branch and find latest completed scan for each
      const latestScansByBranch: Record<string, Scan> = {};

      filteredScans.forEach((scan: Scan) => {
          if (scan.status !== 'completed') return;

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

      // 2. Aggregate stats across ALL branches' latest scans
      const allBranchScans = Object.values(latestScansByBranch);

      const aggregatedStats: {
          critical: number; high: number; medium: number; low: number; info: number; unknown: number;
          risk_score: number; adjusted_risk_score: number;
          threat_intel: ThreatIntelligenceStats | null; reachability: ReachabilityStats | null; prioritized: PrioritizedCounts | null;
      } = {
          critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0,
          risk_score: 0, adjusted_risk_score: 0,
          threat_intel: null, reachability: null, prioritized: null
      };

      // Sum severity counts, take max risk scores
      let maxRisk = 0;
      let maxAdjustedRisk = 0;
      const threatIntelAcc: ThreatIntelligenceStats = {
          kev_count: 0, kev_ransomware_count: 0,
          high_epss_count: 0, medium_epss_count: 0,
          avg_epss_score: null, max_epss_score: null,
          weaponized_count: 0, active_exploitation_count: 0,
      };
      const reachabilityAcc: ReachabilityStats = {
          analyzed_count: 0, reachable_count: 0, likely_reachable_count: 0,
          unreachable_count: 0, unknown_count: 0,
          reachable_critical: 0, reachable_high: 0,
      };
      const prioritizedAcc: PrioritizedCounts = {
          total: 0, critical: 0, high: 0, medium: 0, low: 0,
          actionable_critical: 0, actionable_high: 0,
          actionable_total: 0, deprioritized_count: 0,
      };
      let hasThreatIntel = false;
      let hasReachability = false;
      let hasPrioritized = false;
      let epssScoreSum = 0;
      let epssScoreCount = 0;

      for (const scan of allBranchScans) {
          const s = scan.stats;
          if (!s) continue;

          aggregatedStats.critical += s.critical || 0;
          aggregatedStats.high += s.high || 0;
          aggregatedStats.medium += s.medium || 0;
          aggregatedStats.low += s.low || 0;
          aggregatedStats.info += s.info || 0;
          aggregatedStats.unknown += s.unknown || 0;
          maxRisk = Math.max(maxRisk, s.risk_score || 0);
          maxAdjustedRisk = Math.max(maxAdjustedRisk, s.adjusted_risk_score || 0);

          if (s.threat_intel) {
              hasThreatIntel = true;
              accumulateThreatIntel(threatIntelAcc, s.threat_intel);
              if (s.threat_intel.avg_epss_score != null) {
                  epssScoreSum += s.threat_intel.avg_epss_score;
                  epssScoreCount++;
              }
          }

          if (s.reachability) {
              hasReachability = true;
              accumulateReachability(reachabilityAcc, s.reachability);
          }

          if (s.prioritized) {
              hasPrioritized = true;
              accumulatePrioritized(prioritizedAcc, s.prioritized);
          }
      }

      aggregatedStats.risk_score = maxRisk;
      aggregatedStats.adjusted_risk_score = maxAdjustedRisk;
      if (hasThreatIntel) {
          threatIntelAcc.avg_epss_score = epssScoreCount > 0 ? epssScoreSum / epssScoreCount : null;
          aggregatedStats.threat_intel = threatIntelAcc;
      }
      if (hasReachability) aggregatedStats.reachability = reachabilityAcc;
      if (hasPrioritized) aggregatedStats.prioritized = prioritizedAcc;

      return { stats: aggregatedStats, branchStats: branchStatsData, latestScansByBranch, branchCount: allBranchScans.length };
  }, [filteredScans]);

  // Branch selector state for enrichment detail cards
  const latestScansByBranch = projectStats?.latestScansByBranch || {};
  const branchNames = Object.keys(latestScansByBranch);
  const [enrichmentBranch, setEnrichmentBranch] = useState<string | null>(null);
  const activeBranch = enrichmentBranch && branchNames.includes(enrichmentBranch)
    ? enrichmentBranch
    : branchNames[0] || null;
  const enrichmentScanId = activeBranch ? latestScansByBranch[activeBranch]?.id : '';
  const { data: scanResults } = useScanResults(enrichmentScanId || '');

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

  const stats = projectStats?.stats || { critical: 0, high: 0, medium: 0, low: 0, risk_score: 0 }
  const branchStats = projectStats?.branchStats || []
  
  // Check if we have actual threat intelligence data (not just empty objects)
  const threatIntel = 'threat_intel' in stats ? stats.threat_intel : null
  const hasThreatIntelData = threatIntel && (
    (threatIntel.kev_count ?? 0) > 0 || 
    (threatIntel.high_epss_count ?? 0) > 0 || 
    (threatIntel.exploitable_count ?? 0) > 0 ||
    (threatIntel.total_enriched ?? 0) > 0
  )
  const reachability = 'reachability' in stats ? stats.reachability : null
  const hasReachabilityData = reachability && (
    (reachability.reachable ?? 0) > 0 || 
    (reachability.potentially_reachable ?? 0) > 0 ||
    (reachability.total_analyzed ?? 0) > 0
  )
  const hasEnhancedStats = hasThreatIntelData || hasReachabilityData
  
  // Trend Data Processing
  const sortedScans = [...filteredScans].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
  
  // Group by date - TrendEntry allows dynamic branch keys
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
            <div className="text-2xl font-bold">{uniqueScansCount}</div>
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
            <div className="text-2xl font-bold">{waivers?.pages?.[0]?.total || 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Intelligence Dashboard - aggregated across all selected branches */}
      {hasEnhancedStats && (
        <ThreatIntelligenceDashboard stats={stats} branchCount={projectStats?.branchCount} />
      )}

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
                    </div>
                </CardContent>
            </Card>
        </div>
      )}

      {/* Post-Processor Intelligence (EPSS/KEV, Reachability) - per branch */}
      {activeBranch && scanResults && scanResults.some(r => isPostProcessorResult(r.analyzer_name)) && (
        <div className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <h3 className="text-xl font-semibold">Enrichment & Intelligence</h3>
            {branchNames.length > 1 && (
              <Tabs value={activeBranch} onValueChange={setEnrichmentBranch}>
                <TabsList>
                  {branchNames.map(branch => (
                    <TabsTrigger key={branch} value={branch} className="gap-1.5">
                      <GitBranch className="h-3 w-3" />
                      {branch}
                    </TabsTrigger>
                  ))}
                </TabsList>
              </Tabs>
            )}
          </div>
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
