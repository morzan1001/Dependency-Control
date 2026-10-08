import type { ReactNode } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge, type BadgeProps } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { 
  AlertTriangle, 
  Target, 
  TrendingUp, 
  Shield, 
  Skull,
  ZapOff,
  CheckCircle2,
  AlertCircle,
  Info,
  ArrowDownRight,
  Activity,
  type LucideIcon,
} from 'lucide-react'
import { EnhancedStats } from '@/types/scan'

interface Props {
  stats: EnhancedStats
  className?: string
}

function CountRow({ icon: Icon, iconClass, label, count, variant = 'secondary', className }: Readonly<{
  icon: LucideIcon; iconClass: string; label: string; count: ReactNode; variant?: BadgeProps['variant']; className?: string
}>) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${iconClass}`} />
        <span className="text-sm">{label}</span>
      </div>
      <Badge variant={variant} className={className}>{count}</Badge>
    </div>
  )
}

export function ThreatIntelligenceDashboard({ stats, className }: Readonly<Props>) {
  const threatIntel = stats.threat_intel
  const reachability = stats.reachability
  const prioritized = stats.prioritized

  // prioritized.total counts vulnerabilities only — the population the actionable/deprioritized
  // tiles are computed over; the stats.* severity buckets span every finding type.
  const totalVulns =
    prioritized?.total ?? ((stats.critical ?? 0) + (stats.high ?? 0) + (stats.medium ?? 0) + (stats.low ?? 0))
  const actionableCount = prioritized?.actionable_total || 0
  const deprioritizedCount = prioritized?.deprioritized_count || 0
  const reductionPercent = totalVulns > 0
    ? Math.min(100, Math.round((deprioritizedCount / totalVulns) * 100))
    : 0

  const priorityTiles = [
    {
      box: 'bg-red-500/10 border border-red-500/20', tone: 'text-severity-critical', icon: AlertTriangle,
      label: 'Action Required', value: prioritized?.actionable_critical || 0, caption: 'Critical + Exploitable',
      tooltip: 'Critical vulnerabilities that are either in CISA KEV (actively exploited) or have high EPSS (>10%), ' +
        'and not ruled out by reachability analysis. These require immediate attention.',
    },
    {
      box: 'bg-orange-500/10 border border-orange-500/20', tone: 'text-severity-high', icon: Activity,
      label: 'High Priority', value: prioritized?.actionable_high || 0, caption: 'High + Exploitable',
      tooltip: 'High severity vulnerabilities with real exploitation risk (KEV or high EPSS), ' +
        'not ruled out by reachability analysis.',
    },
    {
      box: 'bg-primary/10 border border-primary/20', tone: 'text-primary', icon: Target,
      label: 'Total Actionable', value: actionableCount, caption: `of ${totalVulns} total`,
      tooltip: 'All vulnerabilities that are exploitable (KEV or high EPSS) and not ruled out by reachability analysis.',
    },
    {
      box: 'bg-muted border', tone: 'text-muted-foreground', icon: ZapOff,
      label: 'Deprioritized', value: deprioritizedCount, caption: 'Low risk or unreachable',
      tooltip: 'Vulnerabilities that are either unreachable in your code OR have low exploitation probability ' +
        '(low EPSS, not in KEV). These can be safely deferred.',
    },
  ]

  if (!threatIntel && !reachability) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Threat Intelligence
          </CardTitle>
          <CardDescription>
            EPSS/KEV enrichment and reachability analysis not yet available.
            Run a scan with the EPSS/KEV and Reachability analyzers enabled.
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }
  
  return (
    <div className={`space-y-4 ${className}`}>
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Target className="h-5 w-5 text-primary" />
              Prioritized View
            </CardTitle>
            <div className="flex items-center gap-2">
              {reductionPercent > 0 && (
                <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/30">
                  <ArrowDownRight className="h-3 w-3 mr-1" />
                  {reductionPercent}% noise reduction
                </Badge>
              )}
            </div>
          </div>
          <CardDescription>
            Focus on what matters most based on real-world threat data
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {priorityTiles.map((tile) => (
              <TooltipProvider key={tile.label}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className={`p-3 rounded-lg ${tile.box}`}>
                      <div className={`flex items-center gap-2 ${tile.tone} mb-1`}>
                        <tile.icon className="h-4 w-4" />
                        <span className="text-xs font-medium">{tile.label}</span>
                      </div>
                      <div className={`text-2xl font-bold ${tile.tone}`}>
                        {tile.value}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {tile.caption}
                      </div>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="max-w-xs">{tile.tooltip}</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ))}
          </div>

          {totalVulns > 0 && (
            <div className="mt-4 space-y-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Actionable vulnerabilities</span>
                <span>{actionableCount} of {totalVulns} ({Math.min(100, Math.round((actionableCount / totalVulns) * 100))}%)</span>
              </div>
              <Progress
                value={Math.min(100, (actionableCount / totalVulns) * 100)}
                className="h-2"
              />
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {threatIntel && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <TrendingUp className="h-4 w-4" />
                Exploitation Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <CountRow
                icon={AlertCircle} iconClass="text-severity-critical" label="KEV findings (actively exploited)"
                count={threatIntel.kev_count} variant={threatIntel.kev_count > 0 ? 'destructive' : 'secondary'}
              />
              {threatIntel.kev_ransomware_count > 0 && (
                <CountRow
                  icon={Skull} iconClass="text-severity-critical" label="Used in Ransomware"
                  count={threatIntel.kev_ransomware_count} variant="destructive"
                />
              )}
              <CountRow
                icon={TrendingUp} iconClass="text-severity-high" label="High EPSS (>10%)" count={threatIntel.high_epss_count}
                variant={threatIntel.high_epss_count > 0 ? 'default' : 'secondary'}
                className={threatIntel.high_epss_count > 0 ? 'bg-orange-500' : ''}
              />
              <CountRow
                icon={Activity} iconClass="text-severity-medium" label="Medium EPSS (1-10%)" count={threatIntel.medium_epss_count}
              />
              {threatIntel.avg_epss_score !== null && (
                <div className="pt-2 border-t text-xs text-muted-foreground">
                  <div className="flex justify-between">
                    <span>Average EPSS:</span>
                    <span>{(threatIntel.avg_epss_score * 100).toFixed(2)}%</span>
                  </div>
                  {threatIntel.max_epss_score !== null && (
                    <div className="flex justify-between">
                      <span>Max EPSS:</span>
                      <span>{(threatIntel.max_epss_score * 100).toFixed(2)}%</span>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {reachability?.analyzed_count === 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Target className="h-4 w-4" />
                Reachability Analysis
              </CardTitle>
              <CardDescription>
                {(reachability.coverable_count ?? 0) === 0
                  ? 'No finding here is in an ecosystem a callgraph can analyse (npm, PyPI, Go, Maven). ' +
                    'OS packages from a container image are never coverable, so enabling the ' +
                    'callgraph jobs would not change these results.'
                  : `${reachability.coverable_count} of ${totalVulns} findings are in a callgraph-supported ` +
                    'ecosystem. Add the callgraph job for that language to your pipeline to get verdicts.'}
              </CardDescription>
            </CardHeader>
          </Card>
        )}

        {reachability && reachability.analyzed_count > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Target className="h-4 w-4" />
                Reachability Analysis
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <CountRow
                icon={AlertTriangle} iconClass="text-severity-critical" label="Confirmed Reachable (symbol-level)"
                count={reachability.confirmed_reachable_count}
                variant={reachability.confirmed_reachable_count > 0 ? 'destructive' : 'secondary'}
              />
              <CountRow
                icon={AlertCircle} iconClass="text-severity-high" label="Likely Reachable (import-level)"
                count={reachability.likely_reachable_count} className="bg-orange-500/20"
              />
              <CountRow
                icon={CheckCircle2} iconClass="text-success" label="Unreachable (Safe)"
                count={reachability.unreachable_count} className="bg-green-500/20 text-green-600"
              />
              <CountRow icon={Info} iconClass="text-muted-foreground" label="Unknown" count={reachability.unknown_count} />

              {reachability.coverable_count !== undefined && (
                <p className="text-xs text-muted-foreground pt-1">
                  {reachability.coverable_count} of {totalVulns} findings are in a callgraph-supported
                  ecosystem; the rest can never receive a verdict.
                </p>
              )}
              
              {(reachability.reachable_critical > 0 || reachability.reachable_high > 0) && (
                <div className="pt-2 border-t text-xs text-muted-foreground">
                  <div className="flex justify-between">
                    <span>Reachable Critical:</span>
                    <span className="text-severity-critical font-medium">{reachability.reachable_critical}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Reachable High:</span>
                    <span className="text-severity-high font-medium">{reachability.reachable_high}</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {stats.adjusted_risk_score !== undefined && stats.adjusted_risk_score !== stats.risk_score && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4" />
              Risk Score Comparison
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-3 bg-muted rounded-lg">
                <div className="text-xs text-muted-foreground mb-1">Base (severity-weighted)</div>
                <div className="text-2xl font-bold">{(stats.risk_score ?? 0).toFixed(1)}</div>
              </div>
              <div className="text-center p-3 bg-primary/10 rounded-lg border border-primary/20">
                <div className="text-xs text-primary mb-1">Reachability-adjusted</div>
                <div className="text-2xl font-bold text-primary">
                  {(stats.adjusted_risk_score ?? 0).toFixed(1)}
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2 text-center">
              The adjusted score incorporates real-world exploitation data and code reachability
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
