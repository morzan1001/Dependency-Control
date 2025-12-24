/**
 * Threat Intelligence Dashboard Component
 * 
 * Displays prioritized vulnerability data using EPSS, KEV, and Reachability
 * to help teams focus on the most critical and actionable issues.
 */

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
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
  Activity
} from 'lucide-react'

interface ThreatIntelStats {
  kev_count: number
  kev_ransomware_count: number
  high_epss_count: number
  medium_epss_count: number
  avg_epss_score: number | null
  max_epss_score: number | null
  weaponized_count: number
  active_exploitation_count: number
}

interface ReachabilityStats {
  analyzed_count: number
  reachable_count: number
  likely_reachable_count: number
  unreachable_count: number
  unknown_count: number
  reachable_critical: number
  reachable_high: number
}

interface PrioritizedCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  actionable_critical: number
  actionable_high: number
  actionable_total: number
  deprioritized_count: number
}

interface Props {
  stats: {
    critical: number
    high: number
    medium: number
    low: number
    risk_score: number
    adjusted_risk_score?: number
    threat_intel?: ThreatIntelStats | null
    reachability?: ReachabilityStats | null
    prioritized?: PrioritizedCounts | null
  }
  className?: string
}

export function ThreatIntelligenceDashboard({ stats, className }: Props) {
  const threatIntel = stats.threat_intel
  const reachability = stats.reachability
  const prioritized = stats.prioritized
  
  // Calculate key metrics
  const totalVulns = stats.critical + stats.high + stats.medium + stats.low
  const actionableCount = prioritized?.actionable_total || 0
  const deprioritizedCount = prioritized?.deprioritized_count || 0
  const reductionPercent = totalVulns > 0 
    ? Math.round((deprioritizedCount / totalVulns) * 100) 
    : 0
  
  // If no threat intel data, show a simpler view
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
      {/* Priority Overview */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Target className="h-5 w-5 text-primary" />
              Prioritized View
            </CardTitle>
            {reductionPercent > 0 && (
              <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/30">
                <ArrowDownRight className="h-3 w-3 mr-1" />
                {reductionPercent}% noise reduction
              </Badge>
            )}
          </div>
          <CardDescription>
            Focus on what matters most based on real-world threat data
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {/* Actionable Critical */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="flex items-center gap-2 text-red-600 mb-1">
                      <AlertTriangle className="h-4 w-4" />
                      <span className="text-xs font-medium">Action Required</span>
                    </div>
                    <div className="text-2xl font-bold text-red-600">
                      {prioritized?.actionable_critical || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Critical + Exploitable + Reachable
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="max-w-xs">
                    Critical vulnerabilities that are either in CISA KEV (actively exploited) 
                    or have high EPSS (&gt;10%), AND are confirmed reachable in your code.
                    These require immediate attention.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>

            {/* Actionable High */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                    <div className="flex items-center gap-2 text-orange-600 mb-1">
                      <Activity className="h-4 w-4" />
                      <span className="text-xs font-medium">High Priority</span>
                    </div>
                    <div className="text-2xl font-bold text-orange-600">
                      {prioritized?.actionable_high || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      High + Exploitable + Reachable
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="max-w-xs">
                    High severity vulnerabilities with real exploitation risk 
                    that affect code paths in your application.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>

            {/* Total Actionable */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
                    <div className="flex items-center gap-2 text-primary mb-1">
                      <Target className="h-4 w-4" />
                      <span className="text-xs font-medium">Total Actionable</span>
                    </div>
                    <div className="text-2xl font-bold text-primary">
                      {actionableCount}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      of {totalVulns} total
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="max-w-xs">
                    All vulnerabilities that are both exploitable (KEV or high EPSS) 
                    AND reachable in your application.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>

            {/* Deprioritized */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="p-3 rounded-lg bg-muted border">
                    <div className="flex items-center gap-2 text-muted-foreground mb-1">
                      <ZapOff className="h-4 w-4" />
                      <span className="text-xs font-medium">Deprioritized</span>
                    </div>
                    <div className="text-2xl font-bold text-muted-foreground">
                      {deprioritizedCount}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Low risk or unreachable
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="max-w-xs">
                    Vulnerabilities that are either unreachable in your code 
                    OR have low exploitation probability (low EPSS, not in KEV).
                    These can be safely deferred.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
          
          {/* Progress bar showing actionable vs total */}
          {totalVulns > 0 && (
            <div className="mt-4 space-y-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Actionable vulnerabilities</span>
                <span>{actionableCount} of {totalVulns} ({Math.round((actionableCount / totalVulns) * 100)}%)</span>
              </div>
              <Progress 
                value={(actionableCount / totalVulns) * 100} 
                className="h-2"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Threat Intelligence Details */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* EPSS/KEV Card */}
        {threatIntel && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <TrendingUp className="h-4 w-4" />
                Exploitation Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* KEV Status */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 text-red-500" />
                  <span className="text-sm">CISA KEV (Actively Exploited)</span>
                </div>
                <Badge variant={threatIntel.kev_count > 0 ? "destructive" : "secondary"}>
                  {threatIntel.kev_count}
                </Badge>
              </div>
              
              {/* Ransomware */}
              {threatIntel.kev_ransomware_count > 0 && (
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Skull className="h-4 w-4 text-red-600" />
                    <span className="text-sm">Used in Ransomware</span>
                  </div>
                  <Badge variant="destructive">{threatIntel.kev_ransomware_count}</Badge>
                </div>
              )}
              
              {/* High EPSS */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-orange-500" />
                  <span className="text-sm">High EPSS (&gt;10%)</span>
                </div>
                <Badge variant={threatIntel.high_epss_count > 0 ? "default" : "secondary"} 
                       className={threatIntel.high_epss_count > 0 ? "bg-orange-500" : ""}>
                  {threatIntel.high_epss_count}
                </Badge>
              </div>
              
              {/* Medium EPSS */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm">Medium EPSS (1-10%)</span>
                </div>
                <Badge variant="secondary">{threatIntel.medium_epss_count}</Badge>
              </div>
              
              {/* EPSS Stats */}
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

        {/* Reachability Card */}
        {reachability && reachability.analyzed_count > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Target className="h-4 w-4" />
                Reachability Analysis
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Reachable */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <span className="text-sm">Confirmed Reachable</span>
                </div>
                <Badge variant={reachability.reachable_count > 0 ? "destructive" : "secondary"}>
                  {reachability.reachable_count}
                </Badge>
              </div>
              
              {/* Likely Reachable */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 text-orange-500" />
                  <span className="text-sm">Likely Reachable</span>
                </div>
                <Badge variant="secondary" className="bg-orange-500/20">
                  {reachability.likely_reachable_count}
                </Badge>
              </div>
              
              {/* Unreachable */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Unreachable (Safe)</span>
                </div>
                <Badge variant="secondary" className="bg-green-500/20 text-green-600">
                  {reachability.unreachable_count}
                </Badge>
              </div>
              
              {/* Unknown */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">Unknown</span>
                </div>
                <Badge variant="secondary">{reachability.unknown_count}</Badge>
              </div>
              
              {/* Severity breakdown */}
              {(reachability.reachable_critical > 0 || reachability.reachable_high > 0) && (
                <div className="pt-2 border-t text-xs text-muted-foreground">
                  <div className="flex justify-between">
                    <span>Reachable Critical:</span>
                    <span className="text-red-500 font-medium">{reachability.reachable_critical}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Reachable High:</span>
                    <span className="text-orange-500 font-medium">{reachability.reachable_high}</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Risk Score Comparison */}
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
                <div className="text-xs text-muted-foreground mb-1">Traditional (CVSS only)</div>
                <div className="text-2xl font-bold">{stats.risk_score.toFixed(1)}</div>
              </div>
              <div className="text-center p-3 bg-primary/10 rounded-lg border border-primary/20">
                <div className="text-xs text-primary mb-1">Adjusted (EPSS/KEV/Reach)</div>
                <div className="text-2xl font-bold text-primary">
                  {stats.adjusted_risk_score.toFixed(1)}
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
