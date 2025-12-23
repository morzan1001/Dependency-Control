import { useQuery } from '@tanstack/react-query'
import { getImpactAnalysis, ImpactAnalysisResult } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Progress } from '@/components/ui/progress'
import { AlertTriangle, TrendingUp, Zap, Shield, CheckCircle, XCircle, Lock, Calendar, Target, TrendingUp as TrendingUpIcon, CircleAlert, Globe, Clock } from 'lucide-react'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

interface ImpactAnalysisProps {
  onSelectComponent?: (result: ImpactAnalysisResult) => void;
}

export function ImpactAnalysis({ onSelectComponent }: ImpactAnalysisProps) {
  const { data: results, isLoading } = useQuery({
    queryKey: ['impact-analysis'],
    queryFn: () => getImpactAnalysis(20),
  })

  // Calculate max impact score for relative sizing
  const maxImpact = results?.reduce((max, r) => Math.max(max, r.fix_impact_score), 0) || 1

  const formatEpssScore = (score?: number) => {
    if (score === undefined || score === null) return null
    return `${(score * 100).toFixed(1)}%`
  }

  const getExploitMaturityColor = (maturity?: string) => {
    if (!maturity || maturity === 'unknown') return 'text-muted-foreground'
    const colors: Record<string, string> = {
      'active': 'text-red-500',
      'weaponized': 'text-red-600',
      'high': 'text-orange-500',
      'medium': 'text-yellow-500',
      'low': 'text-blue-500',
    }
    return colors[maturity] || 'text-muted-foreground'
  }

  // Helper to render priority reason with icon instead of emoji
  const renderPriorityReason = (reason: string) => {
    const [type, text] = reason.includes(':') ? reason.split(':', 2) : ['', reason]
    
    const iconMap: Record<string, React.ReactNode> = {
      'ransomware': <Lock className="h-3 w-3 text-purple-500 flex-shrink-0" />,
      'deadline_overdue': <AlertTriangle className="h-3 w-3 text-red-500 flex-shrink-0" />,
      'deadline': <Calendar className="h-3 w-3 text-orange-500 flex-shrink-0" />,
      'kev': <Target className="h-3 w-3 text-red-500 flex-shrink-0" />,
      'epss': <TrendingUpIcon className="h-3 w-3 text-orange-500 flex-shrink-0" />,
      'critical': <CircleAlert className="h-3 w-3 text-red-500 flex-shrink-0" />,
      'blast_radius': <Globe className="h-3 w-3 text-blue-500 flex-shrink-0" />,
      'fix_available': <CheckCircle className="h-3 w-3 text-green-500 flex-shrink-0" />,
      'overdue': <Clock className="h-3 w-3 text-yellow-500 flex-shrink-0" />,
    }

    const icon = iconMap[type] || null
    const displayText = text || reason

    return (
      <span className="flex items-center gap-1">
        {icon}
        <span>{displayText}</span>
      </span>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Zap className="h-5 w-5 text-yellow-500" />
          <div>
            <CardTitle>Impact Analysis</CardTitle>
            <CardDescription>
              Prioritized list of fixes - addressing these would have the greatest security impact
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array(5).fill(0).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : results && results.length > 0 ? (
          <div className="space-y-4">
            {/* Top 3 Priority Fixes */}
            <div className="grid gap-4 md:grid-cols-3">
              {results.slice(0, 3).map((r, index) => (
                <Card 
                  key={`${r.component}-${r.version}`}
                  className={`cursor-pointer transition-colors hover:bg-muted ${
                    index === 0 ? 'border-red-500 border-2' : 
                    index === 1 ? 'border-orange-500 border-2' : 
                    'border-yellow-500 border-2'
                  }`}
                  onClick={() => onSelectComponent?.(r)}
                >
                  <CardContent className="pt-4">
                    <div className="flex items-center justify-between mb-2">
                      <Badge variant={index === 0 ? "destructive" : "secondary"}>
                        #{index + 1} Priority
                      </Badge>
                      <div className="flex items-center gap-1 text-sm">
                        <TrendingUp className="h-4 w-4" />
                        <span className="font-medium">{Math.round(r.fix_impact_score)}</span>
                      </div>
                    </div>
                    <h4 className="font-medium truncate" title={r.component}>
                      {r.component}
                    </h4>
                    <p className="text-sm text-muted-foreground">v{r.version}</p>
                    <div className="flex items-center gap-2 mt-2 text-sm">
                      <span>{r.affected_projects} projects</span>
                      <span>•</span>
                      <span>{r.total_findings} findings</span>
                    </div>
                    <div className="flex gap-1 mt-2 flex-wrap">
                      {r.findings_by_severity.critical > 0 && (
                        <Badge variant="destructive" className="text-xs">
                          {r.findings_by_severity.critical} Critical
                        </Badge>
                      )}
                      {r.findings_by_severity.high > 0 && (
                        <Badge className="text-xs bg-orange-500">
                          {r.findings_by_severity.high} High
                        </Badge>
                      )}
                    </div>
                    {/* EPSS/KEV indicators */}
                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                      {r.has_kev && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Badge variant="destructive" className="text-xs gap-1">
                                <Shield className="h-3 w-3" />
                                KEV
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>CISA Known Exploited Vulnerability</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                      {r.max_epss_score !== undefined && r.max_epss_score !== null && r.max_epss_score >= 0.01 && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Badge variant="outline" className={`text-xs ${
                                r.max_epss_score >= 0.1 ? 'border-red-500 text-red-500' :
                                'border-orange-500 text-orange-500'
                              }`}>
                                EPSS: {formatEpssScore(r.max_epss_score)}
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Probability of exploitation in 30 days</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                      {r.has_fix && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Badge variant="outline" className="text-xs gap-1 border-green-500 text-green-500">
                                <CheckCircle className="h-3 w-3" />
                                Fix available
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Fix versions: {r.fix_versions?.join(', ') || 'Available'}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                    </div>
                    {/* Priority Reasons */}
                    {r.priority_reasons && r.priority_reasons.length > 0 && (
                      <div className="mt-2 pt-2 border-t border-muted">
                        <ul className="text-xs text-muted-foreground space-y-0.5">
                          {r.priority_reasons.slice(0, 3).map((reason, i) => (
                            <li key={i}>{reason}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Full Table */}
            <Table>
              <TableHeader className="sticky top-0 bg-background z-10 shadow-sm">
                <TableRow>
                  <TableHead>Component</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead className="text-center">Projects</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-center">EPSS</TableHead>
                  <TableHead className="text-center">KEV</TableHead>
                  <TableHead>Impact</TableHead>
                  <TableHead>Fix</TableHead>
                  <TableHead>Priority Reasons</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((r) => (
                  <TableRow 
                    key={`${r.component}-${r.version}`}
                    className={onSelectComponent ? "cursor-pointer hover:bg-muted" : ""}
                    onClick={() => onSelectComponent?.(r)}
                  >
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-destructive" />
                        <span className="font-medium">{r.component}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{r.version}</Badge>
                    </TableCell>
                    <TableCell className="text-center font-medium">
                      {r.affected_projects}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {r.findings_by_severity.critical > 0 && (
                          <Badge variant="destructive" className="text-xs">
                            C:{r.findings_by_severity.critical}
                          </Badge>
                        )}
                        {r.findings_by_severity.high > 0 && (
                          <Badge className="text-xs bg-orange-500 hover:bg-orange-600">
                            H:{r.findings_by_severity.high}
                          </Badge>
                        )}
                        {r.findings_by_severity.medium > 0 && (
                          <Badge className="text-xs bg-yellow-500 hover:bg-yellow-600 text-black">
                            M:{r.findings_by_severity.medium}
                          </Badge>
                        )}
                        {r.findings_by_severity.low > 0 && (
                          <Badge className="text-xs bg-blue-500 hover:bg-blue-600">
                            L:{r.findings_by_severity.low}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      {r.max_epss_score !== undefined && r.max_epss_score !== null ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="flex flex-col items-center">
                                <span className={`font-medium ${
                                  r.max_epss_score >= 0.1 ? 'text-red-500' :
                                  r.max_epss_score >= 0.01 ? 'text-orange-500' : 'text-muted-foreground'
                                }`}>
                                  {formatEpssScore(r.max_epss_score)}
                                </span>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Probability of exploitation in next 30 days</p>
                              {r.epss_percentile !== undefined && (
                                <p className="text-xs">Percentile: {(r.epss_percentile * 100).toFixed(1)}%</p>
                              )}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-center">
                      {r.has_kev ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="flex flex-col items-center gap-1">
                                <Badge variant="destructive" className="text-xs gap-1">
                                  <Shield className="h-3 w-3" />
                                  KEV{r.kev_count && r.kev_count > 1 ? ` (${r.kev_count})` : ''}
                                </Badge>
                                {r.kev_ransomware_use && (
                                  <Badge className="text-xs bg-purple-600 gap-1"><Lock className="h-3 w-3" />Ransomware</Badge>
                                )}
                              </div>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-xs">
                              <p className="font-medium">CISA Known Exploited Vulnerability</p>
                              <p className="text-xs">Actively exploited in the wild</p>
                              {r.kev_ransomware_use && (
                                <p className="text-xs text-purple-400 mt-1 flex items-center gap-1"><AlertTriangle className="h-3 w-3" />Used in ransomware campaigns</p>
                              )}
                              {r.kev_due_date && (
                                <p className="text-xs mt-1 flex items-center gap-1"><Calendar className="h-3 w-3" />Remediation due: {r.kev_due_date}</p>
                              )}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div className="w-24">
                              <Progress 
                                value={(r.fix_impact_score / maxImpact) * 100} 
                                className="h-2"
                              />
                              <span className="text-xs text-muted-foreground">
                                {Math.round(r.fix_impact_score)}
                              </span>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Impact score: {Math.round(r.fix_impact_score)}</p>
                            <p className="text-xs text-muted-foreground">
                              Weighted by severity × projects × EPSS × KEV
                            </p>
                            {r.exploit_maturity && r.exploit_maturity !== 'unknown' && (
                              <p className={`text-xs ${getExploitMaturityColor(r.exploit_maturity)}`}>
                                Exploit maturity: {r.exploit_maturity}
                              </p>
                            )}
                            {r.days_known !== undefined && r.days_known !== null && (
                              <p className="text-xs mt-1 flex items-center gap-1"><Clock className="h-3 w-3" />Known for {r.days_known} days</p>
                            )}
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </TableCell>
                    <TableCell>
                      {r.has_fix ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="flex items-center gap-1 text-green-500">
                                <CheckCircle className="h-4 w-4" />
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Fix versions: {r.fix_versions?.join(', ') || r.recommended_version || 'Available'}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        <div className="flex items-center gap-1 text-muted-foreground">
                          <XCircle className="h-4 w-4" />
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      {r.priority_reasons && r.priority_reasons.length > 0 ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="max-w-[200px]">
                                <div className="text-xs truncate">{renderPriorityReason(r.priority_reasons[0])}</div>
                                {r.priority_reasons.length > 1 && (
                                  <span className="text-xs text-muted-foreground">
                                    +{r.priority_reasons.length - 1} more
                                  </span>
                                )}
                              </div>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-xs">
                              <p className="font-medium mb-1">Priority Reasons:</p>
                              <ul className="text-xs space-y-1">
                                {r.priority_reasons.map((reason, i) => (
                                  <li key={i}>{renderPriorityReason(reason)}</li>
                                ))}
                              </ul>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Zap className="h-12 w-12 mb-4" />
            <p>No vulnerabilities found to analyze</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
