import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createWaiver, Finding } from "@/lib/api"
import { toast } from "sonner"
import { ShieldAlert, Shield, Container, FileCode, HardDrive, Layers, ExternalLink, FileText, Calendar, AlertTriangle, User, Building, ChevronDown, ChevronRight, Copy, Check, Clock, GitBranch, Mail, Package, Activity, Scale, BookOpen, Lightbulb, CheckCircle2, XCircle, Info } from "lucide-react"
import { useAuth } from "@/context/AuthContext"
import { AxiosError } from "axios"
import { useNavigate } from "react-router-dom"

// Helper to get source info
function getSourceInfo(sourceType?: string) {
  switch (sourceType) {
    case 'image':
      return { icon: Container, label: 'Docker Image', color: 'text-blue-500', bgColor: 'bg-blue-50 border-blue-200' }
    case 'file':
      return { icon: FileCode, label: 'Source File', color: 'text-green-500', bgColor: 'bg-green-50 border-green-200' }
    case 'directory':
      return { icon: HardDrive, label: 'Directory', color: 'text-amber-500', bgColor: 'bg-amber-50 border-amber-200' }
    case 'application':
      return { icon: Layers, label: 'Application', color: 'text-purple-500', bgColor: 'bg-purple-50 border-purple-200' }
    default:
      return null
  }
}

// Component for rendering additional details based on finding type
function AdditionalDetailsView({ details }: { details: Record<string, unknown> }) {
  // Skip rendering for these redundant fields that are shown elsewhere
  const skipFields = ['license', 'severity', 'type', 'message', 'id', 'component', 'version', 'fixed_version']
  
  // Fields that should be grouped together in a row (e.g., cycle and lts for EOL)
  const rowGroupFields = ['cycle', 'lts']
  
  // Filter out empty values and redundant fields
  const filteredEntries = Object.entries(details).filter(([key, value]) => {
    if (skipFields.includes(key)) return false
    if (value === null || value === undefined || value === '') return false
    if (Array.isArray(value) && value.length === 0) return false
    if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value as object).length === 0) return false
    return true
  })
  
  // Separate grouped fields from regular fields
  const groupedEntries = filteredEntries.filter(([key]) => rowGroupFields.includes(key))
  const regularEntries = filteredEntries.filter(([key]) => !rowGroupFields.includes(key))
  
  if (filteredEntries.length === 0) {
    return null
  }
  
  // Helper to render a value based on its type
  const renderValue = (key: string, value: unknown) => {
    // Handle license_url specially - render as link
    if (key === 'license_url' && typeof value === 'string') {
      return (
        <a 
          href={value} 
          target="_blank" 
          rel="noopener noreferrer"
          className="text-primary hover:underline flex items-center gap-1"
        >
          <ExternalLink className="h-3 w-3" />
          View License
        </a>
      )
    }
    
    // Handle URLs in any field
    if (typeof value === 'string' && (value.startsWith('http://') || value.startsWith('https://'))) {
      return (
        <a 
          href={value} 
          target="_blank" 
          rel="noopener noreferrer"
          className="text-primary hover:underline break-all"
        >
          {value}
        </a>
      )
    }
    
    // Handle dates
    if (key.includes('date') || key === 'eol' || key === 'end_of_life') {
      const dateStr = String(value)
      try {
        const date = new Date(dateStr)
        if (!isNaN(date.getTime())) {
          return <span>{date.toLocaleDateString()}</span>
        }
      } catch {
        // Fall through to default
      }
    }
    
    // Handle booleans
    if (typeof value === 'boolean') {
      return <Badge variant={value ? "default" : "secondary"}>{value ? 'Yes' : 'No'}</Badge>
    }
    
    // Handle arrays
    if (Array.isArray(value)) {
      // Check if array contains URLs
      const hasUrls = value.some(item => typeof item === 'string' && (item.startsWith('http://') || item.startsWith('https://')))
      if (hasUrls) {
        return (
          <div className="flex flex-col gap-1">
            {value.map((item, i) => (
              typeof item === 'string' && (item.startsWith('http://') || item.startsWith('https://')) ? (
                <a 
                  key={i}
                  href={item} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline break-all text-xs flex items-center gap-1"
                >
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                  {item}
                </a>
              ) : (
                <Badge key={i} variant="outline" className="font-mono text-xs w-fit">
                  {String(item)}
                </Badge>
              )
            ))}
          </div>
        )
      }
      return (
        <div className="flex flex-wrap gap-1">
          {value.map((item, i) => (
            <Badge key={i} variant="outline" className="font-mono text-xs">
              {String(item)}
            </Badge>
          ))}
        </div>
      )
    }
    
    // Handle nested objects
    if (typeof value === 'object' && value !== null) {
      return (
        <pre className="bg-muted p-2 rounded text-xs overflow-auto max-h-32">
          {JSON.stringify(value, null, 2)}
        </pre>
      )
    }
    
    // Default: render as string
    return <span className="break-all">{String(value)}</span>
  }
  
  // Get appropriate icon for field
  const getFieldIcon = (key: string) => {
    if (key.includes('url') || key.includes('link')) return ExternalLink
    if (key.includes('date') || key.includes('eol') || key.includes('end_of_life')) return Calendar
    if (key.includes('license')) return FileText
    if (key.includes('author') || key.includes('maintainer')) return User
    if (key.includes('publisher') || key.includes('vendor')) return Building
    if (key.includes('risk') || key.includes('warning')) return AlertTriangle
    return null
  }
  
  // Format field name for display
  const formatFieldName = (key: string) => {
    return key
      .replace(/_/g, ' ')
      .replace(/([A-Z])/g, ' $1')
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ')
      .trim()
  }
  
  return (
    <div className="bg-muted/50 rounded-lg p-4 space-y-3">
      {/* Grouped fields (cycle + lts) displayed side by side */}
      {groupedEntries.length > 0 && (
        <div className="grid grid-cols-2 gap-4">
          {groupedEntries.map(([key, value]) => {
            const Icon = getFieldIcon(key)
            return (
              <div key={key} className="flex items-start gap-3">
                {Icon && <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />}
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-muted-foreground">{formatFieldName(key)}</p>
                  <div className="text-sm">{renderValue(key, value)}</div>
                </div>
              </div>
            )
          })}
        </div>
      )}
      {/* Regular fields */}
      {regularEntries.map(([key, value]) => {
        const Icon = getFieldIcon(key)
        return (
          <div key={key} className="flex items-start gap-3">
            {Icon && <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />}
            <div className="flex-1 min-w-0">
              <p className="text-xs text-muted-foreground">{formatFieldName(key)}</p>
              <div className="text-sm">{renderValue(key, value)}</div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// Types for maintainer risk details
interface MaintainerRisk {
  type: string;
  severity_score: number;
  message: string;
  detail: string;
}

interface MaintainerInfo {
  author?: string | null;
  author_email?: string | null;
  maintainer?: string | null;
  maintainer_email?: string | null;
  latest_release_date?: string | null;
  days_since_release?: number | null;
  release_count?: number | null;
  home_page?: string | null;
  project_urls?: Record<string, string> | null;
}

interface ScorecardContext {
  overall_score?: number;
  project_url?: string;
  critical_issues?: string[];
  maintenance_risk?: boolean;
  has_vulnerabilities_issue?: boolean;
}

// Component for rendering OpenSSF Scorecard context on vulnerabilities
function ScorecardContextBanner({ context }: { context: ScorecardContext }) {
  // Don't show if no context, no valid score, and no critical issues
  const hasValidScore = context?.overall_score !== undefined && 
                        context.overall_score !== null && 
                        !isNaN(context.overall_score);
  const hasCriticalIssues = context?.critical_issues && context.critical_issues.length > 0;
  
  if (!context || (!hasValidScore && !hasCriticalIssues)) {
    return null
  }

  const score = context.overall_score ?? 0
  const isLowScore = score < 5.0
  const isVeryLowScore = score < 3.0
  
  // Determine banner color based on risk level
  const getBannerStyle = () => {
    if (isVeryLowScore || context.maintenance_risk) {
      return "bg-red-50 border-red-200 text-red-800"
    }
    if (isLowScore) {
      return "bg-amber-50 border-amber-200 text-amber-800"
    }
    return "bg-blue-50 border-blue-200 text-blue-700"
  }
  
  const getScoreColor = () => {
    if (isVeryLowScore) return "text-red-600"
    if (isLowScore) return "text-amber-600"
    return "text-green-600"
  }

  return (
    <div className={`rounded-lg border p-3 space-y-2 ${getBannerStyle()}`}>
      <div className="flex items-start gap-2">
        <Activity className="h-4 w-4 mt-0.5 flex-shrink-0" />
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium">OpenSSF Scorecard</span>
            <span className={`text-sm font-bold ${getScoreColor()}`}>
              {score.toFixed(1)}/10
            </span>
            {context.maintenance_risk && (
              <Badge variant="destructive" className="text-xs">
                Potentially Unmaintained
              </Badge>
            )}
            {context.has_vulnerabilities_issue && (
              <Badge variant="destructive" className="text-xs">
                Has Open Vulnerabilities
              </Badge>
            )}
          </div>
          
          {(isLowScore || context.maintenance_risk) && (
            <p className="text-xs mt-1 opacity-90">
              {context.maintenance_risk 
                ? "This package may not receive security updates. Consider finding an actively maintained alternative."
                : "This package has a low security score. Exercise caution and monitor closely."
              }
            </p>
          )}
          
          {context.critical_issues && context.critical_issues.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {context.critical_issues.map((issue, idx) => (
                <Badge key={idx} variant="outline" className="text-xs bg-white/50">
                  {issue}
                </Badge>
              ))}
            </div>
          )}
          
          {context.project_url && (
            <a 
              href={context.project_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs mt-2 hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              View on OpenSSF Scorecard
            </a>
          )}
        </div>
      </div>
    </div>
  )
}

// Component for rendering quality findings (OpenSSF Scorecard details)
function QualityDetailsView({ details }: { details: Record<string, unknown> }) {
  const overallScore = details.overall_score as number
  const failedChecks = (details.failed_checks as Array<{ name: string; score: number }>) || []
  const criticalIssues = (details.critical_issues as string[]) || []
  const repository = details.repository as string
  const recommendation = details.recommendation as string
  const checksSummary = details.checks_summary as Record<string, number>
  
  const getScoreColor = (score: number) => {
    if (score < 3) return "text-red-600"
    if (score < 5) return "text-amber-600"
    if (score < 7) return "text-yellow-600"
    return "text-green-600"
  }
  
  const getScoreBg = (score: number) => {
    if (score < 3) return "bg-red-100"
    if (score < 5) return "bg-amber-100"
    if (score < 7) return "bg-yellow-100"
    return "bg-green-100"
  }

  // Only show scorecard section if we have a valid score
  const hasValidScore = overallScore !== undefined && overallScore !== null && !isNaN(overallScore);

  return (
    <div className="space-y-4">
      {/* Score Overview - only show if we have a valid score */}
      {hasValidScore && (
        <div className="flex items-center gap-4 p-4 bg-muted/50 rounded-lg border">
          <div className={`flex items-center justify-center w-16 h-16 rounded-full ${getScoreBg(overallScore)}`}>
            <span className={`text-2xl font-bold ${getScoreColor(overallScore)}`}>
              {overallScore.toFixed(1)}
            </span>
          </div>
          <div className="flex-1">
            <h4 className="font-medium">OpenSSF Scorecard</h4>
            <p className="text-sm text-muted-foreground">
              {overallScore >= 7 
                ? "Good security practices"
                : overallScore >= 5 
                  ? "Moderate security practices - room for improvement"
                  : overallScore >= 3 
                    ? "Concerning security practices - review carefully"
                    : "Poor security practices - high risk"
              }
            </p>
            {repository && (
              <a 
                href={repository.startsWith('http') ? repository : repository.includes('github.com') ? `https://${repository}` : `https://github.com/${repository}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-primary mt-1 hover:underline"
              >
                <ExternalLink className="h-3 w-3" />
                {repository.replace(/^https?:\/\//, '')}
              </a>
            )}
          </div>
        </div>
      )}
      
      {/* Critical Issues */}
      {criticalIssues.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500" />
            Critical Issues
          </h4>
          <div className="flex flex-wrap gap-2">
            {criticalIssues.map((issue, idx) => (
              <Badge key={idx} variant="destructive" className="text-xs">
                {issue}
              </Badge>
            ))}
          </div>
        </div>
      )}
      
      {/* Failed Checks */}
      {failedChecks.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2">
            Failed Checks ({failedChecks.length})
          </h4>
          <div className="grid grid-cols-2 gap-2">
            {failedChecks.map((check, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 bg-muted/50 rounded border">
                <span className="text-sm">{check.name}</span>
                <Badge variant="outline" className={getScoreColor(check.score)}>
                  {check.score}/10
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* All Checks Summary */}
      {checksSummary && Object.keys(checksSummary).length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2">
            All Checks
          </h4>
          <div className="grid grid-cols-3 gap-1 text-xs">
            {Object.entries(checksSummary)
              .sort((a, b) => a[1] - b[1])
              .map(([name, score]) => (
                <div key={name} className="flex items-center justify-between p-1.5 bg-muted/30 rounded">
                  <span className="truncate">{name}</span>
                  <span className={`font-mono ${getScoreColor(score)}`}>{score}</span>
                </div>
              ))
            }
          </div>
        </div>
      )}
      
      {/* Recommendation */}
      {recommendation && (
        <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <h4 className="text-sm font-medium text-blue-800 mb-1 flex items-center gap-2">
            <Lightbulb className="h-4 w-4" />
            Recommendations
          </h4>
          <p className="text-sm text-blue-700">
            {recommendation.split(' • ').map((rec, idx) => (
              <span key={idx} className="block">• {rec}</span>
            ))}
          </p>
        </div>
      )}
      
      {/* Scorecard Report Link */}
      {repository && (
        <a 
          href={`https://scorecard.dev/viewer/?uri=${encodeURIComponent(repository.replace(/^https?:\/\//, ''))}`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 text-sm text-primary hover:underline"
        >
          <ExternalLink className="h-4 w-4" />
          View Full Scorecard Report
        </a>
      )}
    </div>
  )
}

// Component for rendering maintainer risk details
function MaintainerRiskDetailsView({ details }: { details: Record<string, unknown> }) {
  const risks = (details.risks as MaintainerRisk[]) || []
  const maintainerInfo = (details.maintainer_info as MaintainerInfo) || {}
  
  const getRiskIcon = (type: string) => {
    switch (type) {
      case 'stale_package': return Clock
      case 'infrequent_updates': return Activity
      case 'free_email_maintainer': return Mail
      case 'single_maintainer': return User
      case 'archived_repo': return GitBranch
      default: return AlertTriangle
    }
  }
  
  const getRiskBadgeVariant = (score: number): "destructive" | "default" | "secondary" => {
    if (score >= 3) return "destructive"
    if (score >= 2) return "default"
    return "secondary"
  }

  const formatRiskType = (type: string) => {
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  return (
    <div className="space-y-4">
      {/* Risk Factors */}
      {risks.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2">Risk Factors ({risks.length})</h4>
          <div className="space-y-2">
            {risks.map((risk, idx) => {
              const Icon = getRiskIcon(risk.type)
              return (
                <div key={idx} className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg border">
                  <Icon className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm">{formatRiskType(risk.type)}</span>
                      <Badge variant={getRiskBadgeVariant(risk.severity_score)} className="text-xs">
                        Score: {risk.severity_score}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{risk.message}</p>
                    {risk.detail && (
                      <p className="text-xs text-muted-foreground mt-1 italic">{risk.detail}</p>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
      
      {/* Maintainer Info */}
      {Object.keys(maintainerInfo).length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2">Maintainer Information</h4>
          <div className="bg-muted/50 rounded-lg p-4 border space-y-3">
            <div className="grid grid-cols-2 gap-4">
              {/* Author */}
              {(maintainerInfo.author || maintainerInfo.author_email) && (
                <div className="flex items-start gap-2">
                  <User className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Author</p>
                    <p className="text-sm font-medium">{maintainerInfo.author || 'Unknown'}</p>
                    {maintainerInfo.author_email && (
                      <p className="text-xs text-muted-foreground">{maintainerInfo.author_email}</p>
                    )}
                  </div>
                </div>
              )}
              
              {/* Maintainer */}
              {(maintainerInfo.maintainer || maintainerInfo.maintainer_email) && (
                <div className="flex items-start gap-2">
                  <Building className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Maintainer</p>
                    <p className="text-sm font-medium">{maintainerInfo.maintainer || 'Unknown'}</p>
                    {maintainerInfo.maintainer_email && (
                      <p className="text-xs text-muted-foreground">{maintainerInfo.maintainer_email}</p>
                    )}
                  </div>
                </div>
              )}
              
              {/* Last Release */}
              {maintainerInfo.latest_release_date && (
                <div className="flex items-start gap-2">
                  <Calendar className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Last Release</p>
                    <p className="text-sm font-medium">
                      {new Date(maintainerInfo.latest_release_date!).toLocaleDateString()}
                    </p>
                    {maintainerInfo.days_since_release && (
                      <p className="text-xs text-muted-foreground">
                        {maintainerInfo.days_since_release} days ago
                      </p>
                    )}
                  </div>
                </div>
              )}
              
              {/* Release Count */}
              {maintainerInfo.release_count && (
                <div className="flex items-start gap-2">
                  <Package className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Total Releases</p>
                    <p className="text-sm font-medium">{maintainerInfo.release_count}</p>
                  </div>
                </div>
              )}
            </div>
            
            {/* Project URLs */}
            {(maintainerInfo.home_page || maintainerInfo.project_urls) && (
              <div className="pt-2 border-t">
                <p className="text-xs text-muted-foreground mb-2">Project Links</p>
                <div className="flex flex-wrap gap-2">
                  {maintainerInfo.home_page && (
                    <a 
                      href={maintainerInfo.home_page} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" />
                      Homepage
                    </a>
                  )}
                  {maintainerInfo.project_urls && (
                    Object.entries(maintainerInfo.project_urls).map(([name, url]) => (
                      name !== 'Homepage' ? (
                        <a 
                          key={name}
                          href={url} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                        >
                          <ExternalLink className="h-3 w-3" />
                          {name}
                        </a>
                      ) : null
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Interface for quality issue entry (from aggregated quality findings)
interface QualityIssueEntry {
  id: string;
  type: string;
  severity: string;
  description: string;
  scanners: string[];
  source?: string;
  details: Record<string, unknown>;
}

// Component for rendering aggregated quality findings (similar to vulnerabilities)
function AggregatedQualityView({ details }: { details: Record<string, unknown> }) {
  const qualityIssues = (details.quality_issues as QualityIssueEntry[]) || []
  const overallScore = details.overall_score as number | undefined
  const hasMaintenanceIssues = details.has_maintenance_issues as boolean
  const issueCount = details.issue_count as number || qualityIssues.length
  const [expandedIssues, setExpandedIssues] = useState<Set<string>>(new Set())
  
  // Helper to check for valid scorecard score
  const hasValidScorecardScore = (d: Record<string, unknown>) => {
    const score = d.overall_score as number | undefined;
    return score !== undefined && score !== null && !isNaN(score);
  }
  
  // Legacy support: if no quality_issues array, check for old structure
  if (qualityIssues.length === 0) {
    // Check for legacy scorecard structure - only if we have a valid score
    const scorecardDetails = (details.scorecard as Record<string, unknown>) || details
    if (hasValidScorecardScore(scorecardDetails)) {
      return <QualityDetailsView details={scorecardDetails} />
    }
    // Check for legacy maintainer_risk structure
    if (details.risks || details.maintainer_risk) {
      const maintDetails = (details.maintainer_risk as Record<string, unknown>) || details
      return <MaintainerRiskDetailsView details={maintDetails} />
    }
    return null
  }
  
  const toggleIssue = (id: string) => {
    setExpandedIssues(prev => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }
  
  const getIssueIcon = (type: string) => {
    switch (type) {
      case 'scorecard': return Shield
      case 'maintainer_risk': return Clock
      default: return AlertTriangle
    }
  }
  
  const getIssueLabel = (type: string) => {
    switch (type) {
      case 'scorecard': return 'OpenSSF Scorecard'
      case 'maintainer_risk': return 'Maintainer Risk'
      default: return 'Quality Issue'
    }
  }
  
  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'destructive'
      case 'HIGH': return 'bg-orange-500 hover:bg-orange-600'
      case 'MEDIUM': return 'bg-yellow-500 hover:bg-yellow-600 text-black'
      case 'LOW': return 'bg-blue-500 hover:bg-blue-600'
      default: return 'secondary'
    }
  }

  // If there's only one quality issue, render it directly without accordion
  if (qualityIssues.length === 1) {
    const singleIssue = qualityIssues[0]
    return (
      <div className="space-y-4">
        {singleIssue.type === 'scorecard' ? (
          <QualityDetailsView details={singleIssue.details} />
        ) : singleIssue.type === 'maintainer_risk' ? (
          <MaintainerRiskDetailsView details={singleIssue.details} />
        ) : (
          <AdditionalDetailsView details={singleIssue.details} />
        )}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Summary Header - only show when multiple issues */}
      <div className="flex items-center gap-4 p-4 bg-muted/50 rounded-lg border">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-medium">
              {`${issueCount} Quality Issues`}
            </h4>
            {hasMaintenanceIssues && (
              <Badge variant="destructive" className="text-xs">
                Maintenance Concerns
              </Badge>
            )}
          </div>
          {overallScore !== undefined && (
            <p className="text-sm text-muted-foreground">
              OpenSSF Scorecard: <span className={overallScore >= 7 ? 'text-green-600' : overallScore >= 5 ? 'text-yellow-600' : 'text-red-600'}>{overallScore.toFixed(1)}/10</span>
            </p>
          )}
        </div>
      </div>
      
      {/* Individual Quality Issues */}
      <div className="space-y-2">
        {qualityIssues.map((issue, idx) => {
          const isExpanded = expandedIssues.has(issue.id)
          const Icon = getIssueIcon(issue.type)
          
          return (
            <div key={issue.id || idx} className="border rounded-lg overflow-hidden">
              {/* Issue Header - Clickable */}
              <button
                onClick={() => toggleIssue(issue.id)}
                className="w-full flex items-center gap-3 p-3 bg-muted/30 hover:bg-muted/50 transition-colors text-left"
              >
                <Icon className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm">{getIssueLabel(issue.type)}</span>
                    <Badge className={getSeverityColor(issue.severity)}>
                      {issue.severity}
                    </Badge>
                    {issue.scanners && issue.scanners.length > 0 && (
                      <Badge variant="outline" className="text-xs">
                        {issue.scanners.join(', ')}
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground truncate">{issue.description}</p>
                </div>
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                )}
              </button>
              
              {/* Expanded Details */}
              {isExpanded && (
                <div className="p-4 border-t bg-background">
                  {issue.type === 'scorecard' ? (
                    <QualityDetailsView details={issue.details} />
                  ) : issue.type === 'maintainer_risk' ? (
                    <MaintainerRiskDetailsView details={issue.details} />
                  ) : (
                    <AdditionalDetailsView details={issue.details} />
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// License category display configuration
const LICENSE_CATEGORY_CONFIG: Record<string, { label: string; color: string; bgColor: string; icon: React.ElementType; description: string }> = {
  permissive: {
    label: 'Permissive',
    color: 'text-green-600',
    bgColor: 'bg-green-50 border-green-200',
    icon: CheckCircle2,
    description: 'No restrictions on commercial use'
  },
  public_domain: {
    label: 'Public Domain',
    color: 'text-green-600',
    bgColor: 'bg-green-50 border-green-200',
    icon: CheckCircle2,
    description: 'No restrictions whatsoever'
  },
  weak_copyleft: {
    label: 'Weak Copyleft',
    color: 'text-blue-600',
    bgColor: 'bg-blue-50 border-blue-200',
    icon: Info,
    description: 'Modifications to library must be shared'
  },
  strong_copyleft: {
    label: 'Strong Copyleft',
    color: 'text-orange-600',
    bgColor: 'bg-orange-50 border-orange-200',
    icon: AlertTriangle,
    description: 'Entire work must be open-sourced if distributed'
  },
  network_copyleft: {
    label: 'Network Copyleft',
    color: 'text-red-600',
    bgColor: 'bg-red-50 border-red-200',
    icon: XCircle,
    description: 'Source disclosure triggered by network access'
  },
  proprietary: {
    label: 'Proprietary',
    color: 'text-red-600',
    bgColor: 'bg-red-50 border-red-200',
    icon: XCircle,
    description: 'May have commercial restrictions'
  },
  unknown: {
    label: 'Unknown',
    color: 'text-gray-600',
    bgColor: 'bg-gray-50 border-gray-200',
    icon: AlertTriangle,
    description: 'License not recognized - manual review needed'
  }
}

// Component for rendering license compliance details
function LicenseDetailsView({ details }: { details: Record<string, unknown> }) {
  const license = (details.license as string) || 'Unknown'
  const licenseUrl = details.license_url as string | undefined
  const category = (details.category as string) || 'unknown'
  const explanation = details.explanation as string | undefined
  const recommendation = details.recommendation as string | undefined
  const obligations = (details.obligations as string[]) || []
  const risks = (details.risks as string[]) || []
  
  const categoryConfig = LICENSE_CATEGORY_CONFIG[category] || LICENSE_CATEGORY_CONFIG.unknown
  const CategoryIcon = categoryConfig.icon

  return (
    <div className="space-y-4">
      {/* License & Category Header */}
      <div className="flex items-start gap-4 p-4 rounded-lg border bg-muted/30">
        <Scale className="h-8 w-8 text-muted-foreground flex-shrink-0" />
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-lg font-semibold">{license}</span>
            {licenseUrl && (
              <a 
                href={licenseUrl} 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-primary hover:underline flex items-center gap-1 text-sm"
              >
                <ExternalLink className="h-3 w-3" />
                View License
              </a>
            )}
          </div>
          <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-md text-sm font-medium border ${categoryConfig.bgColor}`}>
            <CategoryIcon className={`h-4 w-4 ${categoryConfig.color}`} />
            <span className={categoryConfig.color}>{categoryConfig.label}</span>
          </div>
          <p className="text-sm text-muted-foreground mt-2">{categoryConfig.description}</p>
        </div>
      </div>

      {/* Explanation */}
      {explanation && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-muted-foreground" />
            What This Means
          </h4>
          <div className="p-4 rounded-lg border bg-muted/30">
            <p className="text-sm leading-relaxed whitespace-pre-wrap">{explanation}</p>
          </div>
        </div>
      )}

      {/* Recommendation */}
      {recommendation && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium flex items-center gap-2">
            <Lightbulb className="h-4 w-4 text-amber-500" />
            Recommendation
          </h4>
          <div className="p-4 rounded-lg border border-amber-200 bg-amber-50/50">
            <p className="text-sm leading-relaxed whitespace-pre-wrap">{recommendation}</p>
          </div>
        </div>
      )}

      {/* Obligations & Risks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Obligations */}
        {obligations.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-blue-500" />
              Obligations ({obligations.length})
            </h4>
            <div className="p-3 rounded-lg border bg-blue-50/50 space-y-2">
              {obligations.map((obligation, idx) => (
                <div key={idx} className="flex items-start gap-2 text-sm">
                  <span className="text-blue-500 mt-0.5">•</span>
                  <span>{obligation}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Risks */}
        {risks.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              Risks ({risks.length})
            </h4>
            <div className="p-3 rounded-lg border border-red-200 bg-red-50/50 space-y-2">
              {risks.map((risk, idx) => (
                <div key={idx} className="flex items-start gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
                  <span>{risk}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

const getFindingTitle = (f: Finding) => f.id || "Finding Details";
const getFindingPackage = (f: Finding) => f.component || "Unknown";
const getFindingVersion = (f: Finding) => f.version || "Unknown";
const getFindingId = (f: Finding) => f.id;

// Copyable code block component
function CopyableCode({ value, className = "" }: { value: string, className?: string }) {
  const [copied, setCopied] = useState(false)
  
  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  
  return (
    <div className={`flex items-start gap-2 ${className}`}>
      <code className="flex-1 px-2 py-1 bg-background rounded text-xs font-mono break-all">
        {value}
      </code>
      <Button 
        variant="ghost" 
        size="icon" 
        className="h-6 w-6 flex-shrink-0"
        onClick={handleCopy}
      >
        {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
      </Button>
    </div>
  )
}

// Origin badge with expandable details
function OriginBadge({ finding }: { finding: Finding }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const sourceInfo = getSourceInfo(finding.source_type)
  
  if (!sourceInfo && !finding.purl && finding.direct === undefined) {
    return null
  }
  
  const IconComponent = sourceInfo?.icon || Container
  const label = sourceInfo?.label || "Package"
  const color = sourceInfo?.color || "text-muted-foreground"
  const bgColor = sourceInfo?.bgColor || "bg-muted"
  
  return (
    <>
      <Badge
        variant="outline"
        className={`cursor-pointer hover:bg-opacity-80 transition-colors ${bgColor}`}
        onClick={(e) => {
          e.preventDefault()
          e.stopPropagation()
          setIsExpanded(!isExpanded)
        }}
      >
        <IconComponent className={`h-3 w-3 mr-1 ${color}`} />
        <span>{label}</span>
        {isExpanded ? (
          <ChevronDown className="h-3 w-3 ml-1" />
        ) : (
          <ChevronRight className="h-3 w-3 ml-1" />
        )}
      </Badge>
      
      {isExpanded && (
        <div className="w-full mt-2 p-3 border rounded-lg bg-muted/30 space-y-3 text-sm">
          {finding.direct !== undefined && (
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Dependency Type:</span>
              <Badge variant={finding.direct ? "default" : "secondary"}>
                {finding.direct ? "Direct" : "Transitive"}
              </Badge>
            </div>
          )}
          
          {finding.source_target && (
            <div>
              <span className="text-muted-foreground block mb-1">Source:</span>
              <CopyableCode value={finding.source_target} />
            </div>
          )}
          
          {finding.layer_digest && (
            <div>
              <span className="text-muted-foreground block mb-1">Container Layer:</span>
              <CopyableCode value={finding.layer_digest} />
            </div>
          )}
          
          {finding.purl && (
            <div>
              <span className="text-muted-foreground block mb-1">Package URL (PURL):</span>
              <CopyableCode value={finding.purl} />
            </div>
          )}
          
          {finding.locations && finding.locations.length > 0 && (
            <div>
              <span className="text-muted-foreground block mb-1">File Locations ({finding.locations.length}):</span>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {finding.locations.map((loc, i) => (
                  <code key={i} className="block px-2 py-0.5 bg-background rounded text-xs font-mono break-all">
                    {loc}
                  </code>
                ))}
              </div>
            </div>
          )}
          
          {finding.found_by && (
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Found By:</span>
              <Badge variant="outline" className="text-xs">
                {finding.found_by}
              </Badge>
            </div>
          )}
        </div>
      )}
    </>
  )
}

interface FindingDetailsModalProps {
    finding: Finding | null
    isOpen: boolean
    onClose: () => void
    projectId: string
    scanId?: string
    onSelectFinding?: (id: string) => void
    onNavigate?: () => void  // Called before navigation to allow parent cleanup
}

export function FindingDetailsModal({ finding, isOpen, onClose, projectId, scanId, onSelectFinding, onNavigate }: FindingDetailsModalProps) {
    const [showWaiverForm, setShowWaiverForm] = useState(false)
    const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null)
    const { hasPermission } = useAuth()
    const navigate = useNavigate()
    
    if (!finding) return null

    const handleWaive = (vulnId?: string) => {
        setSelectedVulnId(vulnId || null)
        setShowWaiverForm(true)
    }
    
    // Navigate to Raw tab with SBOM anchor
    const handleSbomClick = (source: string) => {
        if (!scanId) return
        // Extract SBOM index from source name (e.g., "SBOM #1" -> 0)
        const match = source.match(/SBOM #(\d+)/i)
        const sbomIndex = match ? parseInt(match[1], 10) - 1 : 0
        // Close this modal and notify parent to close as well
        onClose()
        onNavigate?.()  // Allow parent modals to close
        navigate(`/projects/${projectId}/scans/${scanId}?tab=raw&sbom=${sbomIndex}`)
    }

    return (
        <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
            <DialogContent className="max-w-3xl max-h-[90vh] flex flex-col">
                <DialogHeader className="pb-2">
                    <DialogTitle className="flex items-center gap-2 leading-normal">
                        {finding.severity && (
                            <Badge variant={
                                finding.severity === 'CRITICAL' ? 'destructive' :
                                finding.severity === 'HIGH' ? 'destructive' :
                                finding.severity === 'MEDIUM' ? 'default' : 
                                finding.severity === 'LOW' ? 'secondary' :
                                'outline'
                            }>
                                {finding.severity}
                            </Badge>
                        )}
                        <span className="truncate leading-normal">{getFindingTitle(finding)}</span>
                    </DialogTitle>
                    <DialogDescription>
                        {finding.type} detected in {getFindingPackage(finding)}
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto pr-4">
                    {showWaiverForm ? (
                        <WaiverForm 
                            finding={finding} 
                            vulnId={selectedVulnId}
                            projectId={projectId} 
                            onCancel={() => setShowWaiverForm(false)} 
                            onSuccess={() => {
                                setShowWaiverForm(false)
                                onClose()
                            }}
                        />
                    ) : (
                        <div className="space-y-6 py-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Component</h4>
                                    <p className="font-medium">{getFindingPackage(finding)}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Version</h4>
                                    <p className="font-medium">{getFindingVersion(finding)}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Fixed Version</h4>
                                    <p className="font-medium text-green-600">{finding.details?.fixed_version || "None"}</p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-1">ID</h4>
                                    <p className="font-mono text-sm">{getFindingId(finding)}</p>
                                </div>
                                {finding.scanners && finding.scanners.length > 0 && (
                                    <div className="col-span-2">
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Detected By</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {finding.scanners.map((scanner) => (
                                                <Badge key={scanner} variant="outline" className="font-mono text-xs">
                                                    {scanner}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {finding.found_in && finding.found_in.length > 0 && (
                                    <div className="col-span-2">
                                        <h4 className="text-sm font-medium text-muted-foreground mb-2">Found In Sources</h4>
                                        <div className="flex flex-wrap gap-2 items-start">
                                            {finding.found_in.map((source) => {
                                                // Check if this looks like an SBOM reference
                                                const isSbomRef = source.match(/SBOM #\d+/i) || !source.includes('/')
                                                return (
                                                    <Badge 
                                                        key={source} 
                                                        variant="secondary" 
                                                        className={`font-mono text-xs ${scanId && isSbomRef ? 'cursor-pointer hover:bg-primary/20 transition-colors' : ''}`}
                                                        onClick={scanId && isSbomRef ? (e) => {
                                                            e.preventDefault()
                                                            e.stopPropagation()
                                                            handleSbomClick(source)
                                                        } : undefined}
                                                    >
                                                        {source}
                                                        {scanId && isSbomRef && <ExternalLink className="h-3 w-3 ml-1" />}
                                                    </Badge>
                                                )
                                            })}
                                            {/* Origin Badge inline with SBOM badges */}
                                            {finding.source_type && (
                                                <OriginBadge finding={finding} />
                                            )}
                                        </div>
                                    </div>
                                )}
                                {/* Origin Badge for findings without found_in */}
                                {(!finding.found_in || finding.found_in.length === 0) && finding.source_type && (
                                    <div className="col-span-2">
                                        <OriginBadge finding={finding} />
                                    </div>
                                )}
                                {finding.related_findings && finding.related_findings.length > 0 && (
                                    <div className="col-span-2">
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Related Findings</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {finding.related_findings.map((relatedId) => {
                                                // Format the label nicely
                                                let label = relatedId;
                                                // Handle component:version format (e.g., "requests:2.28.0")
                                                if (relatedId.includes(":") && !relatedId.startsWith("AGG:") && !relatedId.startsWith("OUTDATED") && !relatedId.startsWith("QUALITY")) {
                                                    const parts = relatedId.split(":");
                                                    if (parts.length === 2) {
                                                        label = `${parts[0]} (${parts[1]})`;
                                                    }
                                                }
                                                // Handle legacy AGG:VULN: format if still present
                                                if (relatedId.startsWith("AGG:VULN:")) {
                                                    const parts = relatedId.split(":");
                                                    if (parts.length >= 4) {
                                                        label = `${parts[2]} (${parts[3]})`;
                                                    }
                                                }
                                                // Determine badge color based on type
                                                const isVulnerability = !relatedId.startsWith("OUTDATED") && !relatedId.startsWith("QUALITY");
                                                const badgeClass = isVulnerability 
                                                    ? "font-mono text-xs border-red-200 bg-red-50 text-red-700 cursor-pointer hover:bg-red-100"
                                                    : "font-mono text-xs border-blue-200 bg-blue-50 text-blue-700 cursor-pointer hover:bg-blue-100";
                                                return (
                                                    <Badge 
                                                        key={relatedId} 
                                                        variant="outline" 
                                                        className={badgeClass}
                                                        onClick={() => onSelectFinding?.(relatedId)}
                                                    >
                                                        {label}
                                                    </Badge>
                                                );
                                            })}
                                        </div>
                                        <p className="text-xs text-muted-foreground mt-1">
                                            These components share the exact same version and set of vulnerabilities.
                                        </p>
                                    </div>
                                )}
                            </div>

                            {finding.description && finding.type !== 'vulnerability' && (
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Description</h4>
                                    <p className="text-sm leading-relaxed">{finding.description}</p>
                                </div>
                            )}

                            {finding.type === 'secret' && (
                                <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                                    <div>
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Detector</h4>
                                        <p className="font-medium">{finding.details?.detector || "Unknown"}</p>
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-medium text-muted-foreground mb-1">Verified</h4>
                                        <Badge variant={finding.details?.verified ? "destructive" : "secondary"}>
                                            {finding.details?.verified ? "Verified Live" : "Unverified"}
                                        </Badge>
                                    </div>
                                    {finding.details?.redacted && (
                                        <div className="col-span-2">
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Redacted Secret</h4>
                                            <code className="bg-background p-2 rounded border block w-full font-mono text-sm break-all">
                                                {finding.details.redacted}
                                            </code>
                                        </div>
                                    )}
                                </div>
                            )}

                            {finding.type === 'sast' && (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Rule ID</h4>
                                            <p className="font-mono text-sm">{finding.details?.check_id || "Unknown"}</p>
                                        </div>
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Location</h4>
                                            <p className="text-sm">
                                                Line {finding.details?.start?.line || "?"} - {finding.details?.end?.line || "?"}
                                            </p>
                                        </div>
                                    </div>
                                    {finding.details?.metadata && (
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-2">Rule Metadata</h4>
                                            <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs">
                                                {JSON.stringify(finding.details.metadata, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                </div>
                            )}

                            {finding.type === 'vulnerability' && (
                                <div className="space-y-4">
                                    {(() => {
                                        // Normalize to a list of vulnerabilities
                                        const vulns = finding.details?.vulnerabilities && finding.details.vulnerabilities.length > 0 
                                            ? finding.details.vulnerabilities 
                                            : [finding.details || {}]; // Fallback for legacy or single vuln structure

                                        return (
                                            <div className="space-y-4">
                                                <h4 className="text-sm font-medium text-muted-foreground">
                                                    {vulns.length > 1 
                                                        ? `Found ${vulns.length} vulnerabilities in ${getFindingPackage(finding)}` 
                                                        : "Vulnerability Details"}
                                                </h4>
                                                
                                                {/* Show outdated info if this package is also flagged as outdated */}
                                                {finding.details?.outdated_info?.is_outdated && (
                                                    <div className="flex items-center gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                                                        <Clock className="h-4 w-4 text-amber-500 flex-shrink-0" />
                                                        <div className="text-sm">
                                                            <span className="font-medium text-amber-600 dark:text-amber-400">Outdated Package: </span>
                                                            <span className="text-muted-foreground">
                                                                Current version <span className="font-mono font-medium text-foreground">{finding.details.outdated_info.current_version}</span>
                                                                {finding.details.outdated_info.latest_version && (
                                                                    <> → Latest <span className="font-mono font-medium text-foreground">{finding.details.outdated_info.latest_version}</span></>
                                                                )}
                                                            </span>
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {vulns.map((vuln: any, idx: number) => (
                                                    <div key={idx} className="border rounded-lg p-4 space-y-3">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <Badge variant="outline">{vuln.id || getFindingId(finding)}</Badge>
                                                                <Badge variant={
                                                                    (vuln.severity || finding.severity) === 'CRITICAL' ? 'destructive' :
                                                                    (vuln.severity || finding.severity) === 'HIGH' ? 'destructive' :
                                                                    (vuln.severity || finding.severity) === 'MEDIUM' ? 'default' : 
                                                                    'secondary'
                                                                }>{vuln.severity || finding.severity}</Badge>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-xs text-muted-foreground">
                                                                    Fixed in: <span className="font-medium text-foreground">{vuln.fixed_version || finding.details?.fixed_version || "None"}</span>
                                                                </span>
                                                                {hasPermission('waiver:manage') && (
                                                                    <Button variant="ghost" size="sm" className="h-6 px-2" onClick={() => handleWaive(vuln.id || getFindingId(finding))}>
                                                                        <ShieldAlert className="h-3 w-3 mr-1" />
                                                                        Waive
                                                                    </Button>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                                                            {vuln.description || (finding.details?.vulnerabilities ? "" : finding.description) || "No description available."}
                                                        </p>
                                                        
                                                        <div className="flex flex-wrap gap-4 text-xs">
                                                            {(vuln.cvss_score || finding.details?.cvss_score) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium">CVSS: {vuln.cvss_score || finding.details?.cvss_score}</span>
                                                                    {(vuln.cvss_vector || finding.details?.cvss_vector) && <span className="font-mono text-muted-foreground">{vuln.cvss_vector || finding.details?.cvss_vector}</span>}
                                                                </div>
                                                            )}
                                                            {(vuln.epss_score !== undefined || finding.details?.epss_score !== undefined) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className={`font-medium ${
                                                                        (vuln.epss_score || finding.details?.epss_score) >= 0.1 ? 'text-red-500' :
                                                                        (vuln.epss_score || finding.details?.epss_score) >= 0.01 ? 'text-orange-500' : ''
                                                                    }`}>
                                                                        EPSS: {((vuln.epss_score || finding.details?.epss_score) * 100).toFixed(2)}%
                                                                    </span>
                                                                    {(vuln.epss_percentile || finding.details?.epss_percentile) && (
                                                                        <span className="text-muted-foreground">(Top {(100 - (vuln.epss_percentile || finding.details?.epss_percentile) * 100).toFixed(0)}%)</span>
                                                                    )}
                                                                    {(vuln.epss_date || finding.details?.epss_date) && (
                                                                        <span className="text-muted-foreground text-[10px]">as of {new Date(vuln.epss_date || finding.details?.epss_date).toLocaleDateString()}</span>
                                                                    )}
                                                                </div>
                                                            )}
                                                            {(vuln.in_kev || finding.details?.in_kev) && (
                                                                <div className="flex items-center gap-1 px-2 py-0.5 bg-red-500/10 text-red-600 rounded-md flex-wrap">
                                                                    <AlertTriangle className="h-3 w-3" />
                                                                    <span className="font-medium">Known Exploited</span>
                                                                    {(vuln.kev_ransomware_use || finding.details?.kev_ransomware_use) && (
                                                                        <Badge variant="destructive" className="text-[10px] py-0 h-4">Ransomware</Badge>
                                                                    )}
                                                                    {(vuln.kev_date_added || finding.details?.kev_date_added) && (
                                                                        <span className="text-muted-foreground text-[10px] ml-1">
                                                                            (since {new Date(vuln.kev_date_added || finding.details?.kev_date_added).toLocaleDateString()})
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            )}
                                                            {(vuln.kev_required_action || finding.details?.kev_required_action) && (
                                                                <div className="flex items-center gap-2 w-full">
                                                                    <span className="font-medium text-muted-foreground">Required Action:</span>
                                                                    <span className="text-red-600">{vuln.kev_required_action || finding.details?.kev_required_action}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.exploit_maturity || finding.details?.exploit_maturity) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Exploit:</span>
                                                                    <span className={`${
                                                                        (vuln.exploit_maturity || finding.details?.exploit_maturity) === 'high' ? 'text-red-500 font-medium' :
                                                                        (vuln.exploit_maturity || finding.details?.exploit_maturity) === 'functional' ? 'text-orange-500' :
                                                                        (vuln.exploit_maturity || finding.details?.exploit_maturity) === 'poc' ? 'text-yellow-600' : ''
                                                                    }`}>{vuln.exploit_maturity || finding.details?.exploit_maturity}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.details?.published_date || finding.details?.published_date) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Published:</span>
                                                                    <span>{new Date(vuln.details?.published_date ?? finding.details?.published_date ?? '').toLocaleDateString()}</span>
                                                                </div>
                                                            )}
                                                            {((vuln.details?.cwe_ids ?? finding.details?.cwe_ids)?.length ?? 0) > 0 && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">CWE:</span>
                                                                    <span className="font-mono">{(vuln.details?.cwe_ids ?? finding.details?.cwe_ids ?? []).join(', ')}</span>
                                                                </div>
                                                            )}
                                                            {((vuln.aliases ?? finding.aliases)?.length ?? 0) > 0 && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Aliases:</span>
                                                                    <span className="font-mono">{(vuln.aliases ?? finding.aliases ?? []).join(', ')}</span>
                                                                </div>
                                                            )}
                                                            {(vuln.scanners || finding.scanners) && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="font-medium text-muted-foreground">Detected by:</span>
                                                                    <span className="font-mono">{(vuln.scanners || finding.scanners).join(', ')}</span>
                                                                </div>
                                                            )}
                                                        </div>

                                                        <CollapsibleReferences references={vuln.references || finding.details?.references} />
                                                        <CollapsibleReferences references={vuln.details?.urls || finding.details?.urls} title="URLs" />
                                                    </div>
                                                ))}
                                            </div>
                                        );
                                    })()}
                                    
                                    {/* Show Scorecard context if available */}
                                    {finding.details?.scorecard_context && (
                                        <ScorecardContextBanner context={finding.details.scorecard_context as ScorecardContext} />
                                    )}
                                    
                                    {/* Show maintenance warning */}
                                    {finding.details?.maintenance_warning && (
                                        <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-amber-800">
                                            <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                                            <p className="text-sm">
                                                {finding.details.maintenance_warning_text || "This package may have maintenance concerns."}
                                            </p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* License Compliance findings */}
                            {finding.type === 'license' && finding.details && (
                                <LicenseDetailsView details={finding.details} />
                            )}

                            {/* Quality findings (aggregated: quality_issues list) */}
                            {finding.type === 'quality' && finding.details && (
                                <AggregatedQualityView details={finding.details} />
                            )}

                            {/* Legacy 'other' type with maintainer_risk data */}
                            {finding.type === 'other' && finding.details?.risks && finding.details?.maintainer_info && (
                                <MaintainerRiskDetailsView details={finding.details} />
                            )}

                            {finding.details && finding.type !== 'secret' && finding.type !== 'sast' && finding.type !== 'vulnerability' && finding.type !== 'outdated' && finding.type !== 'quality' && finding.type !== 'license' && !(finding.type === 'other' && finding.details?.risks && finding.details?.maintainer_info) && (
                                <div>
                                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Additional Details</h4>
                                    <AdditionalDetailsView details={finding.details} />
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {!showWaiverForm && (
                    <DialogFooter className="gap-2 sm:gap-0">
                        {hasPermission('waiver:manage') && (
                            <Button variant="outline" onClick={() => setShowWaiverForm(true)}>
                                <ShieldAlert className="mr-2 h-4 w-4" />
                                Create Waiver
                            </Button>
                        )}
                        <Button onClick={onClose}>Close</Button>
                    </DialogFooter>
                )}
            </DialogContent>
        </Dialog>
    )
}

function WaiverForm({ finding, vulnId, projectId, onCancel, onSuccess }: { finding: Finding, vulnId: string | null, projectId: string, onCancel: () => void, onSuccess: () => void }) {
    const [reason, setReason] = useState("")
    const [date, setDate] = useState("")
    const queryClient = useQueryClient()

    const createWaiverMutation = useMutation({
        mutationFn: createWaiver,
        onSuccess: () => {
            toast.success("Waiver created successfully")
            queryClient.invalidateQueries({ queryKey: ['waivers', projectId] })
            onSuccess()
        },
        onError: (error: AxiosError<any>) => {
            toast.error("Failed to create waiver", {
                description: error.response?.data?.detail || "An error occurred"
            })
        }
    })

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        if (!reason) return

        // If waiving a specific vulnerability, we might need to adjust the finding_id or pass extra data
        // For now, we assume the backend can handle the specific ID if we pass it, 
        // OR we are waiving the whole package but noting the specific vuln in the reason.
        // Ideally, the backend API should support a 'vulnerability_id' field.
        // Since we can't change the backend right now, we'll append it to the reason or use it as ID if appropriate.
        
        // Strategy: If vulnId is present, we use it as the finding_id for the waiver? 
        // No, finding_id links to the finding record. 
        // If the backend matches waivers by finding_id string, and we want to waive just one CVE,
        // we might need to change the backend. 
        // BUT, if we assume the user wants to waive THIS specific CVE, and the system uses CVEs as IDs usually...
        // Let's try passing the vulnId as finding_id if present, assuming the backend might check against it.
        // If not, we fall back to finding.id.
        
        // Actually, better approach for now without backend changes:
        // We waive the whole finding (Package) but auto-fill the reason with the specific CVE.
        
        const targetId = vulnId || getFindingId(finding)
        const finalReason = vulnId ? `[${vulnId}] ${reason}` : reason

        createWaiverMutation.mutate({
            project_id: projectId,
            finding_id: targetId, 
            package_name: getFindingPackage(finding),
            package_version: getFindingVersion(finding),
            finding_type: finding.type || "unknown",
            reason: finalReason,
            expiration_date: date ? new Date(date).toISOString() : undefined
        })
    }

    return (
        <form onSubmit={handleSubmit} className="space-y-4 py-4">
            {vulnId && (
                <div className="bg-blue-50 p-3 rounded-md border border-blue-100 text-sm text-blue-800 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4" />
                    Creating waiver specifically for <strong>{vulnId}</strong>
                </div>
            )}
            <div className="space-y-2">
                <Label>Reason for Waiver</Label>
                <textarea 
                    className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                    placeholder="Why is this finding being ignored? (e.g. False positive, Mitigating controls in place...)"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    required
                />
            </div>

            <div className="space-y-2 flex flex-col">
                <Label>Expiration Date (Optional)</Label>
                <Input 
                    type="date" 
                    value={date} 
                    onChange={(e) => setDate(e.target.value)} 
                    min={new Date().toISOString().split('T')[0]}
                />
                <p className="text-xs text-muted-foreground">
                    The waiver will automatically expire on this date.
                </p>
            </div>

            <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
                <Button type="submit" disabled={createWaiverMutation.isPending}>
                    {createWaiverMutation.isPending && <span className="mr-2">Saving...</span>}
                    Confirm Waiver
                </Button>
            </div>
        </form>
    )
}

function CollapsibleReferences({ references, title = "References" }: { references: string[], title?: string }) {
    const [isOpen, setIsOpen] = useState(false)

    if (!references || references.length === 0) return null

    return (
        <div className="pt-2">
            <Button 
                variant="ghost" 
                size="sm" 
                className="h-auto py-1 px-0 text-xs font-medium hover:bg-transparent hover:underline justify-start text-muted-foreground"
                onClick={() => setIsOpen(!isOpen)}
            >
                {isOpen ? "▼" : "▶"} {title} ({references.length})
            </Button>
            
            {isOpen && (
                <div className="flex flex-col gap-1 mt-1 pl-2 border-l-2 border-muted ml-1">
                    {references.map((ref, i) => (
                        <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline truncate block">
                            {ref}
                        </a>
                    ))}
                </div>
            )}
        </div>
    )
}
