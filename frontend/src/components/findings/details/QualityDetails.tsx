import { useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { AdditionalDetailsView } from '@/components/findings/details/AdditionalDetailsView'
import { DetailSection } from '@/components/findings/details/shared'
import type { FindingDetails } from '@/types/scan'
import {
  formatScorecardCriticalIssue,
  getScoreBorderColor,
  getScoreColor,
  getSeverityBgColor,
} from '@/lib/finding-utils'
import {
  Activity,
  AlertTriangle,
  Building,
  Calendar,
  ChevronDown,
  ChevronRight,
  Clock,
  ExternalLink,
  GitBranch,
  Lightbulb,
  Mail,
  Package,
  Shield,
  User,
} from 'lucide-react'

// Types for maintainer risk details
interface MaintainerRisk {
  type: string
  severity?: string
  severity_score?: number
  message?: string
  description?: string
  detail?: string
}

interface MaintainerInfo {
  author?: string | null
  author_email?: string | null
  maintainer?: string | null
  maintainer_email?: string | null
  latest_release_date?: string | null
  days_since_release?: number | null
  release_count?: number | null
  home_page?: string | null
  project_urls?: Record<string, string> | null
}

// Component for rendering quality findings (OpenSSF Scorecard details)
export function QualityDetailsView({ details }: { details: FindingDetails }) {
  const overallScore = details.overall_score as number
  const failedChecks = (details.failed_checks as Array<{ name: string; score: number }>) || []
  const criticalIssues = (details.critical_issues as string[]) || []
  const repository = details.repository as string
  const recommendation = details.recommendation as string
  const checksSummary = details.checks_summary as Record<string, number>

  // Only show scorecard section if we have a valid score
  const hasValidScore = overallScore !== undefined && overallScore !== null && !isNaN(overallScore)

  return (
    <div className="space-y-4">
      {/* Score Overview - only show if we have a valid score */}
      {hasValidScore && (
        <div className="flex items-center gap-4 p-4 bg-muted/50 rounded-lg border">
          <div
            className={`flex items-center justify-center w-16 h-16 rounded-full bg-muted/50 border-2 ${getScoreBorderColor(overallScore)}`}
          >
            <span className={`text-2xl font-bold tabular-nums ${getScoreColor(overallScore)}`}>
              {overallScore.toFixed(1)}
            </span>
          </div>
          <div className="flex-1">
            <h4 className="font-medium">OpenSSF Scorecard</h4>
            <p className="text-sm text-muted-foreground">
              {overallScore >= 7
                ? 'Good security practices'
                : overallScore >= 5
                  ? 'Moderate security practices - room for improvement'
                  : overallScore >= 3
                    ? 'Concerning security practices - review carefully'
                    : 'Poor security practices - high risk'}
            </p>
            {repository && (
              <a
                href={
                  repository.startsWith('http')
                    ? repository
                    : repository.includes('github.com')
                      ? `https://${repository}`
                      : `https://github.com/${repository}`
                }
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
        <DetailSection
          label="Critical Issues"
          icon={<AlertTriangle className="h-4 w-4 text-red-500" />}
        >
          <div className="flex flex-wrap gap-2">
            {criticalIssues.map((issue, idx) => (
              <Badge key={idx} variant="destructive" className="text-xs">
                {formatScorecardCriticalIssue(issue)}
              </Badge>
            ))}
          </div>
        </DetailSection>
      )}

      {/* Failed Checks */}
      {failedChecks.length > 0 && (
        <DetailSection label={`Failed Checks (${failedChecks.length})`}>
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
        </DetailSection>
      )}

      {/* All Checks Summary */}
      {checksSummary && Object.keys(checksSummary).length > 0 && (
        <DetailSection label="All Checks">
          <div className="grid grid-cols-3 gap-1 text-xs">
            {Object.entries(checksSummary)
              .sort((a, b) => a[1] - b[1])
              .map(([name, score]) => (
                <div key={name} className="flex items-center justify-between p-1.5 bg-muted/30 rounded">
                  <span className="truncate">{name}</span>
                  <span className={`font-mono ${getScoreColor(score)}`}>{score}</span>
                </div>
              ))}
          </div>
        </DetailSection>
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
              <span key={idx} className="block">
                • {rec}
              </span>
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
export function MaintainerRiskDetailsView({ details }: { details: FindingDetails }) {
  const risks = (details.risks as MaintainerRisk[]) || []
  const maintainerInfo = (details.maintainer_info as MaintainerInfo) || {}

  const getRiskIcon = (type: string) => {
    switch (type) {
      case 'stale_package':
        return Clock
      case 'infrequent_updates':
        return Activity
      case 'free_email_maintainer':
        return Mail
      case 'single_maintainer':
        return User
      case 'archived_repo':
        return GitBranch
      default:
        return AlertTriangle
    }
  }

  const getRiskBadgeVariant = (score: number): 'destructive' | 'default' | 'secondary' => {
    if (score >= 3) return 'destructive'
    if (score >= 2) return 'default'
    return 'secondary'
  }

  const formatRiskType = (type: string) => {
    return type
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  return (
    <div className="space-y-4">
      {/* Risk Factors */}
      {risks.length > 0 && (
        <DetailSection label={`Risk Factors (${risks.length})`}>
          <div className="space-y-2">
            {risks.map((risk, idx) => {
              const Icon = getRiskIcon(risk.type)
              const severityScore = risk.severity_score ?? 1
              const riskMessage = risk.message || risk.description || ''
              return (
                <div key={idx} className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg border">
                  <Icon className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm">{formatRiskType(risk.type)}</span>
                      <Badge variant={getRiskBadgeVariant(severityScore)} className="text-xs">
                        Score: {severityScore}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{riskMessage}</p>
                    {risk.detail && <p className="text-xs text-muted-foreground mt-1 italic">{risk.detail}</p>}
                  </div>
                </div>
              )
            })}
          </div>
        </DetailSection>
      )}

      {/* Maintainer Info */}
      {Object.keys(maintainerInfo).length > 0 && (
        <DetailSection label="Maintainer Information">
          <div className="bg-muted/50 rounded-lg p-4 border space-y-3">
            <div className="grid grid-cols-2 gap-4">
              {/* Author */}
              {(maintainerInfo.author || maintainerInfo.author_email) && (
                <div className="flex items-start gap-2">
                  <User className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Author</p>
                    <p className="text-sm font-medium">{maintainerInfo.author || 'Unknown'}</p>
                    {maintainerInfo.author_email && <p className="text-xs text-muted-foreground">{maintainerInfo.author_email}</p>}
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
                    <p className="text-sm font-medium">{new Date(maintainerInfo.latest_release_date!).toLocaleDateString()}</p>
                    {maintainerInfo.days_since_release && (
                      <p className="text-xs text-muted-foreground">{maintainerInfo.days_since_release} days ago</p>
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
                  {maintainerInfo.project_urls &&
                    Object.entries(maintainerInfo.project_urls).map(([name, url]) =>
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
                    )}
                </div>
              </div>
            )}
          </div>
        </DetailSection>
      )}
    </div>
  )
}

// Interface for quality issue entry (from aggregated quality findings)
interface QualityIssueEntry {
  id: string
  type: string
  severity: string
  description: string
  scanners: string[]
  source?: string
  details: Record<string, unknown>
}

// Component for rendering aggregated quality findings (similar to vulnerabilities)
export function AggregatedQualityView({ details }: { details: FindingDetails }) {
  const qualityIssues = (details.quality_issues as QualityIssueEntry[]) || []
  const overallScore = details.overall_score as number | undefined
  const hasMaintenanceIssues = details.has_maintenance_issues as boolean
  const issueCount = (details.issue_count as number) || qualityIssues.length
  const [expandedIssues, setExpandedIssues] = useState<Set<string>>(new Set())

  // Helper to check for valid scorecard score
  const hasValidScorecardScore = (d: Record<string, unknown>) => {
    const score = d.overall_score as number | undefined
    return score !== undefined && score !== null && !isNaN(score)
  }

  // Legacy support: if no quality_issues array, check for old structure
  if (qualityIssues.length === 0) {
    // Check for legacy scorecard structure - only if we have a valid score
    const scorecardDetails = (details.scorecard as Record<string, unknown>) || details
    if (hasValidScorecardScore(scorecardDetails)) {
      return <QualityDetailsView details={scorecardDetails as unknown as FindingDetails} />
    }
    // Check for legacy maintainer_risk structure
    if (details.risks || details.maintainer_risk) {
      const maintDetails = (details.maintainer_risk as Record<string, unknown>) || details
      return <MaintainerRiskDetailsView details={maintDetails as unknown as FindingDetails} />
    }
    return null
  }

  const toggleIssue = (id: string) => {
    setExpandedIssues((prev) => {
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
      case 'scorecard':
        return Shield
      case 'maintainer_risk':
        return Clock
      default:
        return AlertTriangle
    }
  }

  const getIssueLabel = (type: string) => {
    switch (type) {
      case 'scorecard':
        return 'OpenSSF Scorecard'
      case 'maintainer_risk':
        return 'Maintainer Risk'
      default:
        return 'Quality Issue'
    }
  }

  // If there's only one quality issue, render it directly without accordion
  if (qualityIssues.length === 1) {
    const singleIssue = qualityIssues[0]
    return (
      <div className="space-y-4">
        {singleIssue.type === 'scorecard' ? (
          <QualityDetailsView details={singleIssue.details as unknown as FindingDetails} />
        ) : singleIssue.type === 'maintainer_risk' ? (
          <MaintainerRiskDetailsView details={singleIssue.details as unknown as FindingDetails} />
        ) : (
          <AdditionalDetailsView details={singleIssue.details as unknown as FindingDetails} />
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
            <h4 className="font-medium">{`${issueCount} Quality Issues`}</h4>
            {hasMaintenanceIssues && (
              <Badge variant="destructive" className="text-xs">
                Maintenance Concerns
              </Badge>
            )}
          </div>
          {overallScore !== undefined && (
            <p className="text-sm text-muted-foreground">
              OpenSSF Scorecard:{' '}
              <span
                className={overallScore >= 7 ? 'text-green-600' : overallScore >= 5 ? 'text-yellow-600' : 'text-red-600'}
              >
                {overallScore.toFixed(1)}/10
              </span>
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
                    <Badge className={getSeverityBgColor(issue.severity)}>{issue.severity}</Badge>
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
                    <QualityDetailsView details={issue.details as unknown as FindingDetails} />
                  ) : issue.type === 'maintainer_risk' ? (
                    <MaintainerRiskDetailsView details={issue.details as unknown as FindingDetails} />
                  ) : (
                    <AdditionalDetailsView details={issue.details as unknown as FindingDetails} />
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
