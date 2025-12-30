import React from 'react'
import { Badge } from '@/components/ui/badge'
import { ContextBanner } from '@/components/findings/ContextBanner'
import type { Finding } from '@/lib/api'
import {
  Activity,
  Calendar,
  Clock,
  ExternalLink,
  Scale,
  ShieldAlert,
  Wrench,
} from 'lucide-react'

interface ContextBannersSectionProps {
  finding: Finding
}

export function ContextBannersSection({ finding }: ContextBannersSectionProps) {
  const banners: React.ReactNode[] = []

  // 1. Outdated Package Info
  if (finding.details?.outdated_info?.is_outdated) {
    const info = finding.details.outdated_info
    banners.push(
      <ContextBanner key="outdated" icon={Clock} title="Outdated Package" variant="warning">
        <span>
          Current version <span className="font-mono font-medium">{info.current_version}</span>
          {info.latest_version && (
            <>
              {' '}
              → Latest <span className="font-mono font-medium">{info.latest_version}</span>
            </>
          )}
        </span>
      </ContextBanner>
    )
  }

  // 2. Quality Issues
  if (finding.details?.quality_info?.has_quality_issues) {
    const info = finding.details.quality_info
    banners.push(
      <ContextBanner key="quality" icon={Activity} title="Quality Concerns" variant="warning">
        <span>
          {info.issue_count ? `${info.issue_count} quality issue(s) detected. ` : ''}
          {info.overall_score !== undefined && (
            <span>
              OpenSSF Score: <span className="font-medium">{info.overall_score.toFixed(1)}/10</span>
            </span>
          )}
          {info.has_maintenance_issues && (
            <span className="ml-2 text-amber-600 font-medium">• Maintenance concerns</span>
          )}
        </span>
      </ContextBanner>
    )
  }

  // 3. License Issues
  if (finding.details?.license_info?.has_license_issue) {
    const info = finding.details.license_info
    banners.push(
      <ContextBanner key="license" icon={Scale} title="License Issue" variant="info">
        <span>
          License: <span className="font-medium">{info.license || 'Unknown'}</span>
          {info.category && <span className="ml-2">({info.category})</span>}
        </span>
      </ContextBanner>
    )
  }

  // 4. End of Life
  if (finding.details?.eol_info?.is_eol) {
    const info = finding.details.eol_info
    banners.push(
      <ContextBanner key="eol" icon={Calendar} title="End of Life" variant="danger">
        <span>
          {info.cycle && (
            <span>
              Version cycle <span className="font-mono font-medium">{info.cycle}</span>{' '}
            </span>
          )}
          {info.eol_date && <span>reached EOL on {new Date(info.eol_date).toLocaleDateString()}</span>}
          {info.latest_version && (
            <span>
              . Consider upgrading to <span className="font-mono font-medium">{info.latest_version}</span>
            </span>
          )}
        </span>
      </ContextBanner>
    )
  }

  // 5. Vulnerability Info (when primary finding is NOT vulnerability)
  if (finding.type !== 'vulnerability' && finding.details?.vulnerability_info?.has_vulnerabilities) {
    const info = finding.details.vulnerability_info
    const criticalCount = info.critical_count ?? 0
    const highCount = info.high_count ?? 0
    banners.push(
      <ContextBanner key="vuln" icon={ShieldAlert} title="Has Vulnerabilities" variant="danger">
        <span>
          {info.vuln_count} known vulnerabilit{info.vuln_count === 1 ? 'y' : 'ies'}
          {(criticalCount > 0 || highCount > 0) && (
            <span className="ml-2">
              ({criticalCount > 0 && (
                <span className="text-red-600 font-medium">{criticalCount} Critical</span>
              )}
              {criticalCount > 0 && highCount > 0 && ', '}
              {highCount > 0 && <span className="text-orange-600 font-medium">{highCount} High</span>})
            </span>
          )}
        </span>
      </ContextBanner>
    )
  }

  // 6. OpenSSF Scorecard Context (for vulnerabilities)
  if (finding.details?.scorecard_context) {
    const ctx = finding.details.scorecard_context as {
      overall_score?: number
      maintenance_risk?: boolean
      has_vulnerabilities_issue?: boolean
      critical_issues?: string[]
      project_url?: string
    }

    const hasValidScore = ctx.overall_score !== undefined && ctx.overall_score !== null && !isNaN(ctx.overall_score)
    const isLowScore = hasValidScore && ctx.overall_score! < 5.0
    const isVeryLowScore = hasValidScore && ctx.overall_score! < 3.0

    if (hasValidScore || ctx.maintenance_risk || (ctx.critical_issues && ctx.critical_issues.length > 0)) {
      const variant = isVeryLowScore || ctx.maintenance_risk ? 'danger' : isLowScore ? 'warning' : 'info'
      banners.push(
        <ContextBanner
          key="scorecard"
          icon={Activity}
          title="OpenSSF Scorecard"
          variant={variant}
          action={
            ctx.project_url && (
              <a
                href={ctx.project_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs hover:underline flex items-center gap-1"
              >
                <ExternalLink className="h-3 w-3" />
                Details
              </a>
            )
          }
        >
          <div className="flex flex-wrap items-center gap-2">
            {hasValidScore && (
              <span
                className={`font-bold ${isVeryLowScore ? 'text-red-600' : isLowScore ? 'text-amber-600' : 'text-green-600'}`}
              >
                {ctx.overall_score!.toFixed(1)}/10
              </span>
            )}
            {ctx.maintenance_risk && (
              <Badge variant="outline" className="text-xs border-current">
                Potentially Unmaintained
              </Badge>
            )}
            {ctx.has_vulnerabilities_issue && (
              <Badge variant="outline" className="text-xs border-current">
                Has Open Vulnerabilities
              </Badge>
            )}
            {ctx.critical_issues &&
              ctx.critical_issues.length > 0 &&
              ctx.critical_issues.slice(0, 3).map((issue, idx) => (
                <Badge key={idx} variant="outline" className="text-xs border-current">
                  {issue}
                </Badge>
              ))}
          </div>
        </ContextBanner>
      )
    }
  }

  // 7. Maintenance Warning (legacy)
  if (finding.details?.maintenance_warning && !finding.details?.scorecard_context) {
    banners.push(
      <ContextBanner key="maintenance" icon={Wrench} title="Maintenance Warning" variant="warning">
        <span>{finding.details.maintenance_warning_text || 'This package may have maintenance concerns.'}</span>
      </ContextBanner>
    )
  }

  if (banners.length === 0) return null

  return <div className="space-y-2">{banners}</div>
}
