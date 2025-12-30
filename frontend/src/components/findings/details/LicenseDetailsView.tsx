import React from 'react'
import type { FindingDetails } from '@/lib/api'
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ExternalLink,
  Info,
  Lightbulb,
  Scale,
  XCircle,
} from 'lucide-react'

// License category display configuration
const LICENSE_CATEGORY_CONFIG: Record<
  string,
  {
    label: string
    color: string
    bgColor: string
    icon: React.ElementType
    description: string
  }
> = {
  permissive: {
    label: 'Permissive',
    color: 'text-green-600',
    bgColor: 'bg-green-50 border-green-200',
    icon: CheckCircle2,
    description: 'No restrictions on commercial use',
  },
  public_domain: {
    label: 'Public Domain',
    color: 'text-green-600',
    bgColor: 'bg-green-50 border-green-200',
    icon: CheckCircle2,
    description: 'No restrictions whatsoever',
  },
  weak_copyleft: {
    label: 'Weak Copyleft',
    color: 'text-blue-600',
    bgColor: 'bg-blue-50 border-blue-200',
    icon: Info,
    description: 'Modifications to library must be shared',
  },
  strong_copyleft: {
    label: 'Strong Copyleft',
    color: 'text-orange-600',
    bgColor: 'bg-orange-50 border-orange-200',
    icon: AlertTriangle,
    description: 'Entire work must be open-sourced if distributed',
  },
  network_copyleft: {
    label: 'Network Copyleft',
    color: 'text-red-600',
    bgColor: 'bg-red-50 border-red-200',
    icon: XCircle,
    description: 'Source disclosure triggered by network access',
  },
  proprietary: {
    label: 'Proprietary',
    color: 'text-red-600',
    bgColor: 'bg-red-50 border-red-200',
    icon: XCircle,
    description: 'May have commercial restrictions',
  },
  unknown: {
    label: 'Unknown',
    color: 'text-gray-600',
    bgColor: 'bg-gray-50 border-gray-200',
    icon: AlertTriangle,
    description: 'License not recognized - manual review needed',
  },
}

// Component for rendering license compliance details
export function LicenseDetailsView({ details }: { details: FindingDetails }) {
  const license = (details.license as string) || 'Unknown'
  const licenseUrl = details.license_url as string | undefined
  const category = (details.category as string) || 'unknown'
  const explanation = details.explanation as string | undefined
  const recommendation = details.recommendation as string | undefined
  const obligations = (details.obligations as string[]) || []
  const risks = (details.license_risks as string[]) || []

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
