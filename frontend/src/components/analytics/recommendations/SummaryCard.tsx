import { RecommendationsResponse } from '@/types/analytics'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  AlertTriangle,
  Lightbulb,
  ShieldAlert,
} from 'lucide-react'

export function SummaryCard({ data }: { data: RecommendationsResponse }) {
  const hasOtherFindings = (data.summary.secrets_to_rotate || 0) > 0 ||
    (data.summary.sast_issues || 0) > 0 ||
    (data.summary.iac_issues || 0) > 0 ||
    (data.summary.license_issues || 0) > 0;

  const totalSecurityFindings = (data.total_findings || data.total_vulnerabilities || 0) +
    (data.summary.secrets_to_rotate || 0) +
    (data.summary.sast_issues || 0) +
    (data.summary.iac_issues || 0);

  const totalInsights = (data.summary.outdated_deps || 0) +
    (data.summary.fragmentation_issues || 0) +
    (data.summary.trend_alerts || 0) +
    (data.summary.cross_project_issues || 0);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg">Recommendations Summary</CardTitle>
        <CardDescription>
          {totalSecurityFindings > 0
            ? `${totalSecurityFindings} security findings • ${totalInsights} dependency insights`
            : totalInsights > 0
              ? `${totalInsights} dependency insights found`
              : 'No significant issues found'
          }
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Vulnerability Summary - only show if there are vulnerabilities */}
        {(data.total_vulnerabilities || 0) > 0 && (
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              Vulnerabilities
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="text-center p-3 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-success">
                  {data.summary.total_fixable_vulns || 0}
                </div>
                <div className="text-xs text-muted-foreground">Fixable</div>
              </div>
              <div className="text-center p-3 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-gray-500">
                  {data.summary.total_unfixable_vulns || 0}
                </div>
                <div className="text-xs text-muted-foreground">No Fix</div>
              </div>
              <div className="text-center p-3 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-blue-500">
                  {data.summary.base_image_updates || 0}
                </div>
                <div className="text-xs text-muted-foreground">Image Updates</div>
              </div>
              <div className="text-center p-3 bg-muted rounded-lg">
                <div className="text-2xl font-bold text-purple-500">
                  {(data.summary.direct_updates || 0) + (data.summary.transitive_updates || 0)}
                </div>
                <div className="text-xs text-muted-foreground">Pkg Updates</div>
              </div>
            </div>
          </div>
        )}

        {/* Other Finding Types */}
        {hasOtherFindings && (
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Other Security Findings
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {(data.summary.secrets_to_rotate || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-destructive">
                    {data.summary.secrets_to_rotate}
                  </div>
                  <div className="text-xs text-muted-foreground">Secrets</div>
                </div>
              )}
              {(data.summary.sast_issues || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-cyan-500">
                    {data.summary.sast_issues}
                  </div>
                  <div className="text-xs text-muted-foreground">SAST Issues</div>
                </div>
              )}
              {(data.summary.iac_issues || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-indigo-500">
                    {data.summary.iac_issues}
                  </div>
                  <div className="text-xs text-muted-foreground">IAC Issues</div>
                </div>
              )}
              {(data.summary.license_issues || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-pink-500">
                    {data.summary.license_issues}
                  </div>
                  <div className="text-xs text-muted-foreground">License Issues</div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Dependency Health & Insights */}
        {((data.summary.outdated_deps || 0) > 0 ||
          (data.summary.fragmentation_issues || 0) > 0 ||
          (data.summary.trend_alerts || 0) > 0 ||
          (data.summary.cross_project_issues || 0) > 0) && (
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <Lightbulb className="h-4 w-4" />
              Health & Insights
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {(data.summary.outdated_deps || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-amber-600">
                    {data.summary.outdated_deps}
                  </div>
                  <div className="text-xs text-muted-foreground">Outdated</div>
                </div>
              )}
              {(data.summary.fragmentation_issues || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-violet-500">
                    {data.summary.fragmentation_issues}
                  </div>
                  <div className="text-xs text-muted-foreground">Fragmentation</div>
                </div>
              )}
              {(data.summary.trend_alerts || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-rose-500">
                    {data.summary.trend_alerts}
                  </div>
                  <div className="text-xs text-muted-foreground">Trend Alerts</div>
                </div>
              )}
              {(data.summary.cross_project_issues || 0) > 0 && (
                <div className="text-center p-3 bg-muted rounded-lg">
                  <div className="text-2xl font-bold text-sky-500">
                    {data.summary.cross_project_issues}
                  </div>
                  <div className="text-xs text-muted-foreground">Cross-Project</div>
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
