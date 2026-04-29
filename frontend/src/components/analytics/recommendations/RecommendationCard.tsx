import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Recommendation, CrossProjectCve } from '@/types/analytics'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  AlertTriangle,
  ArrowUpCircle,
  ChevronDown,
  ChevronRight,
  Clock,
  Code,
  Container,
  Copy,
  ExternalLink,
  FolderTree,
  GitBranch,
  Globe,
  Key,
  Layers,
  Lightbulb,
  Package,
  RefreshCw,
  Scale,
  Server,
  TrendingDown,
  TrendingUp,
  Zap,
} from 'lucide-react'
import { priorityConfig, typeConfig, effortConfig } from './config'

export function RecommendationCard({ recommendation }: { recommendation: Recommendation }) {
  const [expanded, setExpanded] = useState(false)

  const typeInfo = typeConfig[recommendation.type] || typeConfig.direct_dependency_update
  const priorityInfo = priorityConfig[recommendation.priority] || priorityConfig.medium
  const effortInfo = effortConfig[recommendation.effort] || effortConfig.medium
  const TypeIcon = typeInfo.icon

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <Card className="overflow-hidden">
      <button
        type="button"
        className="w-full text-left p-4 cursor-pointer hover:bg-muted/50 transition-colors"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-4">
          {/* Type Icon */}
          <div className={cn("p-2 rounded-lg", typeInfo.bgColor)}>
            <TypeIcon className={cn("h-5 w-5", typeInfo.color)} />
          </div>

          {/* Main Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold truncate">{recommendation.title}</h4>
              <Badge
                variant="outline"
                className={cn("shrink-0", priorityInfo.textColor)}
              >
                {priorityInfo.label}
              </Badge>
              <Badge variant="secondary" className="shrink-0">
                {typeInfo.label}
              </Badge>
            </div>

            <p className="text-sm text-muted-foreground line-clamp-2">
              {recommendation.description}
            </p>

            {/* Impact Summary */}
            <div className="flex items-center gap-4 mt-2">
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="flex items-center gap-1.5 text-sm">
                      <Zap className="h-4 w-4 text-yellow-500" />
                      <span className="font-medium">{recommendation.impact.total}</span>
                      <span className="text-muted-foreground">vulns fixed</span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <div className="space-y-1">
                      {recommendation.impact.critical > 0 && (
                        <div>Critical: {recommendation.impact.critical}</div>
                      )}
                      {recommendation.impact.high > 0 && (
                        <div>High: {recommendation.impact.high}</div>
                      )}
                      {recommendation.impact.medium > 0 && (
                        <div>Medium: {recommendation.impact.medium}</div>
                      )}
                      {recommendation.impact.low > 0 && (
                        <div>Low: {recommendation.impact.low}</div>
                      )}
                    </div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>

              <div className={cn("text-sm", effortInfo.color)}>
                {effortInfo.label}
              </div>
            </div>
          </div>

          {/* Expand Toggle */}
          <span className="shrink-0 inline-flex items-center justify-center h-10 w-10 rounded-md hover:bg-accent hover:text-accent-foreground">
            {expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </span>
        </div>
      </button>

      {/* Expanded Details */}
      {expanded && (
        <CardContent className="pt-0 border-t">
          <div className="space-y-4 pt-4">
            {/* Action Details */}
            {recommendation.action.type === 'update_dependency' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <ArrowUpCircle className="h-4 w-4" />
                  Recommended Action
                </h5>
                <div className="bg-muted rounded-lg p-3 font-mono text-sm">
                  <div className="flex items-center justify-between">
                    <span>
                      Update <strong>{recommendation.action.package}</strong> from{' '}
                      <span className="text-destructive">{recommendation.action.current_version}</span> to{' '}
                      <span className="text-success">{recommendation.action.target_version}</span>
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={(e: React.MouseEvent) => {
                        e.stopPropagation()
                        copyToClipboard(`${recommendation.action.package}@${recommendation.action.target_version}`)
                      }}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {recommendation.action.type === 'update_base_image' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Container className="h-4 w-4" />
                  Base Image
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.current_image && (
                    <div>
                      <span className="text-muted-foreground">Current: </span>
                      <code>{recommendation.action.current_image}</code>
                    </div>
                  )}
                  {recommendation.action.suggestion && (
                    <div>
                      <span className="text-muted-foreground">Suggestion: </span>
                      {recommendation.action.suggestion}
                    </div>
                  )}
                  {recommendation.action.commands && recommendation.action.commands.length > 0 && (
                    <div className="mt-2 space-y-1 font-mono text-xs">
                      {recommendation.action.commands.map((cmd, i) => (
                        <div key={i} className="text-muted-foreground">{cmd}</div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {recommendation.action.type === 'update_transitive' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Layers className="h-4 w-4" />
                  How to Fix
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  <div>
                    Update <strong>{recommendation.action.package}</strong> to{' '}
                    <span className="text-success">{recommendation.action.target_version}</span>
                  </div>
                  {recommendation.action.suggestions && (
                    <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2">
                      {recommendation.action.suggestions.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}

            {recommendation.action.type === 'no_fix' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Lightbulb className="h-4 w-4" />
                  Options
                </h5>
                <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                  {recommendation.action.options?.map((opt, i) => (
                    <li key={i}>{opt}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Secrets Action */}
            {(recommendation.action.type === 'rotate_credential' || recommendation.action.type === 'remove_secret') && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Key className="h-4 w-4" />
                  Secret Details
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.secret_type && (
                    <div>
                      <span className="text-muted-foreground">Type: </span>
                      <code className="text-destructive">{recommendation.action.secret_type}</code>
                    </div>
                  )}
                  {recommendation.action.file_path && (
                    <div>
                      <span className="text-muted-foreground">File: </span>
                      <code>{recommendation.action.file_path}</code>
                      {recommendation.action.line_number && (
                        <span className="text-muted-foreground"> (Line {recommendation.action.line_number})</span>
                      )}
                    </div>
                  )}
                  <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2">
                    <li>Rotate the exposed credential immediately</li>
                    <li>Check git history for previous exposures</li>
                    <li>Use environment variables or secret managers</li>
                  </ul>
                </div>
              </div>
            )}

            {/* SAST Action */}
            {recommendation.action.type === 'fix_code' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Code className="h-4 w-4" />
                  Code Security Issues
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.files && recommendation.action.files.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">Affected Files:</span>
                      <ul className="list-disc list-inside mt-1">
                        {recommendation.action.files.slice(0, 5).map((file, i) => (
                          <li key={i} className="font-mono text-xs">{file}</li>
                        ))}
                        {recommendation.action.files.length > 5 && (
                          <li className="text-muted-foreground">...and {recommendation.action.files.length - 5} more</li>
                        )}
                      </ul>
                    </div>
                  )}
                  {recommendation.action.rule_ids && recommendation.action.rule_ids.length > 0 && (
                    <div className="mt-2">
                      <span className="text-muted-foreground">Rules: </span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {recommendation.action.rule_ids.map((rule, i) => (
                          <Badge key={i} variant="outline">{rule}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* IAC Action */}
            {recommendation.action.type === 'fix_iac' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Server className="h-4 w-4" />
                  Infrastructure Issues
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.resource_type && (
                    <div>
                      <span className="text-muted-foreground">Resource Type: </span>
                      <code>{recommendation.action.resource_type}</code>
                    </div>
                  )}
                  {recommendation.action.description && (
                    <div className="text-muted-foreground mt-2">
                      {recommendation.action.description}
                    </div>
                  )}
                  {recommendation.action.files && recommendation.action.files.length > 0 && (
                    <div className="mt-2">
                      <span className="text-muted-foreground">Affected Files:</span>
                      <ul className="list-disc list-inside mt-1 font-mono text-xs">
                        {recommendation.action.files.slice(0, 5).map((file, i) => (
                          <li key={i}>{file}</li>
                        ))}
                        {recommendation.action.files.length > 5 && (
                          <li className="text-muted-foreground">...and {recommendation.action.files.length - 5} more</li>
                        )}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* License Action */}
            {recommendation.action.type === 'review_license' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Scale className="h-4 w-4" />
                  License Details
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.license_type && (
                    <div>
                      <span className="text-muted-foreground">License Type: </span>
                      <code className="text-severity-high">{recommendation.action.license_type}</code>
                    </div>
                  )}
                  {recommendation.action.components && recommendation.action.components.length > 0 && (
                    <div className="mt-2">
                      <span className="text-muted-foreground">Components:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {recommendation.action.components.map((comp, i) => (
                          <Badge key={i} variant="secondary">{comp}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2">
                    <li>Review license compatibility with your project</li>
                    <li>Consult legal team if needed</li>
                    <li>Consider alternative packages if incompatible</li>
                  </ul>
                </div>
              </div>
            )}

            {/* Supply Chain Action */}
            {recommendation.action.type === 'review_package' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  Supply Chain Concern
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.description && (
                    <div className="text-muted-foreground">
                      {recommendation.action.description}
                    </div>
                  )}
                  <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2">
                    <li>Verify package authenticity and maintainer</li>
                    <li>Check for recent suspicious updates</li>
                    <li>Consider pinning to known-good version</li>
                  </ul>
                </div>
              </div>
            )}

            {/* Outdated Dependencies Action */}
            {recommendation.action.type === 'upgrade_outdated' && recommendation.action.packages && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Outdated Packages
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.packages.map((pkg, i) => (
                    <div key={i} className="flex items-center justify-between border-b last:border-0 pb-2 last:pb-0">
                      <div>
                        <span className="font-medium">{pkg.name}</span>
                        <span className="text-muted-foreground"> v{pkg.current}</span>
                        <span className="text-success"> → v{pkg.recommended_major}+</span>
                      </div>
                      <span className="text-xs text-muted-foreground max-w-[200px] truncate">{pkg.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Version Fragmentation Action */}
            {recommendation.action.type === 'deduplicate_versions' && recommendation.action.packages && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <GitBranch className="h-4 w-4" />
                  Version Fragmentation
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-3 max-h-[300px] overflow-y-auto">
                  {recommendation.action.packages.map((pkg, i) => (
                    <div key={i} className="border-b last:border-0 pb-2 last:pb-0">
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{pkg.name}</span>
                        <Badge variant="secondary" className="text-xs">
                          {pkg.version_count || pkg.versions?.length || 0} versions
                        </Badge>
                      </div>
                      <div className="text-muted-foreground text-xs mt-1">
                        <span className="font-mono">{pkg.versions?.slice(0, 4).join(', ')}</span>
                        {(pkg.versions?.length || 0) > 4 && <span className="text-muted-foreground">...</span>}
                      </div>
                      {pkg.suggestion && (
                        <div className="text-success text-xs mt-1">
                          → {pkg.suggestion}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                {recommendation.action.commands && (
                  <div className="mt-3 p-2 bg-muted/50 rounded font-mono text-xs text-muted-foreground">
                    {recommendation.action.commands.map((cmd, i) => (
                      <div key={i}>{cmd}</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Regression Detected Action */}
            {recommendation.action.type === 'investigate_regression' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <TrendingDown className="h-4 w-4 text-destructive" />
                  Regression Details
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.new_critical_cves && recommendation.action.new_critical_cves.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">New Critical CVEs: </span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {recommendation.action.new_critical_cves.map((cve, i) => (
                          <Badge key={i} variant="destructive">{cve}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="text-muted-foreground mt-2">
                    {recommendation.action.suggestion}
                  </div>
                </div>
              </div>
            )}

            {/* Recurring Issues Action */}
            {recommendation.action.type === 'address_recurring' && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <RefreshCw className="h-4 w-4" />
                  Recurring Issues
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.cves && (
                    <div>
                      <span className="text-muted-foreground">Recurring CVEs: </span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {recommendation.action.cves.map((cve, i) => {
                          const cveStr = typeof cve === 'string' ? cve : cve.cve
                          return <Badge key={i} variant="outline">{cveStr}</Badge>
                        })}
                      </div>
                    </div>
                  )}
                  {recommendation.action.suggestions && (
                    <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2">
                      {recommendation.action.suggestions.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}

            {/* Deep Dependency Chain Action */}
            {recommendation.action.type === 'reduce_chain_depth' && recommendation.action.deepest_chains && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <FolderTree className="h-4 w-4" />
                  Deep Dependency Chains
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.deepest_chains.map((chain, i) => (
                    <div key={i} className="border-b last:border-0 pb-2 last:pb-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{chain.package}</span>
                        <Badge variant="secondary">Depth: {chain.depth}</Badge>
                      </div>
                      {chain.chain_preview && (
                        <div className="text-xs text-muted-foreground mt-1 font-mono">
                          {chain.chain_preview}
                        </div>
                      )}
                    </div>
                  ))}
                  {recommendation.action.suggestions && (
                    <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2">
                      {recommendation.action.suggestions.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}

            {/* Duplicate Functionality Action */}
            {recommendation.action.type === 'consolidate_packages' && recommendation.action.duplicates && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Layers className="h-4 w-4" />
                  Duplicate Functionality
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-3">
                  {recommendation.action.duplicates.map((dup, i) => (
                    <div key={i} className="border-b last:border-0 pb-2 last:pb-0">
                      <div className="font-medium text-amber-500">{dup.category}</div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {dup.found.map((pkg, j) => (
                          <Badge key={j} variant="secondary">{pkg}</Badge>
                        ))}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">{dup.suggestion}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cross-Project / Shared Vulnerability Action */}
            {recommendation.action.type === 'fix_cross_project_vuln' && recommendation.action.cves && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  Cross-Project Vulnerabilities
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {(recommendation.action.cves as CrossProjectCve[]).map((cve, i) => (
                    <div key={i} className="border-b last:border-0 pb-2 last:pb-0">
                      <div className="flex items-center gap-2">
                        <Badge variant="destructive">{cve.cve}</Badge>
                        <span className="text-muted-foreground">affects {cve.total_affected} projects</span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        Projects: {cve.affected_projects?.slice(0, 3).join(', ')}
                        {(cve.affected_projects?.length ?? 0) > 3 && '...'}
                      </div>
                    </div>
                  ))}
                  {recommendation.action.suggestion && (
                    <div className="text-muted-foreground mt-2 text-xs flex items-center gap-1">
                      <Lightbulb className="h-3 w-3" />
                      {recommendation.action.suggestion}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Project Priority Action */}
            {recommendation.action.type === 'prioritize_projects' && recommendation.action.priority_projects && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <TrendingUp className="h-4 w-4" />
                  Priority Projects
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-2">
                  {recommendation.action.priority_projects.map((proj, i) => (
                    <div key={i} className="flex items-center justify-between border-b last:border-0 pb-2 last:pb-0">
                      <span className="font-medium">{proj.name}</span>
                      <div className="flex gap-2">
                        <Badge variant="destructive">{proj.critical} Critical</Badge>
                        <Badge variant="outline" className="text-severity-high">{proj.high} High</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Version Standardization Action */}
            {recommendation.action.type === 'standardize_versions' && recommendation.action.packages && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <GitBranch className="h-4 w-4" />
                  Version Standardization Across Projects
                </h5>
                <div className="bg-muted rounded-lg p-3 text-sm space-y-3">
                  {recommendation.action.packages.map((pkg, i) => (
                    <div key={i} className="border-b last:border-0 pb-2 last:pb-0">
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{pkg.name}</span>
                        {pkg.project_count && (
                          <Badge variant="secondary" className="text-xs">
                            {pkg.project_count} projects
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        Versions in use: <span className="font-mono">{pkg.versions?.join(', ') || 'unknown'}</span>
                      </div>
                      {pkg.suggestion && pkg.suggestion !== 'Use latest stable' && (
                        <div className="text-xs text-success mt-1">
                          Recommended: <span className="font-mono">{pkg.suggestion}</span>
                        </div>
                      )}
                    </div>
                  ))}
                  {recommendation.action.suggestions && (
                    <ul className="list-disc list-inside text-muted-foreground space-y-1 mt-2 text-xs">
                      {recommendation.action.suggestions.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}

            {/* CVEs */}
            {recommendation.action.cves && recommendation.action.cves.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium">Related Vulnerabilities</h5>
                <div className="flex flex-wrap gap-1">
                  {recommendation.action.cves.map((cveItem, idx) => {
                    const cve = typeof cveItem === 'string' ? cveItem : cveItem.cve
                    const isCve = cve.startsWith('CVE-');
                    const isGhsa = cve.startsWith('GHSA-');
                    const link = isCve
                      ? `https://nvd.nist.gov/vuln/detail/${cve}`
                      : isGhsa
                        ? `https://github.com/advisories/${cve}`
                        : null;

                    return link ? (
                      <a
                        key={`${cve}-${idx}`}
                        href={link}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center gap-1"
                      >
                        <Badge variant="outline" className="hover:bg-muted cursor-pointer">
                          {cve}
                          <ExternalLink className="h-3 w-3 ml-1" />
                        </Badge>
                      </a>
                    ) : (
                      <Badge key={`${cve}-${idx}`} variant="outline">{cve}</Badge>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Affected Projects */}
            {recommendation.affected_projects && recommendation.affected_projects.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium flex items-center gap-2">
                  <FolderTree className="h-4 w-4" />
                  Affected Projects
                </h5>
                <div className="flex flex-wrap gap-2">
                  {recommendation.affected_projects.slice(0, 5).map((proj) => (
                    <Link
                      key={proj.id}
                      to={`/projects/${proj.id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-muted hover:bg-muted/80 text-sm transition-colors"
                    >
                      <Package className="h-3 w-3" />
                      {proj.name}
                    </Link>
                  ))}
                  {recommendation.affected_projects.length > 5 && (
                    <Badge variant="secondary">
                      +{recommendation.affected_projects.length - 5} more
                    </Badge>
                  )}
                </div>
              </div>
            )}

            {/* Affected Components */}
            {recommendation.affected_components.length > 0 && recommendation.affected_components.length <= 10 && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium">Affected Components</h5>
                <div className="flex flex-wrap gap-1">
                  {recommendation.affected_components.map((comp) => (
                    <Badge key={comp} variant="secondary">
                      {comp}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            {recommendation.affected_components.length > 10 && (
              <div className="text-sm text-muted-foreground">
                {recommendation.affected_components.length} components affected
              </div>
            )}
          </div>
        </CardContent>
      )}
    </Card>
  )
}
