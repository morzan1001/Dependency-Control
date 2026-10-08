import { useState, type ReactNode } from 'react'
import { Recommendation, RecommendationAction, CrossProjectCve, RecurringCve } from '@/types/analytics'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { advisoryUrl } from '@/lib/finding-utils'
import { useCopyToClipboard } from '@/hooks/use-copy-to-clipboard'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  ArrowUpCircle,
  ChevronDown,
  ChevronRight,
  Code,
  Container,
  Copy,
  ExternalLink,
  FolderTree,
  GitBranch,
  Globe,
  Layers,
  Lightbulb,
  RefreshCw,
  TrendingDown,
  TrendingUp,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { priorityConfig, typeConfig, effortConfig } from './config'

const FILES_LISTED = 5
const SEVERITY_CHIPS = [
  ['critical', 'Critical'],
  ['high', 'High'],
  ['medium', 'Medium'],
  ['low', 'Low'],
] as const

/** Files the recommendation covers beyond the ones listed; the action's own list is already a sample. */
function filesBeyond(action: RecommendationAction): number {
  const listed = action.files?.length ?? 0
  return Math.max(action.files_total ?? listed, listed) - Math.min(listed, FILES_LISTED)
}

function ActionSection({ icon: Icon, iconClassName, title, bodyClassName = 'space-y-2', footer, children }: Readonly<{
  icon: LucideIcon
  iconClassName?: string
  title: string
  bodyClassName?: string
  footer?: ReactNode
  children: ReactNode
}>) {
  return (
    <div className="space-y-2">
      <h5 className="text-sm font-medium flex items-center gap-2">
        <Icon className={cn("h-4 w-4", iconClassName)} />
        {title}
      </h5>
      <div className={cn("bg-muted rounded-lg p-3 text-sm", bodyClassName)}>
        {children}
      </div>
      {footer}
    </div>
  )
}

function componentsHeading(recommendation: Recommendation): string {
  const shown = recommendation.affected_components.length
  const total = Math.max(recommendation.affected_components_total, shown)
  return total > shown
    ? `Affected Components (${shown} of ${total.toLocaleString()})`
    : `Affected Components (${total.toLocaleString()})`
}

export function RecommendationCard({ recommendation }: Readonly<{ recommendation: Recommendation }>) {
  const [expanded, setExpanded] = useState(false)

  const typeInfo = typeConfig[recommendation.type] ?? {
    icon: Lightbulb,
    label: recommendation.type.split('_').map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(' '),
    color: 'text-muted-foreground',
    bgColor: 'bg-muted',
  }
  const priorityInfo = priorityConfig[recommendation.priority] || priorityConfig.medium
  const effortInfo = effortConfig[recommendation.effort] || effortConfig.medium
  const TypeIcon = typeInfo.icon
  const severityCounts = SEVERITY_CHIPS.filter(([key]) => (recommendation.impact[key] ?? 0) > 0)
  const { copy } = useCopyToClipboard()

  return (
    <Card className="overflow-hidden">
      <button
        type="button"
        className="w-full text-left p-4 cursor-pointer hover:bg-muted/50 transition-colors"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-4">          <div className={cn("p-2 rounded-lg", typeInfo.bgColor)}>
            <TypeIcon className={cn("h-5 w-5", typeInfo.color)} />
          </div>
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
              {recommendation.ranked_out_of > 0 && (
                <Badge variant="outline" className="shrink-0 text-muted-foreground">
                  Ranked {recommendation.rank} of {recommendation.ranked_out_of.toLocaleString()}
                </Badge>
              )}
            </div>

            <p className="text-sm text-muted-foreground line-clamp-2">
              {recommendation.description}
            </p>
            <div className="flex items-center gap-4 mt-2">
              {recommendation.impact.total > 0 && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div className="flex items-center gap-1.5 text-sm">
                        <Zap className="h-4 w-4 text-yellow-500" />
                        <span className="font-medium">{recommendation.impact.total}</span>
                        <span className="text-muted-foreground">addressed</span>
                      </div>
                    </TooltipTrigger>
                    {severityCounts.length > 0 && (
                      <TooltipContent>
                        <div className="space-y-1">
                          {severityCounts.map(([key, label]) => (
                            <div key={key}>{label}: {recommendation.impact[key]}</div>
                          ))}
                        </div>
                      </TooltipContent>
                    )}
                  </Tooltip>
                </TooltipProvider>
              )}

              <div className={cn("text-sm", effortInfo.color)}>
                {effortInfo.label}
              </div>
            </div>
          </div>
          <span className="shrink-0 inline-flex items-center justify-center h-10 w-10 rounded-md hover:bg-accent hover:text-accent-foreground">
            {expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </span>
        </div>
      </button>
      {expanded && (
        <CardContent className="pt-0 border-t">
          <div className="space-y-4 pt-4">            {recommendation.action.type === 'update_dependency' && (
              <ActionSection icon={ArrowUpCircle} title="Recommended Action" bodyClassName="font-mono">
                <div className="flex items-center justify-between">
                  <span>
                    Update <strong>{recommendation.action.package}</strong> from{' '}
                    <span className="text-destructive">{recommendation.action.current_version}</span> to{' '}
                    <span className="text-success">{recommendation.action.target_version}</span>
                  </span>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={(e) => copy(`${recommendation.action.package}@${recommendation.action.target_version}`, e)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </ActionSection>
            )}

            {recommendation.action.type === 'update_base_image' && (
              <ActionSection icon={Container} title="Base Image">
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
                    {recommendation.action.commands.map((cmd) => (
                      <div key={cmd} className="text-muted-foreground">{cmd}</div>
                    ))}
                  </div>
                )}
              </ActionSection>
            )}

            {recommendation.action.type === 'update_transitive' && (
              <ActionSection icon={Layers} title="How to Fix">
                <div>
                  Update <strong>{recommendation.action.package}</strong> to{' '}
                  <span className="text-success">{recommendation.action.target_version}</span>
                </div>
              </ActionSection>
            )}

            {recommendation.action.type === 'fix_code' && (
              <ActionSection icon={Code} title="Code Security Issues">
                {recommendation.action.files && recommendation.action.files.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Affected Files:</span>
                    <ul className="list-disc list-inside mt-1">
                      {recommendation.action.files.slice(0, 5).map((file) => (
                        <li key={file} className="font-mono text-xs">{file}</li>
                      ))}
                      {filesBeyond(recommendation.action) > 0 && (
                        <li className="text-muted-foreground">
                          {`...and ${filesBeyond(recommendation.action).toLocaleString()} more`}
                        </li>
                      )}
                    </ul>
                  </div>
                )}
                {recommendation.action.rule_ids && recommendation.action.rule_ids.length > 0 && (
                  <div className="mt-2">
                    <span className="text-muted-foreground">Rules: </span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {recommendation.action.rule_ids.map((rule) => (
                        <Badge key={rule} variant="outline">{rule}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </ActionSection>
            )}
            {recommendation.action.type === 'deduplicate_versions' && recommendation.action.packages && (
              <ActionSection
                icon={GitBranch}
                title="Version Fragmentation"
                bodyClassName="space-y-3 max-h-[300px] overflow-y-auto"
                footer={recommendation.action.commands && (
                  <div className="mt-3 p-2 bg-muted/50 rounded font-mono text-xs text-muted-foreground">
                    {recommendation.action.commands.map((cmd) => (
                      <div key={cmd}>{cmd}</div>
                    ))}
                  </div>
                )}
              >
                {recommendation.action.packages.map((pkg) => (
                  <div key={pkg.name} className="border-b last:border-0 pb-2 last:pb-0">
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
              </ActionSection>
            )}
            {recommendation.action.type === 'investigate_regression' && (
              <ActionSection icon={TrendingDown} iconClassName="text-destructive" title="Regression Details">
                {recommendation.action.new_critical_cves && recommendation.action.new_critical_cves.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">New Critical CVEs: </span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {recommendation.action.new_critical_cves.map((cve) => (
                        <Badge key={cve} variant="destructive">{cve}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div className="text-muted-foreground mt-2">
                  {recommendation.action.suggestion}
                </div>
              </ActionSection>
            )}
            {recommendation.action.type === 'address_recurring' && (
              <ActionSection icon={RefreshCw} title="Recurring Issues">
                {(recommendation.action.cves as RecurringCve[] | undefined)?.map((row) => (
                  <div key={row.cve} className="flex items-center gap-2">
                    <Badge variant="outline">{row.cve}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {`${row.components.join(', ')} · ${row.scans} scans`}
                    </span>
                  </div>
                ))}
              </ActionSection>
            )}
            {recommendation.action.type === 'reduce_chain_depth' && recommendation.action.deepest_chains && (
              <ActionSection icon={FolderTree} title="Deep Dependency Chains">
                {recommendation.action.deepest_chains.map((chain) => (
                  <div key={chain.package} className="border-b last:border-0 pb-2 last:pb-0">
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
              </ActionSection>
            )}
            {recommendation.action.type === 'consolidate_packages' && recommendation.action.duplicates && (
              <ActionSection icon={Layers} title="Duplicate Functionality" bodyClassName="space-y-3">
                {recommendation.action.duplicates.map((dup) => (
                  <div key={dup.category} className="border-b last:border-0 pb-2 last:pb-0">
                    <div className="font-medium text-amber-500">{dup.category}</div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {dup.found.map((pkg) => (
                        <Badge key={pkg} variant="secondary">{pkg}</Badge>
                      ))}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">{dup.suggestion}</div>
                  </div>
                ))}
              </ActionSection>
            )}
            {recommendation.action.type === 'fix_cross_project_vuln' && recommendation.action.cves && (
              <ActionSection icon={Globe} title="Cross-Project Vulnerabilities">
                {(recommendation.action.cves as CrossProjectCve[]).map((cve) => (
                  <div key={cve.cve} className="border-b last:border-0 pb-2 last:pb-0">
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
              </ActionSection>
            )}
            {recommendation.action.type === 'prioritize_projects' && recommendation.action.priority_projects && (
              <ActionSection icon={TrendingUp} title="Priority Projects">
                {recommendation.action.priority_projects.map((proj) => (
                  <div key={proj.name} className="flex items-center justify-between border-b last:border-0 pb-2 last:pb-0">
                    <span className="font-medium">{proj.name}</span>
                    <div className="flex gap-2">
                      <Badge variant="destructive">{proj.critical} Critical</Badge>
                      <Badge variant="outline" className="text-severity-high">{proj.high} High</Badge>
                    </div>
                  </div>
                ))}
              </ActionSection>
            )}
            {recommendation.action.type === 'standardize_versions' && recommendation.action.packages && (
              <ActionSection icon={GitBranch} title="Version Standardization Across Projects" bodyClassName="space-y-3">
                {recommendation.action.packages.map((pkg) => (
                  <div key={pkg.name} className="border-b last:border-0 pb-2 last:pb-0">
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
                    {pkg.suggestion && (
                      <div className="text-xs text-success mt-1">
                        Recommended: <span className="font-mono">{pkg.suggestion}</span>
                      </div>
                    )}
                  </div>
                ))}
              </ActionSection>
            )}

            {recommendation.action.steps && recommendation.action.steps.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium">Steps</h5>
                <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
                  {recommendation.action.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
              </div>
            )}

            {/* CVEs (skip when the action type already renders its own CVE list) */}
            {!['address_recurring', 'fix_cross_project_vuln'].includes(recommendation.action.type) &&
              recommendation.action.cves && recommendation.action.cves.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium">Related Vulnerabilities</h5>
                <div className="flex flex-wrap gap-1">
                  {recommendation.action.cves.map((cveItem) => {
                    const cve = typeof cveItem === 'string' ? cveItem : cveItem.cve
                    const link = advisoryUrl(cve)

                    return link ? (
                      <a
                        key={cve}
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
                      <Badge key={cve} variant="outline">{cve}</Badge>
                    );
                  })}
                </div>
              </div>
            )}
            {recommendation.affected_components.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-sm font-medium">
                  {componentsHeading(recommendation)}
                </h5>
                <div className="flex flex-wrap gap-1">
                  {recommendation.affected_components.map((comp) => (
                    <Badge key={comp} variant="secondary">
                      {comp}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      )}
    </Card>
  )
}
