import { useProjectRecommendations } from '@/hooks/queries/use-analytics'
import { Recommendation, RecommendationsResponse, CrossProjectCve } from '@/types/analytics'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ProjectCombobox } from '@/components/ui/project-combobox'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import { Link } from 'react-router-dom'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  AlertTriangle,
  ArrowUpCircle,
  Calendar,
  ChevronDown,
  ChevronRight,
  Clock,
  Code,
  Container,
  Copy,
  ExternalLink,
  FileWarning,
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
  Shield,
  ShieldAlert,
  ShieldX,
  Sparkles,
  TrendingDown,
  TrendingUp,
  Zap,
} from 'lucide-react'

interface RecommendationsProps {
  projectId?: string
  scanId?: string
}

const priorityConfig = {
  critical: { color: 'bg-red-500', textColor: 'text-red-500', label: 'Critical' },
  high: { color: 'bg-orange-500', textColor: 'text-orange-500', label: 'High' },
  medium: { color: 'bg-yellow-500', textColor: 'text-yellow-500', label: 'Medium' },
  low: { color: 'bg-blue-500', textColor: 'text-blue-500', label: 'Low' },
}

const typeConfig: Record<string, { icon: typeof Container; label: string; color: string; bgColor: string }> = {
  base_image_update: {
    icon: Container,
    label: 'Base Image Update',
    color: 'text-blue-500',
    bgColor: 'bg-blue-500/10',
  },
  direct_dependency_update: {
    icon: Package,
    label: 'Dependency Update',
    color: 'text-green-500',
    bgColor: 'bg-green-500/10',
  },
  transitive_fix_via_parent: {
    icon: Layers,
    label: 'Transitive Fix',
    color: 'text-purple-500',
    bgColor: 'bg-purple-500/10',
  },
  no_fix_available: {
    icon: ShieldX,
    label: 'No Fix Available',
    color: 'text-gray-500',
    bgColor: 'bg-gray-500/10',
  },
  consider_waiver: {
    icon: Shield,
    label: 'Consider Waiver',
    color: 'text-amber-500',
    bgColor: 'bg-amber-500/10',
  },
  rotate_secrets: {
    icon: Key,
    label: 'Rotate Secrets',
    color: 'text-red-500',
    bgColor: 'bg-red-500/10',
  },
  remove_secrets: {
    icon: FileWarning,
    label: 'Remove Secrets',
    color: 'text-orange-500',
    bgColor: 'bg-orange-500/10',
  },
  fix_code_security: {
    icon: Code,
    label: 'Fix Code Issues',
    color: 'text-cyan-500',
    bgColor: 'bg-cyan-500/10',
  },
  fix_infrastructure: {
    icon: Server,
    label: 'Fix Infrastructure',
    color: 'text-indigo-500',
    bgColor: 'bg-indigo-500/10',
  },
  license_compliance: {
    icon: Scale,
    label: 'License Compliance',
    color: 'text-pink-500',
    bgColor: 'bg-pink-500/10',
  },
  supply_chain_risk: {
    icon: AlertTriangle,
    label: 'Supply Chain Risk',
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-500/10',
  },
  // Dependency Health & Hygiene
  outdated_dependency: {
    icon: Clock,
    label: 'Outdated Dependency',
    color: 'text-amber-600',
    bgColor: 'bg-amber-600/10',
  },
  version_fragmentation: {
    icon: GitBranch,
    label: 'Version Fragmentation',
    color: 'text-violet-500',
    bgColor: 'bg-violet-500/10',
  },
  dev_in_production: {
    icon: Sparkles,
    label: 'Dev in Production',
    color: 'text-teal-500',
    bgColor: 'bg-teal-500/10',
  },
  unmaintained_package: {
    icon: Calendar,
    label: 'Unmaintained Package',
    color: 'text-gray-600',
    bgColor: 'bg-gray-600/10',
  },
  // Trend-based
  recurring_vulnerability: {
    icon: RefreshCw,
    label: 'Recurring Issue',
    color: 'text-rose-500',
    bgColor: 'bg-rose-500/10',
  },
  regression_detected: {
    icon: TrendingDown,
    label: 'Regression Detected',
    color: 'text-red-600',
    bgColor: 'bg-red-600/10',
  },
  // Dependency Graph
  deep_dependency_chain: {
    icon: FolderTree,
    label: 'Deep Dependency Chain',
    color: 'text-slate-500',
    bgColor: 'bg-slate-500/10',
  },
  duplicate_functionality: {
    icon: Layers,
    label: 'Duplicate Functionality',
    color: 'text-fuchsia-500',
    bgColor: 'bg-fuchsia-500/10',
  },
  // Cross-Project
  cross_project_pattern: {
    icon: Globe,
    label: 'Cross-Project Pattern',
    color: 'text-sky-500',
    bgColor: 'bg-sky-500/10',
  },
  shared_vulnerability: {
    icon: Globe,
    label: 'Shared Vulnerability',
    color: 'text-red-500',
    bgColor: 'bg-red-500/10',
  },
  // ================================================================
  // NEW: Hotspot & Actionable Recommendations
  // ================================================================
  critical_hotspot: {
    icon: Zap,
    label: 'Critical Hotspot',
    color: 'text-red-600',
    bgColor: 'bg-red-600/20',
  },
  known_exploit: {
    icon: ShieldAlert,
    label: 'Known Exploit (KEV)',
    color: 'text-red-500',
    bgColor: 'bg-red-500/20',
  },
  ransomware_risk: {
    icon: ShieldX,
    label: 'Ransomware Risk',
    color: 'text-red-700',
    bgColor: 'bg-red-700/20',
  },
  actively_exploited: {
    icon: TrendingUp,
    label: 'High Exploit Probability',
    color: 'text-orange-600',
    bgColor: 'bg-orange-600/20',
  },
  malware_detected: {
    icon: ShieldX,
    label: 'Malware Detected',
    color: 'text-red-800',
    bgColor: 'bg-red-800/20',
  },
  typosquat_detected: {
    icon: AlertTriangle,
    label: 'Typosquatting',
    color: 'text-amber-600',
    bgColor: 'bg-amber-600/20',
  },
  hash_mismatch: {
    icon: Shield,
    label: 'Hash Mismatch',
    color: 'text-red-500',
    bgColor: 'bg-red-500/10',
  },
  eol_dependency: {
    icon: Clock,
    label: 'End-of-Life',
    color: 'text-gray-600',
    bgColor: 'bg-gray-600/20',
  },
  quick_win: {
    icon: Lightbulb,
    label: 'Quick Win',
    color: 'text-green-600',
    bgColor: 'bg-green-600/20',
  },
  single_update_multi_fix: {
    icon: ArrowUpCircle,
    label: 'Multi-Fix Update',
    color: 'text-green-500',
    bgColor: 'bg-green-500/20',
  },
  toxic_dependency: {
    icon: AlertTriangle,
    label: 'Toxic Dependency',
    color: 'text-purple-600',
    bgColor: 'bg-purple-600/20',
  },
  attack_surface_reduction: {
    icon: Shield,
    label: 'Reduce Attack Surface',
    color: 'text-blue-600',
    bgColor: 'bg-blue-600/10',
  },
  critical_risk: {
    icon: ShieldAlert,
    label: 'Critical Risk',
    color: 'text-red-500',
    bgColor: 'bg-red-500/10',
  },
}

const effortConfig = {
  low: { label: 'Low Effort', color: 'text-green-600' },
  medium: { label: 'Medium Effort', color: 'text-yellow-600' },
  high: { label: 'High Effort', color: 'text-red-600' },
}

function RecommendationCard({ recommendation }: { recommendation: Recommendation }) {
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
      <div 
        className="p-4 cursor-pointer hover:bg-muted/50 transition-colors"
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
          <Button variant="ghost" size="icon" className="shrink-0">
            {expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>
      
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
                      <span className="text-red-500">{recommendation.action.current_version}</span> to{' '}
                      <span className="text-green-500">{recommendation.action.target_version}</span>
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
                    <span className="text-green-500">{recommendation.action.target_version}</span>
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
                      <code className="text-red-500">{recommendation.action.secret_type}</code>
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
                      <code className="text-orange-500">{recommendation.action.license_type}</code>
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
                        <span className="text-green-500"> → v{pkg.recommended_major}+</span>
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
                        <div className="text-green-500 text-xs mt-1">
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
                  <TrendingDown className="h-4 w-4 text-red-500" />
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
                        <Badge variant="outline" className="text-orange-500">{proj.high} High</Badge>
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
                        <div className="text-xs text-green-500 mt-1">
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

function SummaryCard({ data }: { data: RecommendationsResponse }) {
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
                <div className="text-2xl font-bold text-green-500">
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
                  <div className="text-2xl font-bold text-red-500">
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

export function Recommendations({ projectId: initialProjectId, scanId }: RecommendationsProps) {
  const [selectedProjectId, setSelectedProjectId] = useState<string>(initialProjectId || '')
  
  const { data, isLoading, error } = useProjectRecommendations(selectedProjectId, scanId)
  
  return (
    <div className="space-y-6">
      {/* Project Selector */}
      {!initialProjectId && (
        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
            <CardDescription>
              Get actionable remediation recommendations for your project's vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <ProjectCombobox
                value={selectedProjectId}
                onValueChange={setSelectedProjectId}
                className="w-[350px]"
              />
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* Loading State */}
      {isLoading && selectedProjectId && (
        <div className="space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      )}
      
      {/* Error State */}
      {error && (
        <Card>
          <CardContent className="py-8">
            <div className="flex flex-col items-center gap-2 text-muted-foreground">
              <ShieldAlert className="h-12 w-12" />
              <p>Failed to load recommendations</p>
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* Empty State */}
      {!selectedProjectId && !initialProjectId && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4 text-muted-foreground">
              <Lightbulb className="h-12 w-12" />
              <p>Select a project to view remediation recommendations</p>
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* Results */}
      {data && (
        <>
          {/* Summary */}
          <SummaryCard data={data} />
          
          {/* Recommendations List */}
          {data.recommendations.length > 0 ? (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">
                {data.recommendations.length} Recommendations
              </h3>
              {data.recommendations.map((rec, index) => (
                <RecommendationCard key={index} recommendation={rec} />
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12">
                <div className="flex flex-col items-center gap-4 text-muted-foreground">
                  <Shield className="h-12 w-12 text-green-500" />
                  <p className="text-lg font-medium text-foreground">No vulnerabilities found!</p>
                  <p>This project has no known vulnerabilities to remediate.</p>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
