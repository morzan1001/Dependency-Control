import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getComponentFindings, getDependencyMetadata, DependencyMetadata, ComponentFinding } from '@/lib/api'
import { FindingDetailsModal } from '@/components/FindingDetailsModal'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { cn } from '@/lib/utils'
import { Link } from 'react-router-dom'
import {
  Package,
  ExternalLink,
  Globe,
  GitBranch,
  Download,
  Shield,
  User,
  Building,
  FileText,
  Star,
  GitFork,
  CircleDot,
  Users,
  Calendar,
  AlertTriangle,
  AlertOctagon,
  TrendingUp,
  Link2,
  ChevronDown,
  ChevronUp,
  ArrowUp,
  ArrowDown,
  Tag,
  Copy,
  Check,
} from "lucide-react"

// Severity order for sorting
const severityOrder: Record<string, number> = {
  'CRITICAL': 4,
  'HIGH': 3,
  'MEDIUM': 2,
  'LOW': 1,
  'UNKNOWN': 0,
}

type SortField = 'id' | 'type' | 'severity' | 'project_name'
type SortOrder = 'asc' | 'desc'

interface AnalyticsDependencyModalProps {
  component: string;
  version?: string;
  type?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
      {copied ? (
        <Check className="h-3 w-3 text-green-500" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </Button>
  )
}

function InfoRow({
  icon: Icon,
  label,
  value,
  href,
  copyable = false,
}: {
  icon: React.ElementType
  label: string
  value?: string | null
  href?: string
  copyable?: boolean
}) {
  if (!value) return null

  // Only use href if it's a valid absolute URL
  const validHref = href && (href.startsWith('http://') || href.startsWith('https://')) ? href : undefined

  return (
    <div className="flex items-start gap-3 py-1.5">
      <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <div className="flex items-center gap-2">
          {validHref ? (
            <a
              href={validHref}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-primary hover:underline break-all"
            >
              {value}
            </a>
          ) : (
            <p className="text-sm break-all">{value}</p>
          )}
          {copyable && <CopyButton text={value} />}
        </div>
      </div>
    </div>
  )
}

// Dependency Metadata Section Component
function DependencyMetadataSection({ metadata }: { metadata: DependencyMetadata }) {
  const [showDetails, setShowDetails] = useState(false)
  
  const hasExternalLinks = metadata.homepage || metadata.repository_url || metadata.download_url
  const hasDepsDevData = metadata.deps_dev
  
  return (
    <div className="space-y-4 border rounded-lg p-4 bg-muted/30">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="text-base font-mono">
              {metadata.version}
            </Badge>
            <Badge variant="secondary">{metadata.type}</Badge>
            {metadata.deps_dev?.is_deprecated && (
              <Badge variant="destructive">Deprecated</Badge>
            )}
          </div>
          {metadata.description && (
            <p className="text-sm text-muted-foreground mt-2">{metadata.description}</p>
          )}
        </div>
        
        {/* Quick Stats */}
        <div className="flex items-center gap-3 flex-shrink-0">
          {metadata.project_count > 0 && (
            <div className="text-center">
              <p className="text-lg font-semibold">{metadata.project_count}</p>
              <p className="text-xs text-muted-foreground">Projects</p>
            </div>
          )}
          {metadata.total_vulnerability_count > 0 && (
            <div className="text-center text-destructive">
              <p className="text-lg font-semibold">{metadata.total_vulnerability_count}</p>
              <p className="text-xs">Vulnerabilities</p>
            </div>
          )}
        </div>
      </div>

      {/* deps.dev Stats Grid */}
      {hasDepsDevData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {metadata.deps_dev?.stars !== undefined && (
            <div className="flex items-center gap-2 p-2 bg-background rounded-md">
              <Star className="h-4 w-4 text-yellow-500" />
              <div>
                <p className="text-sm font-medium">{metadata.deps_dev.stars.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Stars</p>
              </div>
            </div>
          )}
          {metadata.deps_dev?.forks !== undefined && (
            <div className="flex items-center gap-2 p-2 bg-background rounded-md">
              <GitFork className="h-4 w-4 text-blue-500" />
              <div>
                <p className="text-sm font-medium">{metadata.deps_dev.forks.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Forks</p>
              </div>
            </div>
          )}
          {metadata.deps_dev?.open_issues !== undefined && (
            <div className="flex items-center gap-2 p-2 bg-background rounded-md">
              <CircleDot className="h-4 w-4 text-green-500" />
              <div>
                <p className="text-sm font-medium">{metadata.deps_dev.open_issues.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Issues</p>
              </div>
            </div>
          )}
          {metadata.deps_dev?.dependents?.total !== undefined && (
            <div className="flex items-center gap-2 p-2 bg-background rounded-md">
              <Users className="h-4 w-4 text-purple-500" />
              <div>
                <p className="text-sm font-medium">{metadata.deps_dev.dependents.total.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Dependents</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scorecard */}
      {metadata.deps_dev?.scorecard && (
        <div className="flex items-center gap-3 p-3 bg-background rounded-md">
          <Shield className={cn(
            "h-6 w-6",
            (metadata.deps_dev.scorecard.overall_score ?? 0) >= 7 ? "text-green-500" :
            (metadata.deps_dev.scorecard.overall_score ?? 0) >= 4 ? "text-amber-500" :
            "text-red-500"
          )} />
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="font-medium">OpenSSF Scorecard</span>
              <Badge variant={
                (metadata.deps_dev.scorecard.overall_score ?? 0) >= 7 ? "default" :
                (metadata.deps_dev.scorecard.overall_score ?? 0) >= 4 ? "secondary" :
                "destructive"
              }>
                {metadata.deps_dev.scorecard.overall_score?.toFixed(1) ?? "N/A"} / 10
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {metadata.deps_dev.scorecard.checks_count} checks evaluated
              {metadata.deps_dev.scorecard.date && ` • ${new Date(metadata.deps_dev.scorecard.date).toLocaleDateString()}`}
            </p>
          </div>
          {metadata.deps_dev?.project_url && (
            <a
              href={`https://scorecard.dev/viewer/?uri=${encodeURIComponent(metadata.deps_dev.project_url.replace(/^https?:\/\//, ''))}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline text-sm flex items-center gap-1"
            >
              View Report <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
      )}

      {/* Known Advisories Warning */}
      {metadata.deps_dev?.known_advisories && metadata.deps_dev.known_advisories.length > 0 && (
        <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-md">
          <AlertOctagon className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-red-600 dark:text-red-400">
              {metadata.deps_dev.known_advisories.length} Known Security {metadata.deps_dev.known_advisories.length === 1 ? "Advisory" : "Advisories"}
            </p>
            <div className="flex flex-wrap gap-1 mt-1">
              {metadata.deps_dev.known_advisories.map((advisory, i) => (
                <Badge key={i} variant="destructive" className="text-xs">
                  {advisory}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Collapsible Details */}
      <Collapsible open={showDetails} onOpenChange={setShowDetails}>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="w-full justify-between">
            <span className="text-sm">
              {showDetails ? "Hide" : "Show"} Details
            </span>
            {showDetails ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-4 pt-4">
          {/* Package Identity */}
          {metadata.purl && (
            <div className="space-y-1">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <Tag className="h-4 w-4" /> PURL
              </h4>
              <div className="flex items-center gap-2 ml-6">
                <code className="text-xs font-mono break-all bg-muted px-2 py-1 rounded">{metadata.purl}</code>
                <CopyButton text={metadata.purl} />
              </div>
            </div>
          )}

          {/* Group */}
          {metadata.group && (
            <InfoRow icon={Tag} label="Group" value={metadata.group} />
          )}

          {/* Maintainers */}
          {(metadata.author || metadata.publisher) && (
            <div className="space-y-1">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <User className="h-4 w-4" /> Maintainers
              </h4>
              <InfoRow icon={User} label="Author" value={metadata.author} />
              <InfoRow icon={Building} label="Publisher" value={metadata.publisher} />
            </div>
          )}

          {/* External Links */}
          {hasExternalLinks && (
            <div className="space-y-1">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <ExternalLink className="h-4 w-4" /> External Links
              </h4>
              <InfoRow icon={Globe} label="Homepage" value={metadata.homepage} href={metadata.homepage ?? undefined} />
              <InfoRow icon={GitBranch} label="Repository" value={metadata.repository_url} href={metadata.repository_url ?? undefined} />
              <InfoRow icon={Download} label="Download" value={metadata.download_url} href={metadata.download_url ?? undefined} />
            </div>
          )}

          {/* deps.dev Links */}
          {metadata.deps_dev?.links && Object.keys(metadata.deps_dev.links).length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium">Additional Links</h4>
              <div className="flex flex-wrap gap-2">
                {Object.entries(metadata.deps_dev.links).map(([label, url]) => (
                  <a
                    key={label}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-muted hover:bg-muted/80 rounded-md transition-colors"
                  >
                    <Link2 className="h-3 w-3" />
                    {label}
                    <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* License */}
          {metadata.license && (
            <div className="space-y-1">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <FileText className="h-4 w-4" /> License
                {metadata.license_category && (
                  <Badge variant={
                    metadata.license_category === "permissive" ? "default" :
                    metadata.license_category === "public_domain" ? "default" :
                    metadata.license_category === "weak_copyleft" ? "secondary" :
                    metadata.license_category === "strong_copyleft" ? "destructive" :
                    metadata.license_category === "network_copyleft" ? "destructive" :
                    "outline"
                  } className="text-xs">
                    {metadata.license_category.replace(/_/g, ' ')}
                  </Badge>
                )}
              </h4>
              <div className="ml-6">
                {metadata.license_url ? (
                  <a
                    href={metadata.license_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline"
                  >
                    {metadata.license}
                  </a>
                ) : (
                  <p className="text-sm">{metadata.license}</p>
                )}
              </div>
              
              {metadata.license_risks && metadata.license_risks.length > 0 && (
                <div className="space-y-1 ml-6">
                  <p className="text-xs text-muted-foreground">Risks</p>
                  {metadata.license_risks.map((risk, i) => (
                    <div key={i} className="flex items-start gap-2 text-sm text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="h-3 w-3 mt-0.5 flex-shrink-0" />
                      <span>{risk}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Published Date */}
          {metadata.deps_dev?.published_at && (
            <InfoRow
              icon={Calendar}
              label="Published"
              value={new Date(metadata.deps_dev.published_at).toLocaleDateString(undefined, {
                year: "numeric",
                month: "long",
                day: "numeric"
              })}
            />
          )}

          {/* Affected Projects */}
          {metadata.affected_projects.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <TrendingUp className="h-4 w-4" /> Used in {metadata.affected_projects.length} Project{metadata.affected_projects.length !== 1 ? 's' : ''}
              </h4>
              <div className="flex flex-wrap gap-2">
                {metadata.affected_projects.map((proj) => (
                  <Link
                    key={proj.id}
                    to={`/projects/${proj.id}`}
                    className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-muted hover:bg-muted/80 rounded-md transition-colors"
                  >
                    {proj.name}
                    <Badge variant={proj.direct ? "default" : "secondary"} className="ml-1 text-[10px] px-1">
                      {proj.direct ? 'Direct' : 'Transitive'}
                    </Badge>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Enrichment Sources */}
          {metadata.enrichment_sources && metadata.enrichment_sources.length > 0 && (
            <p className="text-xs text-muted-foreground pt-2 border-t">
              Data enriched from: {metadata.enrichment_sources.map(s => 
                s === "deps_dev" ? "deps.dev" : 
                s === "license_compliance" ? "License Scanner" : 
                s
              ).join(", ")}
            </p>
          )}
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}

// Main Modal Component
export function AnalyticsDependencyModal({ 
  component, 
  version,
  type,
  open, 
  onOpenChange 
}: AnalyticsDependencyModalProps) {
  const [sortBy, setSortBy] = useState<SortField>('severity')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')
  const [selectedFinding, setSelectedFinding] = useState<ComponentFinding | null>(null)
  const [findingModalOpen, setFindingModalOpen] = useState(false)

  // Fetch dependency metadata
  const { data: metadata, isLoading: isLoadingMetadata } = useQuery({
    queryKey: ['dependency-metadata', component, version, type],
    queryFn: () => getDependencyMetadata(component, version, type),
    enabled: open && !!component,
  })

  // Fetch findings
  const { data: findings, isLoading: isLoadingFindings } = useQuery({
    queryKey: ['component-findings', component, version],
    queryFn: () => getComponentFindings(component, version),
    enabled: open && !!component,
  })

  const sortedFindings = useMemo(() => {
    if (!findings) return []
    
    return [...findings].sort((a, b) => {
      let comparison = 0
      
      switch (sortBy) {
        case 'id':
          comparison = (a.id || '').localeCompare(b.id || '')
          break
        case 'type':
          comparison = (a.type || '').localeCompare(b.type || '')
          break
        case 'severity':
          const sevA = severityOrder[a.severity?.toUpperCase() || 'UNKNOWN'] || 0
          const sevB = severityOrder[b.severity?.toUpperCase() || 'UNKNOWN'] || 0
          comparison = sevA - sevB
          break
        case 'project_name':
          comparison = ((a as any).project_name || '').localeCompare((b as any).project_name || '')
          break
      }
      
      return sortOrder === 'asc' ? comparison : -comparison
    })
  }, [findings, sortBy, sortOrder])

  const handleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortOrder(field === 'severity' ? 'desc' : 'asc')
    }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortBy !== field) return null
    return sortOrder === 'asc' 
      ? <ArrowUp className="h-4 w-4 inline-block ml-1" />
      : <ArrowDown className="h-4 w-4 inline-block ml-1" />
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            {component}
            {version && <Badge variant="outline">{version}</Badge>}
          </DialogTitle>
          <DialogDescription>
            Dependency details and findings across all your projects.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-6 pr-2">
          {/* Metadata Section */}
          {isLoadingMetadata ? (
            <div className="space-y-3">
              <Skeleton className="h-8 w-3/4" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : metadata ? (
            <DependencyMetadataSection metadata={metadata} />
          ) : null}

          {/* Findings Section */}
          <div className="space-y-3">
            <h3 className="text-lg font-medium flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Findings
              {sortedFindings.length > 0 && (
                <Badge variant="secondary">{sortedFindings.length}</Badge>
              )}
            </h3>

            {isLoadingFindings ? (
              <div className="space-y-2">
                {Array(3).fill(0).map((_, i) => (
                  <Skeleton key={i} className="h-16 w-full" />
                ))}
              </div>
            ) : sortedFindings.length > 0 ? (
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead 
                      className="w-[180px] cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('id')}
                    >
                      Finding
                      <SortIcon field="id" />
                    </TableHead>
                    <TableHead 
                      className="w-[100px] cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('type')}
                    >
                      Type
                      <SortIcon field="type" />
                    </TableHead>
                    <TableHead 
                      className="w-[100px] cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('severity')}
                    >
                      Severity
                      <SortIcon field="severity" />
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSort('project_name')}
                    >
                      Project
                      <SortIcon field="project_name" />
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedFindings.map((finding, idx) => (
                    <TableRow 
                      key={`${finding.id}-${(finding as any).project_id}-${idx}`}
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => {
                        setSelectedFinding(finding)
                        setFindingModalOpen(true)
                      }}
                    >
                      <TableCell className="font-mono text-xs truncate">
                        <div className="flex items-center gap-1">
                          {finding.id?.startsWith('CVE-') ? (
                            <span className="text-destructive font-medium">{finding.id}</span>
                          ) : finding.id?.includes('Multiple') ? (
                            <span className="text-orange-500 font-medium">{finding.id}</span>
                          ) : (
                            <span>{finding.id || '-'}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{finding.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(finding.severity || 'UNKNOWN')}>
                          {finding.severity || 'UNKNOWN'}
                        </Badge>
                      </TableCell>
                      <TableCell className="truncate">
                        <Link
                          to={`/projects/${(finding as any).project_id}`}
                          className="text-primary hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {(finding as any).project_name || 'Unknown'}
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground bg-muted/30 rounded-lg">
                <Shield className="h-8 w-8 mb-2" />
                <p>No findings for this dependency</p>
              </div>
            )}
          </div>
        </div>

        {/* Finding Details Modal */}
        {selectedFinding && (
          <FindingDetailsModal
            finding={selectedFinding}
            isOpen={findingModalOpen}
            onClose={() => {
              setFindingModalOpen(false)
              setSelectedFinding(null)
            }}
            projectId={(selectedFinding as any).project_id}
            scanId={(selectedFinding as any).scan_id}
            onNavigate={() => {
              // Close both modals when navigating
              setFindingModalOpen(false)
              setSelectedFinding(null)
              onOpenChange(false)
            }}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}
