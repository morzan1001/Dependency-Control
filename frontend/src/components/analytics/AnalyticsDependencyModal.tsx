import { useState, useMemo } from 'react'
import { useDependencyMetadata, useComponentFindings } from '@/hooks/queries/use-analytics'
import { useAnalyticsMode } from '@/context/analytics-mode'
import { useCopyToClipboard } from '@/hooks/use-copy-to-clipboard'
import { DependencyMetadata, ComponentFinding } from '@/types/analytics'
import { FindingDetailsModal } from '@/components/findings/FindingDetailsModal'
import { resolveRelatedFindingInRows } from '@/components/findings/related-finding-rows'
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
import { SortableHead } from '@/components/ui/sortable-head'
import {
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useSortState } from '@/hooks/use-pagination-state'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { cn, formatDate } from '@/lib/utils'
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
  Link2,
  ChevronDown,
  ChevronUp,
  Tag,
  Copy,
  Check,
} from "lucide-react"
import { getDisplayId, SEVERITY_ORDER } from '@/lib/finding-utils'
import type { Severity } from '@/types/common'
import { AdvisoryLink } from '@/components/findings/AdvisoryLink'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { FindingTypeBadge } from '@/components/findings/FindingTypeBadge'
import { AnalyticsErrorCard } from './AnalyticsErrorCard'

function severityRank(severity?: string): number {
  const idx = SEVERITY_ORDER.indexOf((severity?.toUpperCase() ?? 'UNKNOWN') as Severity)
  return idx === -1 ? 0 : SEVERITY_ORDER.length - idx
}

type SortField = 'id' | 'type' | 'severity' | 'project_name'

function formatEnrichmentSource(source: string): string {
  if (source === "deps_dev") return "deps.dev"
  if (source === "license_compliance") return "License Scanner"
  return source
}

interface AnalyticsDependencyModalProps {
  component: string;
  version?: string;
  type?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function CopyButton({ text }: Readonly<{ text: string }>) {
  const { copied, copy } = useCopyToClipboard()

  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={(e) => copy(text, e)}>
      {copied ? (
        <Check className="h-3 w-3 text-green-500" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </Button>
  )
}

// Only allow http(s) hrefs; metadata URLs come from untrusted registries (block javascript:/data:).
function safeHref(url?: string | null): string | undefined {
  return url && (url.startsWith('http://') || url.startsWith('https://')) ? url : undefined
}

function InfoRow({ icon: Icon, label, value }: Readonly<{ icon: React.ElementType; label: string; value?: string | null }>) {
  if (!value) return null
  return (
    <div className="flex items-start gap-3 py-1.5">
      <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-sm break-all">{value}</p>
      </div>
    </div>
  )
}

function getLicenseBadgeVariant(category?: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (category === 'permissive' || category === 'public_domain') return 'default'
  if (category === 'weak_copyleft') return 'secondary'
  if (category === 'strong_copyleft' || category === 'network_copyleft') return 'destructive'
  return 'outline'
}

function ScorecardDisplay({ metadata }: Readonly<{ metadata: DependencyMetadata }>) {
  const scorecard = metadata.deps_dev?.scorecard
  if (!scorecard) return null

  const score = scorecard.overall_score ?? 0
  let colorClass = 'text-destructive'
  if (score >= 7) colorClass = 'text-success'
  else if (score >= 4) colorClass = 'text-warning'

  let badgeVariant: 'default' | 'secondary' | 'destructive' = 'destructive'
  if (score >= 7) badgeVariant = 'default'
  else if (score >= 4) badgeVariant = 'secondary'

  return (
    <div className="flex items-center gap-3 p-3 bg-background rounded-md">
      <Shield className={cn("h-6 w-6", colorClass)} />
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="font-medium">OpenSSF Scorecard</span>
          <Badge variant={badgeVariant}>
            {scorecard.overall_score?.toFixed(1) ?? "N/A"} / 10
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground mt-0.5">
          {scorecard.checks_count} checks evaluated
          {scorecard.date && ` • ${formatDate(scorecard.date)}`}
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
  )
}

function DependencyMetadataSection({ metadata }: Readonly<{ metadata: DependencyMetadata }>) {
  const [showDetails, setShowDetails] = useState(false)

  const licenseHref = safeHref(metadata.license_url)
  const externalLinks = [
    { label: 'Homepage', href: safeHref(metadata.homepage), icon: Globe },
    { label: 'Repository', href: safeHref(metadata.repository_url), icon: GitBranch },
    { label: 'Download', href: safeHref(metadata.download_url), icon: Download },
  ].filter((link) => link.href)
  const depsDev = metadata.deps_dev
  const statTiles = [
    { label: 'Stars', value: depsDev?.stars, icon: Star, color: 'text-yellow-500' },
    { label: 'Forks', value: depsDev?.forks, icon: GitFork, color: 'text-blue-500' },
    { label: 'Issues', value: depsDev?.open_issues, icon: CircleDot, color: 'text-green-500' },
    { label: 'Dependents', value: depsDev?.dependents?.total, icon: Users, color: 'text-purple-500' },
  ]
  const knownAdvisories = depsDev?.known_advisories ?? []
  const depsDevLinks = depsDev?.links
    ? Object.entries(depsDev.links)
        .map(([label, url]) => [label, safeHref(url)] as const)
        .filter((entry): entry is readonly [string, string] => Boolean(entry[1]))
    : []

  const hasMaintainerInfo = metadata.author || metadata.publisher
  
  return (
    <div className="space-y-4 border rounded-lg p-4 bg-muted/30">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="text-base font-mono">
              {metadata.version}
            </Badge>
            {metadata.versions && metadata.versions.length > 1 && (
              <span className="text-xs text-muted-foreground" title={metadata.versions.join(", ")}>
                Most used of {metadata.versions.length} versions
              </span>
            )}
            <Badge variant="secondary">{metadata.type}</Badge>
            {depsDev?.is_deprecated && (
              <Badge variant="destructive">Deprecated</Badge>
            )}
            {metadata.license && (
              <Badge variant={getLicenseBadgeVariant(metadata.license_category)} className="text-xs wrap-anywhere">
                <FileText className="h-3 w-3 mr-1" />
                {metadata.license}
              </Badge>
            )}
          </div>
          {metadata.description && (
            <p className="text-sm text-muted-foreground mt-2">{metadata.description}</p>
          )}
        </div>
        
        <div className="flex items-center gap-3 flex-shrink-0">
          {metadata.total_vulnerability_count > 0 && (
            <div className="text-center text-severity-critical">
              <p className="text-lg font-semibold">{metadata.total_vulnerability_count}</p>
              <p className="text-xs">Vulnerabilities</p>
            </div>
          )}
        </div>
      </div>

      {knownAdvisories.length > 0 && (
        <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-md">
          <AlertOctagon className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-severity-critical">
              {knownAdvisories.length} Known Security {knownAdvisories.length === 1 ? "Advisory" : "Advisories"}
            </p>
            <div className="flex flex-wrap gap-1 mt-1">
              {knownAdvisories.map((advisory) => (
                <AdvisoryLink key={advisory} id={advisory} variant="destructive" />
              ))}
            </div>
          </div>
        </div>
      )}

      {depsDev && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {statTiles.map(({ label, value, icon: Icon, color }) => value !== undefined && (
            <div key={label} className="flex items-center gap-2 p-2 bg-background rounded-md">
              <Icon className={cn("h-4 w-4", color)} />
              <div>
                <p className="text-sm font-medium">{value.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      <ScorecardDisplay metadata={metadata} />

      {externalLinks.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {externalLinks.map(({ label, href, icon: Icon }) => (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-background hover:bg-muted rounded-md transition-colors border"
            >
              <Icon className="h-4 w-4" />
              {label}
              <ExternalLink className="h-3 w-3" />
            </a>
          ))}
        </div>
      )}

      {metadata.license_risks && metadata.license_risks.length > 0 && (
        <div className="flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-md">
          <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-amber-600 dark:text-amber-400">
              License Considerations
            </p>
            <ul className="mt-1 space-y-0.5">
              {metadata.license_risks.map((risk) => (
                <li key={risk} className="text-sm text-muted-foreground flex items-start gap-1">
                  <span className="text-amber-500">•</span>
                  {risk}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <Collapsible open={showDetails} onOpenChange={setShowDetails}>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="w-full justify-between">
            <span className="text-sm">
              {showDetails ? "Hide" : "Show"} Additional Details
            </span>
            {showDetails ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-4 pt-4">
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

          <InfoRow icon={Tag} label="Group" value={metadata.group} />

          {hasMaintainerInfo && (
            <div className="space-y-1">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <User className="h-4 w-4" /> Maintainers
              </h4>
              <InfoRow icon={User} label="Author" value={metadata.author} />
              <InfoRow icon={Building} label="Publisher" value={metadata.publisher} />
            </div>
          )}

          {depsDevLinks.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium">Additional Links</h4>
              <div className="flex flex-wrap gap-2">
                {depsDevLinks.map(([label, url]) => (
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

          {metadata.license && licenseHref && (
            <div className="space-y-1">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <FileText className="h-4 w-4" /> License Details
              </h4>
              <div className="ml-6">
                <a
                  href={licenseHref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-primary hover:underline flex items-center gap-1"
                >
                  View full license text <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          )}

          {depsDev?.published_at && (
            <InfoRow
              icon={Calendar}
              label="Published"
              value={formatDate(depsDev.published_at, {
                year: "numeric",
                month: "long",
                day: "numeric"
              })}
            />
          )}

          {metadata.enrichment_sources && metadata.enrichment_sources.length > 0 && (
            <p className="text-xs text-muted-foreground pt-2 border-t">
              Data enriched from: {metadata.enrichment_sources.map(formatEnrichmentSource).join(", ")}
            </p>
          )}
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}

export function AnalyticsDependencyModal({
  component, 
  version,
  type,
  open,
  onOpenChange
}: Readonly<AnalyticsDependencyModalProps>) {
  const sort = useSortState<SortField>('severity')
  const [selectedFinding, setSelectedFinding] = useState<ComponentFinding | null>(null)

  const enabledComponent = open ? component : ''
  // The opening table's mode, so the drill-down reports the same scope as the clicked row.
  const releaseEnvironment = useAnalyticsMode()
  const { data: metadata, isLoading: isLoadingMetadata } = useDependencyMetadata(
    enabledComponent, version, type, releaseEnvironment,
  )
  const { data: findingsPage, isLoading: isLoadingFindings, error: findingsError, refetch: refetchFindings } = useComponentFindings(
    enabledComponent, version, releaseEnvironment,
  )
  const totalFindings = findingsPage?.total ?? 0

  const sortedFindings = useMemo(() => {
    if (!findingsPage) return []

    return [...findingsPage.items].sort((a, b) => {
      let comparison = 0
      
      switch (sort.sortBy) {
        case 'id':
          comparison = (getDisplayId(a) ?? '').localeCompare(getDisplayId(b) ?? '')
          break
        case 'type':
          comparison = (a.type || '').localeCompare(b.type || '')
          break
        case 'severity': {
          comparison = severityRank(a.severity) - severityRank(b.severity)
          break
        }
        case 'project_name':
          comparison = (a.project_name || '').localeCompare(b.project_name || '')
          break
      }
      
      return sort.sortOrder === 'asc' ? comparison : -comparison
    })
  }, [findingsPage, sort.sortBy, sort.sortOrder])

  const metadataSection = metadata ? (
    <DependencyMetadataSection metadata={metadata} />
  ) : null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-center gap-2 sm:justify-start">
            <Package className="h-5 w-5" />
            {component}
            {version && <Badge variant="outline">{version}</Badge>}
          </DialogTitle>
          <DialogDescription>
            Dependency details and findings across all your projects.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-6 pr-2">
          {isLoadingMetadata ? (
            <div className="space-y-3">
              <Skeleton className="h-8 w-3/4" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : (
            metadataSection
          )}

          <div className="space-y-3">
            <h3 className="text-lg font-medium flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Findings
              {totalFindings > 0 && (
                <Badge variant="secondary">{totalFindings}</Badge>
              )}
            </h3>
            {sortedFindings.length < totalFindings && (
              <p className="text-sm text-muted-foreground">
                Showing the {sortedFindings.length} most severe of {totalFindings} findings.
              </p>
            )}

            {isLoadingFindings && (
              <div className="space-y-2">
                {['s1', 's2', 's3'].map((skeletonId) => (
                  <Skeleton key={skeletonId} className="h-16 w-full" />
                ))}
              </div>
            )}
            {findingsError && (
              <AnalyticsErrorCard title="Failed to load findings" error={findingsError} onRetry={() => refetchFindings()} />
            )}
            {!isLoadingFindings && sortedFindings.length > 0 && (
              // Narrower than its fixed columns, the table would leave the Project column no width at all.
              <Table className="table-fixed min-w-[660px]">
                <TableHeader>
                  <TableRow>
                    <SortableHead column="id" sort={sort} firstOrder="asc" className="w-[180px]">Finding</SortableHead>
                    <SortableHead column="type" sort={sort} firstOrder="asc" className="w-[160px]">Type</SortableHead>
                    <SortableHead column="severity" sort={sort} className="w-[120px]">Severity</SortableHead>
                    <SortableHead column="project_name" sort={sort} firstOrder="asc">Project</SortableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedFindings.map((finding) => (
                    <TableRow
                      key={`${finding.type}:${finding.id}:${finding.version}:${finding.scan_id}`}
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <TableCell className="font-mono text-xs truncate">
                        {getDisplayId(finding) || '-'}
                      </TableCell>
                      <TableCell>
                        <FindingTypeBadge type={finding.type} />
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={finding.severity || 'UNKNOWN'} />
                      </TableCell>
                      <TableCell className="truncate">
                        <Link
                          to={`/projects/${finding.project_id}`}
                          className="text-primary hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {finding.project_name || 'Unknown'}
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {!isLoadingFindings && !findingsError && sortedFindings.length === 0 && (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground bg-muted/30 rounded-lg">
                <Shield className="h-8 w-8 mb-2" />
                <p>No findings for this dependency</p>
              </div>
            )}
          </div>
        </div>

        {selectedFinding && (
          <FindingDetailsModal
            finding={selectedFinding}
            onClose={() => setSelectedFinding(null)}
            projectId={selectedFinding.project_id}
            scanId={selectedFinding.scan_id}
            onSelectFinding={(id) => {
              const sameScan = sortedFindings.filter((f) => f.scan_id === selectedFinding.scan_id)
              const found = resolveRelatedFindingInRows(sameScan, id, selectedFinding)
              if (found) {
                setSelectedFinding(found);
              }
            }}
            onNavigate={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}
