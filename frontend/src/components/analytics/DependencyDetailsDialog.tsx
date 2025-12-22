import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { AdvancedSearchResult } from "@/lib/api"
import { cn } from "@/lib/utils"
import {
  Package,
  Container,
  FileCode,
  HardDrive,
  ExternalLink,
  Copy,
  Check,
  Globe,
  GitBranch,
  Download,
  Shield,
  User,
  Building,
  Layers,
  FileText,
  Hash,
  MapPin,
  Tag,
  Info,
  Star,
  GitFork,
  CircleDot,
  Users,
  Calendar,
  AlertTriangle,
  AlertOctagon,
  TrendingUp,
  Link2,
} from "lucide-react"
import { useState } from "react"
import { Link } from "react-router-dom"

interface DependencyDetailsDialogProps {
  dependency: AdvancedSearchResult | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

function getSourceInfo(sourceType?: string) {
  switch (sourceType) {
    case "image":
      return {
        icon: Container,
        label: "Docker Image",
        color: "text-blue-500",
        bgColor: "bg-blue-500/10",
      }
    case "file":
      return {
        icon: FileCode,
        label: "Source File",
        color: "text-green-500",
        bgColor: "bg-green-500/10",
      }
    case "directory":
      return {
        icon: HardDrive,
        label: "Directory",
        color: "text-amber-500",
        bgColor: "bg-amber-500/10",
      }
    default:
      return null
  }
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

  return (
    <div className="flex items-start gap-3 py-2">
      <Icon className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <div className="flex items-center gap-2">
          {href ? (
            <a
              href={href}
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

export function DependencyDetailsDialog({
  dependency,
  open,
  onOpenChange,
}: DependencyDetailsDialogProps) {
  if (!dependency) return null

  const sourceInfo = getSourceInfo(dependency.source_type)
  const hasExternalLinks =
    dependency.homepage || dependency.repository_url || dependency.download_url
  const hasHashes = dependency.hashes && Object.keys(dependency.hashes).length > 0
  const hasCpes = dependency.cpes && dependency.cpes.length > 0
  const hasLocations = dependency.locations && dependency.locations.length > 0
  const hasProperties =
    dependency.properties && Object.keys(dependency.properties).length > 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            {dependency.package}
          </DialogTitle>
          <DialogDescription>
            Detailed information about this dependency
          </DialogDescription>
        </DialogHeader>

        <div className="max-h-[65vh] pr-4 overflow-y-auto">
          <div className="space-y-6">
            {/* Basic Info */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Version</p>
                <Badge variant="outline" className="text-base">
                  {dependency.version}
                </Badge>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Package Type</p>
                <Badge variant="secondary">{dependency.type}</Badge>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Dependency Type</p>
                <Badge variant={dependency.direct ? "default" : "secondary"}>
                  {dependency.direct ? "Direct" : "Transitive"}
                </Badge>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Project</p>
                <Link
                  to={`/projects/${dependency.project_id}`}
                  className="text-sm text-primary hover:underline"
                >
                  {dependency.project_name}
                </Link>
              </div>
            </div>

            {/* Description */}
            {dependency.description && (
              <>
                <hr className="border-border" />
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Info className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">Description</h4>
                  </div>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {dependency.description}
                  </p>
                </div>
              </>
            )}

            {/* deps.dev Package Insights */}
            {dependency.deps_dev && (
              <>
                <hr className="border-border" />
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <TrendingUp className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">Package Insights</h4>
                    <span className="text-xs text-muted-foreground">(via deps.dev)</span>
                  </div>

                  {/* Deprecated Warning */}
                  {dependency.deps_dev.is_deprecated && (
                    <div className="flex items-center gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-md">
                      <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0" />
                      <div>
                        <p className="font-medium text-amber-600 dark:text-amber-400">This package is deprecated</p>
                        <p className="text-sm text-muted-foreground">Consider finding an alternative.</p>
                      </div>
                    </div>
                  )}

                  {/* Known Advisories Warning */}
                  {dependency.deps_dev.known_advisories && dependency.deps_dev.known_advisories.length > 0 && (
                    <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-md">
                      <AlertOctagon className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-medium text-red-600 dark:text-red-400">
                          {dependency.deps_dev.known_advisories.length} Known Security {dependency.deps_dev.known_advisories.length === 1 ? "Advisory" : "Advisories"}
                        </p>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {dependency.deps_dev.known_advisories.map((advisory, i) => (
                            <Badge key={i} variant="destructive" className="text-xs">
                              {advisory}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Stats Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {dependency.deps_dev.stars !== undefined && (
                      <div className="flex items-center gap-2 p-2 bg-muted/50 rounded-md">
                        <Star className="h-4 w-4 text-yellow-500" />
                        <div>
                          <p className="text-sm font-medium">{dependency.deps_dev.stars.toLocaleString()}</p>
                          <p className="text-xs text-muted-foreground">Stars</p>
                        </div>
                      </div>
                    )}
                    {dependency.deps_dev.forks !== undefined && (
                      <div className="flex items-center gap-2 p-2 bg-muted/50 rounded-md">
                        <GitFork className="h-4 w-4 text-blue-500" />
                        <div>
                          <p className="text-sm font-medium">{dependency.deps_dev.forks.toLocaleString()}</p>
                          <p className="text-xs text-muted-foreground">Forks</p>
                        </div>
                      </div>
                    )}
                    {dependency.deps_dev.open_issues !== undefined && (
                      <div className="flex items-center gap-2 p-2 bg-muted/50 rounded-md">
                        <CircleDot className="h-4 w-4 text-green-500" />
                        <div>
                          <p className="text-sm font-medium">{dependency.deps_dev.open_issues.toLocaleString()}</p>
                          <p className="text-xs text-muted-foreground">Issues</p>
                        </div>
                      </div>
                    )}
                    {dependency.deps_dev.dependents?.total !== undefined && (
                      <div className="flex items-center gap-2 p-2 bg-muted/50 rounded-md">
                        <Users className="h-4 w-4 text-purple-500" />
                        <div>
                          <p className="text-sm font-medium">{dependency.deps_dev.dependents.total.toLocaleString()}</p>
                          <p className="text-xs text-muted-foreground">Dependents</p>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Scorecard Score */}
                  {dependency.deps_dev.scorecard && (
                    <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-md">
                      <Shield className={cn(
                        "h-6 w-6",
                        (dependency.deps_dev.scorecard.overall_score ?? 0) >= 7 ? "text-green-500" :
                        (dependency.deps_dev.scorecard.overall_score ?? 0) >= 4 ? "text-amber-500" :
                        "text-red-500"
                      )} />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">OpenSSF Scorecard</span>
                          <Badge variant={
                            (dependency.deps_dev.scorecard.overall_score ?? 0) >= 7 ? "default" :
                            (dependency.deps_dev.scorecard.overall_score ?? 0) >= 4 ? "secondary" :
                            "destructive"
                          }>
                            {dependency.deps_dev.scorecard.overall_score?.toFixed(1) ?? "N/A"} / 10
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {dependency.deps_dev.scorecard.checks_count} checks evaluated
                          {dependency.deps_dev.scorecard.date && ` • ${new Date(dependency.deps_dev.scorecard.date).toLocaleDateString()}`}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Published Date */}
                  {dependency.deps_dev.published_at && (
                    <InfoRow
                      icon={Calendar}
                      label="Published"
                      value={new Date(dependency.deps_dev.published_at).toLocaleDateString(undefined, {
                        year: "numeric",
                        month: "long",
                        day: "numeric"
                      })}
                    />
                  )}

                  {/* Project Description */}
                  {dependency.deps_dev.project_description && !dependency.description && (
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Project Description</p>
                      <p className="text-sm">{dependency.deps_dev.project_description}</p>
                    </div>
                  )}

                  {/* deps.dev Links */}
                  {dependency.deps_dev.links && Object.keys(dependency.deps_dev.links).length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground">Additional Links</p>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(dependency.deps_dev.links).map(([label, url]) => (
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

                  {/* Project URL */}
                  {dependency.deps_dev.project_url && (
                    <InfoRow
                      icon={GitBranch}
                      label="Project Repository"
                      value={dependency.deps_dev.project_url.replace(/^https?:\/\//, '')}
                      href={dependency.deps_dev.project_url}
                    />
                  )}
                </div>
              </>
            )}

            {/* Source Information */}
            {sourceInfo && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Layers className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">Source Information</h4>
                  </div>
                  <div
                    className={cn(
                      "flex items-center gap-2 px-3 py-2 rounded-md w-fit",
                      sourceInfo.bgColor
                    )}
                  >
                    <sourceInfo.icon className={cn("h-4 w-4", sourceInfo.color)} />
                    <span className="font-medium">{sourceInfo.label}</span>
                  </div>
                  {dependency.source_target && (
                    <InfoRow
                      icon={Tag}
                      label="Target"
                      value={dependency.source_target}
                      copyable
                    />
                  )}
                  {dependency.layer_digest && (
                    <InfoRow
                      icon={Layers}
                      label="Layer Digest"
                      value={dependency.layer_digest}
                      copyable
                    />
                  )}
                  {dependency.found_by && (
                    <InfoRow
                      icon={Shield}
                      label="Found By"
                      value={dependency.found_by}
                    />
                  )}
                </div>
              </>
            )}

            {/* Package Identity */}
            <hr className="border-border" />
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Package className="h-4 w-4 text-muted-foreground" />
                <h4 className="font-medium">Package Identity</h4>
              </div>
              <InfoRow icon={Tag} label="PURL" value={dependency.purl} copyable />
              {dependency.group && (
                <InfoRow icon={Tag} label="Group" value={dependency.group} />
              )}
            </div>

            {/* License Information (Aggregated) */}
            {(dependency.license || dependency.licenses_detailed?.length) && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">License</h4>
                    {dependency.license_category && (
                      <Badge variant={
                        dependency.license_category === "permissive" ? "default" :
                        dependency.license_category === "public_domain" ? "default" :
                        dependency.license_category === "weak_copyleft" ? "secondary" :
                        dependency.license_category === "strong_copyleft" ? "destructive" :
                        dependency.license_category === "network_copyleft" ? "destructive" :
                        "outline"
                      } className="text-xs">
                        {dependency.license_category.replace(/_/g, ' ')}
                      </Badge>
                    )}
                  </div>
                  
                  {/* Primary License */}
                  <InfoRow
                    icon={FileText}
                    label="License"
                    value={dependency.license}
                    href={dependency.license_url || undefined}
                  />
                  
                  {/* License Sources (if multiple) */}
                  {dependency.licenses_detailed && dependency.licenses_detailed.length > 1 && (
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">License Sources</p>
                      <div className="flex flex-wrap gap-1">
                        {dependency.licenses_detailed.map((lic, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {lic.spdx_id}
                            <span className="text-muted-foreground ml-1">({lic.source})</span>
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* License Risks */}
                  {dependency.license_risks && dependency.license_risks.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Risks</p>
                      <div className="space-y-1">
                        {dependency.license_risks.map((risk, i) => (
                          <div key={i} className="flex items-start gap-2 text-sm text-amber-600 dark:text-amber-400">
                            <AlertTriangle className="h-3 w-3 mt-0.5 flex-shrink-0" />
                            <span>{risk}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* License Obligations */}
                  {dependency.license_obligations && dependency.license_obligations.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Obligations</p>
                      <ul className="text-sm text-muted-foreground list-disc list-inside space-y-0.5">
                        {dependency.license_obligations.slice(0, 5).map((obl, i) => (
                          <li key={i}>{obl}</li>
                        ))}
                        {dependency.license_obligations.length > 5 && (
                          <li className="text-xs">+{dependency.license_obligations.length - 5} more</li>
                        )}
                      </ul>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Author/Publisher */}
            {(dependency.author || dependency.publisher) && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <User className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">Maintainers</h4>
                  </div>
                  <InfoRow icon={User} label="Author" value={dependency.author} />
                  <InfoRow
                    icon={Building}
                    label="Publisher"
                    value={dependency.publisher}
                  />
                </div>
              </>
            )}

            {/* External Links */}
            {hasExternalLinks && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <ExternalLink className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">External Links</h4>
                  </div>
                  <InfoRow
                    icon={Globe}
                    label="Homepage"
                    value={dependency.homepage}
                    href={dependency.homepage}
                  />
                  <InfoRow
                    icon={GitBranch}
                    label="Repository"
                    value={dependency.repository_url}
                    href={dependency.repository_url}
                  />
                  <InfoRow
                    icon={Download}
                    label="Download"
                    value={dependency.download_url}
                    href={dependency.download_url}
                  />
                </div>
              </>
            )}

            {/* File Locations */}
            {hasLocations && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <MapPin className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">
                      File Locations ({dependency.locations!.length})
                    </h4>
                  </div>
                  <div className="space-y-1 bg-muted/50 rounded-md p-3">
                    {dependency.locations!.map((loc, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-2 text-sm font-mono"
                      >
                        <FileCode className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                        <span className="break-all">{loc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {/* CPEs */}
            {hasCpes && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">CPE Identifiers ({dependency.cpes!.length})</h4>
                  </div>
                  <div className="space-y-1 bg-muted/50 rounded-md p-3">
                    {dependency.cpes!.map((cpe, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-2 text-xs font-mono"
                      >
                        <span className="break-all">{cpe}</span>
                        <CopyButton text={cpe} />
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {/* Hashes */}
            {hasHashes && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Hash className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">Checksums</h4>
                  </div>
                  <div className="space-y-2 bg-muted/50 rounded-md p-3">
                    {Object.entries(dependency.hashes!).map(([alg, value]) => (
                      <div key={alg} className="space-y-1">
                        <p className="text-xs text-muted-foreground uppercase">
                          {alg}
                        </p>
                        <div className="flex items-center gap-2">
                          <code className="text-xs break-all flex-1">{value}</code>
                          <CopyButton text={value} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {/* Additional Properties */}
            {hasProperties && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Info className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">Additional Properties</h4>
                  </div>
                  <div className="space-y-2 bg-muted/50 rounded-md p-3">
                    {Object.entries(dependency.properties!).map(([key, value]) => (
                      <div key={key} className="flex items-start gap-2 text-sm">
                        <span className="font-medium min-w-0 break-all">{key}:</span>
                        <span className="text-muted-foreground break-all">
                          {value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
            
            {/* Enrichment Sources Footer */}
            {dependency.enrichment_sources && dependency.enrichment_sources.length > 0 && (
              <div className="pt-4 border-t border-border">
                <p className="text-xs text-muted-foreground">
                  Data enriched from: {dependency.enrichment_sources.map(s => 
                    s === "deps_dev" ? "deps.dev" : 
                    s === "license_compliance" ? "License Scanner" : 
                    s
                  ).join(", ")}
                </p>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
