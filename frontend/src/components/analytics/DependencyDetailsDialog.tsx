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

            {/* License Information */}
            {dependency.license && (
              <>
                <hr className="border-border" />
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-medium">License</h4>
                  </div>
                  <InfoRow
                    icon={FileText}
                    label="License"
                    value={dependency.license}
                    href={dependency.license_url || undefined}
                  />
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
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
