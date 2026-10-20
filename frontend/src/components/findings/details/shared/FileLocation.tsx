import { FileCode, ExternalLink } from "lucide-react"
import { buildFileUrl } from "@/lib/scm-links"
import { shortCommitHash } from "@/lib/utils"
import type { FindingLocation } from "@/types/scan"
import { DetailSection } from "./DetailSection"

type ScmContext = {
    projectUrl?: string | null
    pipelineUrl?: string | null
    commitHash?: string | null
    branch?: string | null
} | null

interface FileLocationProps {
    readonly filePath: string
    readonly startLine?: number | null
    readonly endLine?: number | null
    readonly startCol?: number | null
    readonly endCol?: number | null
    readonly scmContext?: ScmContext
}

function buildLocationString(
    startLine?: number | null,
    endLine?: number | null,
    startCol?: number | null,
    endCol?: number | null
): string {
    if (!startLine) return "Unknown"

    let str = `Line ${startLine}`
    if (endLine && endLine !== startLine) {
        str += ` - ${endLine}`
    }
    if (startCol && endCol) {
        str += ` (Col ${startCol}-${endCol})`
    }
    return str
}

function buildScmFileUrl(filePath: string, scmContext: ScmContext | undefined, startLine?: number | null, endLine?: number | null) {
    return scmContext ? buildFileUrl({
        projectUrl: scmContext.projectUrl,
        pipelineUrl: scmContext.pipelineUrl,
        commitHash: scmContext.commitHash,
        branch: scmContext.branch,
        filePath,
        startLine: typeof startLine === 'number' ? startLine : null,
        endLine: typeof endLine === 'number' ? endLine : null,
    }) : null
}

export function FileLocation({
    filePath,
    startLine,
    endLine,
    startCol,
    endCol,
    scmContext
}: FileLocationProps) {
    const fileUrl = buildScmFileUrl(filePath, scmContext, startLine, endLine)

    const locationStr = buildLocationString(startLine, endLine, startCol, endCol)

    return (
        <div className="p-4 bg-muted/50 rounded-lg border">
            <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                    <h4 className="text-sm font-medium text-muted-foreground mb-1">File</h4>
                    <div className="flex items-center gap-2">
                        <FileCode className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        {fileUrl ? (
                            <a
                                href={fileUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="font-mono text-sm text-primary hover:underline truncate"
                                title={filePath}
                            >
                                {filePath}
                                <ExternalLink className="h-3 w-3 ml-1 inline" />
                            </a>
                        ) : (
                            <code className="font-mono text-sm truncate" title={filePath}>
                                {filePath}
                            </code>
                        )}
                    </div>
                </div>
                <div className="flex-shrink-0">
                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Location</h4>
                    <p className="text-sm">{locationStr}</p>
                </div>
            </div>
        </div>
    )
}

interface AdditionalLocationsProps {
    readonly filePath: string
    readonly locations?: FindingLocation[]
    readonly scmContext?: ScmContext
}

export function AdditionalLocations({ filePath, locations, scmContext }: AdditionalLocationsProps) {
    if (!locations?.length) return null
    return (
        <DetailSection label="Additional Locations">
            <ul className="space-y-1">
                {locations.map((location) => {
                    const startLine = location.start?.line ?? location.line
                    const endLine = location.end?.line
                    const label = startLine ? buildLocationString(startLine, endLine, location.start?.column, location.end?.column) : null
                    const url = label ? buildScmFileUrl(filePath, scmContext, startLine, endLine) : null
                    return (
                        <li key={JSON.stringify(location)} className="flex flex-wrap items-center gap-2 text-sm">
                            {url ? (
                                <a href={url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                                    {label}
                                    <ExternalLink className="h-3 w-3 ml-1 inline" />
                                </a>
                            ) : label && <span>{label}</span>}
                            {location.commit && (
                                <code className="font-mono text-xs text-muted-foreground">{shortCommitHash(location.commit)}</code>
                            )}
                            {location.search_key && (
                                <code className="font-mono text-xs text-muted-foreground break-all">{location.search_key}</code>
                            )}
                        </li>
                    )
                })}
            </ul>
        </DetailSection>
    )
}
