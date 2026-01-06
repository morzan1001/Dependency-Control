import { FileCode, ExternalLink } from "lucide-react"
import { buildFileUrl } from "@/lib/scm-links"

interface FileLocationProps {
    /** The file path to display */
    readonly filePath: string
    /** Start line number */
    readonly startLine?: number | null
    /** End line number */
    readonly endLine?: number | null
    /** Start column */
    readonly startCol?: number | null
    /** End column */
    readonly endCol?: number | null
    /** SCM context for building repository link */
    readonly scmContext?: {
        projectUrl?: string | null
        pipelineUrl?: string | null
        commitHash?: string | null
        branch?: string | null
    } | null
}

/**
 * Build a human-readable location string from line/column info.
 */
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

/**
 * Reusable component for displaying file path with optional repository link and location.
 */
export function FileLocation({ 
    filePath, 
    startLine, 
    endLine, 
    startCol, 
    endCol, 
    scmContext 
}: FileLocationProps) {
    // Build repository URL if context is available
    const fileUrl = scmContext ? buildFileUrl({
        projectUrl: scmContext.projectUrl,
        pipelineUrl: scmContext.pipelineUrl,
        commitHash: scmContext.commitHash,
        branch: scmContext.branch,
        filePath,
        startLine: typeof startLine === 'number' ? startLine : null,
        endLine: typeof endLine === 'number' ? endLine : null,
    }) : null

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

export { buildLocationString }
