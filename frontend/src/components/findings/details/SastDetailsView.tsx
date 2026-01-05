import { Finding } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { ExternalLink, FileCode, AlertTriangle, Info, BookOpen } from "lucide-react"
import { Button } from "@/components/ui/button"
import ReactMarkdown, { Components } from 'react-markdown'
import { buildFileUrl } from "@/lib/scm-links"

// Markdown component overrides - defined outside component to avoid re-creation
const markdownComponents: Partial<Components> = {
    // Style code blocks
    code: ({ className, children, ...props }) => {
        const isInline = !className
        if (isInline) {
            return (
                <code className="bg-muted px-1 py-0.5 rounded text-xs font-mono" {...props}>
                    {children}
                </code>
            )
        }
        return (
            <pre className="bg-muted p-3 rounded-lg overflow-auto">
                <code className="text-xs font-mono" {...props}>
                    {children}
                </code>
            </pre>
        )
    },
    // Style headings
    h2: ({ children }) => (
        <h5 className="text-sm font-semibold mt-4 mb-2 flex items-center gap-2">
            <Info className="h-4 w-4" />
            {children}
        </h5>
    ),
    // Style lists
    ul: ({ children }) => (
        <ul className="list-disc list-inside space-y-1 text-sm">{children}</ul>
    ),
    li: ({ children }) => (
        <li className="text-sm text-muted-foreground">{children}</li>
    ),
}

export interface ScanContext {
    projectUrl?: string | null
    pipelineUrl?: string | null
    commitHash?: string | null
    branch?: string | null
}

interface SastDetailsViewProps {
    readonly finding: Finding
    readonly scanContext?: ScanContext
}

export function SastDetailsView({ finding, scanContext }: SastDetailsViewProps) {
    const details = finding.details || {}
    const isBearer = finding.scanners?.includes('bearer')
    const isOpenGrep = finding.scanners?.includes('opengrep')
    const isKics = finding.scanners?.includes('kics')

    // Determine rule ID based on scanner
    const ruleId = details.rule_id || details.check_id || "Unknown"
    
    // Location info
    const startLine = details.start?.line || details.line
    const endLine = details.end?.line || details.line || startLine
    const startCol = details.start?.column
    const endCol = details.end?.column

    // Build location string
    let locationStr = startLine ? `Line ${startLine}` : "Unknown"
    if (startLine && endLine && endLine !== startLine) {
        locationStr += ` - ${endLine}`
    }
    if (startCol && endCol) {
        locationStr += ` (Col ${startCol}-${endCol})`
    }

    // Build file URL for source code link
    const fileUrl = scanContext ? buildFileUrl({
        projectUrl: scanContext.projectUrl,
        pipelineUrl: scanContext.pipelineUrl,
        commitHash: scanContext.commitHash,
        branch: scanContext.branch,
        filePath: finding.component,
        startLine: typeof startLine === 'number' ? startLine : null,
        endLine: typeof endLine === 'number' ? endLine : null,
    }) : null

    return (
        <div className="space-y-4">
            {/* File and Location with Source Link */}
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
                                    title={finding.component}
                                >
                                    {finding.component}
                                    <ExternalLink className="h-3 w-3 ml-1 inline" />
                                </a>
                            ) : (
                                <code className="font-mono text-sm truncate" title={finding.component}>
                                    {finding.component}
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

            {/* Rule Info */}
            <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Rule ID</h4>
                    <div className="flex items-center gap-2">
                        <code className="font-mono text-sm bg-background px-2 py-0.5 rounded">{ruleId}</code>
                    </div>
                </div>
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Scanner</h4>
                    <div className="flex flex-wrap gap-1">
                        {finding.scanners?.map(scanner => (
                            <Badge key={scanner} variant="secondary" className="text-xs">
                                {scanner}
                            </Badge>
                        ))}
                    </div>
                </div>
            </div>

            {/* Bearer-specific: Title */}
            {isBearer && details.title && details.title !== finding.description && (
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Issue</h4>
                    <p className="text-sm font-medium">{details.title}</p>
                </div>
            )}

            {/* CWE IDs (Bearer) */}
            {details.cwe_ids && details.cwe_ids.length > 0 && (
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">CWE References</h4>
                    <div className="flex flex-wrap gap-2">
                        {details.cwe_ids.map((cwe: string) => (
                            <a
                                key={cwe}
                                href={`https://cwe.mitre.org/data/definitions/${cwe}.html`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center"
                            >
                                <Badge variant="outline" className="hover:bg-muted cursor-pointer">
                                    <AlertTriangle className="h-3 w-3 mr-1" />
                                    CWE-{cwe}
                                    <ExternalLink className="h-3 w-3 ml-1" />
                                </Badge>
                            </a>
                        ))}
                    </div>
                </div>
            )}

            {/* Category Groups (Bearer) */}
            {details.category_groups && details.category_groups.length > 0 && (
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Categories</h4>
                    <div className="flex flex-wrap gap-2">
                        {details.category_groups.map((cat: string) => (
                            <Badge key={cat} variant="secondary">
                                {cat}
                            </Badge>
                        ))}
                    </div>
                </div>
            )}

            {/* Code Extract (Bearer) */}
            {details.code_extract && (
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Code</h4>
                    <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs font-mono border">
                        <code>{details.code_extract}</code>
                    </pre>
                </div>
            )}

            {/* Description with Markdown support (Bearer descriptions are often markdown) */}
            {finding.description && (
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Description & Remediation</h4>
                    <div className="prose prose-sm dark:prose-invert max-w-none bg-muted/30 p-4 rounded-lg border">
                        <ReactMarkdown components={markdownComponents}>
                            {finding.description}
                        </ReactMarkdown>
                    </div>
                </div>
            )}

            {/* Documentation Link (Bearer) */}
            {details.documentation_url && (
                <div className="pt-2">
                    <Button variant="outline" size="sm" asChild>
                        <a 
                            href={details.documentation_url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-2"
                        >
                            <BookOpen className="h-4 w-4" />
                            View Full Documentation
                            <ExternalLink className="h-3 w-3" />
                        </a>
                    </Button>
                </div>
            )}

            {/* OpenGrep-specific metadata */}
            {isOpenGrep && details.metadata && (
                <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Rule Metadata</h4>
                    <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs">
                        {JSON.stringify(details.metadata, null, 2)}
                    </pre>
                </div>
            )}

            {/* KICS-specific fields */}
            {isKics && (
                <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                    {details.category && (
                        <div>
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Category</h4>
                            <p className="text-sm">{details.category}</p>
                        </div>
                    )}
                    {details.platform && (
                        <div>
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Platform</h4>
                            <p className="text-sm">{details.platform}</p>
                        </div>
                    )}
                    {details.expected_value && (
                        <div>
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Expected</h4>
                            <p className="text-sm font-mono text-green-600">{details.expected_value}</p>
                        </div>
                    )}
                    {details.actual_value && (
                        <div>
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Actual</h4>
                            <p className="text-sm font-mono text-red-600">{details.actual_value}</p>
                        </div>
                    )}
                </div>
            )}

            {/* Fingerprint for debugging/reference */}
            {details.fingerprint && (
                <div className="pt-2 border-t">
                    <p className="text-xs text-muted-foreground">
                        Fingerprint: <code className="font-mono">{details.fingerprint}</code>
                    </p>
                </div>
            )}
        </div>
    )
}
