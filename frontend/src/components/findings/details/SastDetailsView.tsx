import { Finding } from "@/types/scan"
import { Badge } from "@/components/ui/badge"
import { ExternalLink, AlertTriangle, Info, BookOpen, Shield, Target, Gauge } from "lucide-react"
import { Button } from "@/components/ui/button"
import ReactMarkdown, { Components } from 'react-markdown'
import { 
    DetailSection, 
    BadgeList, 
    ReferencesList, 
    RiskBadge, 
    FileLocation 
} from "./shared"

// Markdown component overrides - defined outside component to avoid re-creation
const markdownComponents: Partial<Components> = {
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
    h2: ({ children }) => (
        <h5 className="text-sm font-semibold mt-4 mb-2 flex items-center gap-2">
            <Info className="h-4 w-4" />
            {children}
        </h5>
    ),
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

    const ruleId = details.rule_id || details.check_id || "Unknown"
    const startLine = details.start?.line || details.line
    const endLine = details.end?.line || details.line || startLine

    return (
        <div className="space-y-4">
            {/* File and Location with Source Link */}
            <FileLocation
                filePath={finding.component || "Unknown"}
                startLine={startLine}
                endLine={endLine}
                startCol={details.start?.column}
                endCol={details.end?.column}
                scmContext={scanContext}
            />

            {/* Rule Info */}
            <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                <DetailSection label="Rule ID" compact>
                    <code className="font-mono text-sm bg-background px-2 py-0.5 rounded">{ruleId}</code>
                </DetailSection>
                <DetailSection label="Scanner" compact>
                    <div className="flex flex-wrap gap-1">
                        {finding.scanners?.map(scanner => (
                            <Badge key={scanner} variant="secondary" className="text-xs">
                                {scanner}
                            </Badge>
                        ))}
                    </div>
                </DetailSection>
            </div>

            {/* Bearer-specific: Title */}
            {isBearer && details.title && details.title !== finding.description && (
                <DetailSection label="Issue" compact>
                    <p className="text-sm font-medium">{details.title}</p>
                </DetailSection>
            )}

            {/* CWE IDs (shared between Bearer and OpenGrep) */}
            {details.cwe_ids && details.cwe_ids.length > 0 && (
                <DetailSection label="CWE References">
                    <BadgeList
                        items={details.cwe_ids}
                        variant="outline"
                        icon={AlertTriangle}
                        formatLabel={(cwe) => `CWE-${cwe}`}
                        buildUrl={(cwe) => `https://cwe.mitre.org/data/definitions/${cwe}.html`}
                    />
                </DetailSection>
            )}

            {/* OWASP References (OpenGrep) */}
            {details.owasp && details.owasp.length > 0 && (
                <DetailSection label="OWASP References">
                    <BadgeList
                        items={details.owasp}
                        variant="outline"
                        icon={Shield}
                        badgeClassName="text-orange-600 border-orange-300"
                    />
                </DetailSection>
            )}

            {/* Category Groups (Bearer) */}
            {details.category_groups && details.category_groups.length > 0 && (
                <DetailSection label="Categories">
                    <BadgeList items={details.category_groups} variant="secondary" />
                </DetailSection>
            )}

            {/* Risk Assessment (OpenGrep) */}
            {isOpenGrep && (details.confidence || details.likelihood || details.impact) && (
                <div className="grid grid-cols-3 gap-4 p-4 bg-muted/50 rounded-lg border">
                    {details.confidence && (
                        <DetailSection label="Confidence" icon={Target} compact>
                            <RiskBadge level={details.confidence} />
                        </DetailSection>
                    )}
                    {details.likelihood && (
                        <DetailSection label="Likelihood" icon={Gauge} compact>
                            <RiskBadge level={details.likelihood} />
                        </DetailSection>
                    )}
                    {details.impact && (
                        <DetailSection label="Impact" icon={AlertTriangle} compact>
                            <RiskBadge level={details.impact} />
                        </DetailSection>
                    )}
                </div>
            )}

            {/* Vulnerability Class, Technology, Subcategory (OpenGrep) */}
            {isOpenGrep && (
                ((details.vulnerability_class?.length ?? 0) > 0) ||
                ((details.technology?.length ?? 0) > 0) ||
                ((details.subcategory?.length ?? 0) > 0)
            ) && (
                <div className="flex flex-wrap gap-4">
                    {details.vulnerability_class && details.vulnerability_class.length > 0 && (
                        <DetailSection label="Vulnerability Class">
                            <BadgeList 
                                items={details.vulnerability_class} 
                                variant="outline"
                                badgeClassName="text-red-600 border-red-300"
                            />
                        </DetailSection>
                    )}
                    {details.technology && details.technology.length > 0 && (
                        <DetailSection label="Technology">
                            <BadgeList items={details.technology} variant="secondary" />
                        </DetailSection>
                    )}
                    {details.subcategory && details.subcategory.length > 0 && (
                        <DetailSection label="Subcategory">
                            <BadgeList items={details.subcategory} variant="outline" />
                        </DetailSection>
                    )}
                </div>
            )}

            {/* Code Extract (Bearer) */}
            {details.code_extract && (
                <DetailSection label="Code">
                    <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs font-mono border">
                        <code>{details.code_extract}</code>
                    </pre>
                </DetailSection>
            )}

            {/* Description with Markdown support */}
            {finding.description && (
                <DetailSection label="Description & Remediation">
                    <div className="prose prose-sm dark:prose-invert max-w-none bg-muted/30 p-4 rounded-lg border">
                        <ReactMarkdown components={markdownComponents}>
                            {finding.description}
                        </ReactMarkdown>
                    </div>
                </DetailSection>
            )}

            {/* References (OpenGrep) */}
            {details.references && details.references.length > 0 && (
                <DetailSection label="References">
                    <ReferencesList urls={details.references} />
                </DetailSection>
            )}

            {/* Source Rule URL (OpenGrep) */}
            {isOpenGrep && details.source_rule_url && (
                <DetailSection label="Rule Source">
                    <a
                        href={details.source_rule_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline inline-flex items-center gap-1"
                    >
                        <ExternalLink className="h-3 w-3" />
                        {details.source_rule_url}
                    </a>
                </DetailSection>
            )}

            {/* Documentation Link (shared) */}
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

            {/* KICS-specific fields */}
            {isKics && (
                <div className="grid grid-cols-2 gap-4 p-4 bg-muted/50 rounded-lg border">
                    {details.category && (
                        <DetailSection label="Category" compact>
                            <p className="text-sm">{details.category}</p>
                        </DetailSection>
                    )}
                    {details.platform && (
                        <DetailSection label="Platform" compact>
                            <p className="text-sm">{details.platform}</p>
                        </DetailSection>
                    )}
                    {details.expected_value && (
                        <DetailSection label="Expected" compact>
                            <p className="text-sm font-mono text-green-600">{details.expected_value}</p>
                        </DetailSection>
                    )}
                    {details.actual_value && (
                        <DetailSection label="Actual" compact>
                            <p className="text-sm font-mono text-red-600">{details.actual_value}</p>
                        </DetailSection>
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
